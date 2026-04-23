import json
from pathlib import Path

from backend.models.scheduling import FairnessConfig, SchedulerState
from backend.models.testing import TaskModel
from backend.models.tool_wrappers import ToolArtifacts, ToolBudget, ToolReproduction, ToolWrapperResult
from backend.services.evidence_builder_service import EvidenceBuilderService
from backend.services.task_scheduler import TaskScheduler


def _rate_abuse_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_business_logic_rate_abuse",
            "class": "business_logic",
            "subtype": "rate_abuse",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "hypothesis": "Bounded burst should reveal missing rate limiting.",
            "test_strategy": "bounded_rate_probe",
            "hypothesis_family": "resource_abuse_rate_limit",
            "worker_role": "Business Flow / Stateful Agent",
            "allowed_tools": ["schemathesis_stateful_test"],
        }
    )


def _schemathesis_result(tmp_path: Path) -> ToolWrapperResult:
    stdout = tmp_path / "stdout.log"
    stderr = tmp_path / "stderr.log"
    stdout.write_text("POST /identity/api/auth/login -> 200\nPOST /identity/api/auth/login -> 200\nPOST /identity/api/auth/login -> 500\n", encoding="utf-8")
    stderr.write_text("response violates schema\n", encoding="utf-8")
    return ToolWrapperResult(
        tool_name="schemathesis_stateful_test",
        source_task_id="task_business_logic_rate_abuse",
        worker_role="Business Flow / Stateful Agent",
        status="partial",
        signals=["unexpected_2xx", "schema_violation", "5xx"],
        artifacts=ToolArtifacts(stdout_path=str(stdout), stderr_path=str(stderr), replay_pack_path=str(tmp_path / "replay_pack.json")),
        candidate_findings=[{"endpoint": "/identity/api/auth/login", "method": "POST", "vuln_type": "rate_abuse"}],
        reproduction=ToolReproduction(method="POST", url="http://api.test/identity/api/auth/login", headers={}, body={}),
        budget=ToolBudget(max_requests=20, used_requests=20, duration_sec=1.2),
        termination_reason="tool_reported_findings",
    )


def test_wrapper_derived_judge_ready_evidence_survives(tmp_path: Path) -> None:
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=_rate_abuse_task(),
        worker_role="Business Flow / Stateful Agent",
        tool_result=_schemathesis_result(tmp_path),
        run_id="run-judge-handoff",
    )

    payload = evidence.model_dump(mode="json")

    assert payload["classification_hint"] == "unrestricted_resource_consumption"
    assert "no_rate_limit_detected" in payload["strong_indicators"]
    assert "repeated_success_without_throttle" in payload["strong_indicators"]
    assert payload["tool_summary"]["bounded_burst_count"] == 20
    assert payload["response_summary"]["evidence_strength"] == "sufficient_indicators"
    assert payload["response_summary"]["tool_summary"]["request_count"] == 20


def test_legacy_empty_indicators_do_not_overwrite_wrapper_strong_indicators(tmp_path: Path) -> None:
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=_rate_abuse_task(),
        worker_role="Business Flow / Stateful Agent",
        tool_result=_schemathesis_result(tmp_path),
        run_id="run-judge-handoff",
    ).model_dump(mode="json")
    evidence["response_summary"]["legacy_indicators"] = []

    assert evidence["indicators"]
    assert "no_rate_limit_detected" in evidence["indicators"]
    assert evidence["response_summary"]["strong_indicators"] == evidence["strong_indicators"]


def test_rate_abuse_wrapper_evidence_reaches_judge_input_logs(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    task = _rate_abuse_task()
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Business Flow / Stateful Agent",
        tool_result=_schemathesis_result(tmp_path),
        run_id="run-judge-handoff",
    ).model_dump(mode="json")

    TaskScheduler().update_queue_after_verdict(
        tasks=[],
        active_task=task,
        verdict="rework",
        rework_hint="retry",
        evidence=evidence,
        max_retries=1,
        state=SchedulerState(run_id="run-judge-handoff", root_trace_id="run-judge-handoff"),
        fairness=FairnessConfig(),
    )

    events_path = tmp_path / "logs" / "run-judge-handoff" / "events.jsonl"
    events = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    handoff_events = {event["event_type"]: event for event in events if str(event.get("event_type", "")).startswith("judge_input_")}

    assert "judge_input_source_selected" in handoff_events
    assert "judge_input_built" in handoff_events
    assert "judge_input_wrapper_fields_present" in handoff_events
    assert handoff_events["judge_input_source_selected"]["reason"]["source"] == "wrapper"
    assert handoff_events["judge_input_built"]["counters"]["strong_indicators_count"] >= 2
