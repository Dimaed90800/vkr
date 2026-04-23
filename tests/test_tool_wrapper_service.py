from pathlib import Path

import pytest

from backend.models.testing import ExecutionContext, TaskModel
from backend.models.tool_wrappers import ToolArtifacts, ToolBudget, ToolWrapperRequest, ToolWrapperResult
from backend.services.evidence_builder_service import EvidenceBuilderService
from backend.services.tool_wrappers.service import ToolWrapperService


@pytest.fixture(autouse=True)
def _diagnostic_logs_to_tmp(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "diagnostic_logs"))


def _task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_contract_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/api/items",
            "method": "GET",
            "hypothesis": "Malformed input may violate the API contract.",
            "allowed_tools": ["schemathesis_negative_test", "cats_fuzz_test"],
            "worker_role": "Contract & Negative Testing Agent",
            "preferred_tool": "schemathesis_negative_test",
            "fallback_tools": ["cats_fuzz_test"],
            "artifact_requirements": ["http_trace", "raw_report"],
        }
    )


def _restler_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_flow_001",
            "class": "business_logic",
            "subtype": "stateful_sequence",
            "endpoint": "/api/orders",
            "method": "POST",
            "hypothesis": "Invalid stateful sequences may bypass expected workflow steps.",
            "allowed_tools": ["restler_compile", "restler_fuzz", "restler_replay", "logic_test"],
            "worker_role": "Business Flow / Stateful Agent",
            "preferred_tool": "restler_fuzz",
            "fallback_tools": ["schemathesis_stateful_test", "logic_test"],
            "artifact_requirements": ["sequence_trace", "raw_report"],
        }
    )


def _rate_abuse_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_rate_001",
            "class": "business_logic",
            "subtype": "rate_abuse",
            "endpoint": "/api/orders",
            "method": "POST",
            "hypothesis": "Repeated sensitive action may be accepted without throttling.",
            "allowed_tools": ["schemathesis_stateful_test", "logic_test"],
            "worker_role": "Business Flow / Stateful Agent",
            "preferred_tool": "schemathesis_stateful_test",
            "resource_family": "rate_abuse",
        }
    )


def test_wrapper_stub_returns_normalized_judge_ready_evidence(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-test-wrapper",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        budgets=ToolBudget(max_requests=5, max_duration_sec=10, concurrency=1),
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Contract & Negative Testing Agent",
        tool_result=result,
    )

    assert result.tool_name == "cats_fuzz_test"
    assert result.schema_version == "tool-wrapper-result/v1"
    assert result.status == "partial"
    assert "wrapper_scaffold_ready" in result.signals
    assert Path(result.artifacts.replay_pack_path).exists()
    assert evidence.schema_version == "judge-ready-evidence/v1"
    assert evidence.source_task_id == "task_contract_001"
    assert evidence.tool_name == "cats_fuzz_test"
    assert evidence.worker_role == "Contract & Negative Testing Agent"
    assert evidence.reproduction["url"] == "http://127.0.0.1:8001/api/items"


def test_schemathesis_missing_openapi_returns_normalized_partial(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="schemathesis_negative_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-test-missing-openapi",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=3,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        budgets=ToolBudget(max_requests=3, max_duration_sec=10, concurrency=1),
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)

    assert result.status == "partial"
    assert result.schema_version == "tool-wrapper-result/v1"
    assert result.source_task_id == "task_contract_001"
    assert result.fallback_reason
    assert "openapi_missing" in result.signals
    assert result.termination_reason == "missing_openapi"
    assert Path(result.artifacts.replay_pack_path).exists()


def test_replay_pack_contains_reproduction_metadata(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run/test wrapper",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        arguments={"headers": {"Authorization": "Bearer secret-token"}},
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)
    replay_pack_path = Path(result.artifacts.replay_pack_path)
    replay_pack = replay_pack_path.read_text(encoding="utf-8")

    assert replay_pack_path == tmp_path / "run_test_wrapper" / "cats_fuzz_test" / "task_contract_001" / "replay_pack.json"
    assert '"schema_version": "replay-pack/v1"' in replay_pack
    assert '"source_task_id": "task_contract_001"' in replay_pack
    assert '"Authorization": "<redacted>"' in replay_pack
    assert '"strategy": "deterministic_tool_replay"' in replay_pack


def test_restler_wrapper_scaffold_returns_normalized_contract(tmp_path: Path) -> None:
    task = _restler_task()
    request = ToolWrapperRequest(
        tool_name="restler_fuzz",
        run_id="run-restler-smoke",
        target_url="http://127.0.0.1:8001",
        openapi_url="http://127.0.0.1:8001/openapi.json",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-restler-smoke",
            openapi_url="http://127.0.0.1:8001/openapi.json",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=4,
            max_duration_sec=20,
        ),
        task=task,
        task_metadata={"worker_role": "Business Flow / Stateful Agent"},
        budgets=ToolBudget(max_requests=4, max_duration_sec=20, concurrency=1),
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Business Flow / Stateful Agent",
        tool_result=result,
        run_id="run-restler-smoke",
    )
    replay_pack_path = Path(result.artifacts.replay_pack_path)
    replay_pack = replay_pack_path.read_text(encoding="utf-8")

    assert result.schema_version == "tool-wrapper-result/v1"
    assert result.tool_name == "restler_fuzz"
    assert result.status == "partial"
    assert result.termination_reason == "tool_unavailable"
    assert "wrapper_scaffold_ready" in result.signals
    assert "stateful_sequence_fuzzing_planned" in result.signals
    assert replay_pack_path == tmp_path / "run-restler-smoke" / "restler_fuzz" / "task_flow_001" / "replay_pack.json"
    assert '"strategy": "restler_sequence_replay"' in replay_pack
    assert '"replay_sequence_path": "restler/Replay/replay_sequence.json"' in replay_pack
    assert any(path.endswith("restler_wrapper_config.json") for path in result.artifacts.raw_report_paths)
    assert evidence.schema_version == "judge-ready-evidence/v1"
    assert evidence.tool_name == "restler_fuzz"


def test_schemathesis_rate_abuse_evidence_adds_concrete_indicators(tmp_path: Path) -> None:
    stdout_path = tmp_path / "stdout.log"
    stderr_path = tmp_path / "stderr.log"
    stdout_path.write_text(
        "POST /api/orders -> 200\nPOST /api/orders -> 200\nPOST /api/orders -> 200\n",
        encoding="utf-8",
    )
    stderr_path.write_text("", encoding="utf-8")
    task = _rate_abuse_task()
    result = ToolWrapperResult(
        tool_name="schemathesis_stateful_test",
        source_task_id=task.id,
        worker_role="Business Flow / Stateful Agent",
        status="ok",
        summary="Schemathesis completed bounded burst.",
        signals=["negative_test_completed"],
        artifacts=ToolArtifacts(stdout_path=str(stdout_path), stderr_path=str(stderr_path)),
        candidate_findings=[
            {
                "task_id": task.id,
                "vuln_type": "rate_abuse",
                "endpoint": "/api/orders",
                "method": "POST",
                "signals": ["negative_test_completed"],
            }
        ],
        budget=ToolBudget(max_requests=5, used_requests=3, max_duration_sec=10, termination_reason="completed"),
        termination_reason="completed",
    )

    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Business Flow / Stateful Agent",
        tool_result=result,
        run_id="run-rate-abuse",
    )

    assert "no_rate_limit_detected" in evidence.signals
    assert "repeated_success_without_throttle" in evidence.signals
    assert evidence.tool_summary["success_count"] == 3
    assert evidence.tool_summary["saw_429"] is False
    assert evidence.tool_summary["bounded_burst_count"] == 3
    assert evidence.candidate_finding["tool_summary"]["success_count"] == 3
