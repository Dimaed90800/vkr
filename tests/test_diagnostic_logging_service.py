import json
from pathlib import Path
from unittest.mock import patch

from backend.models.scheduling import FairnessConfig, SchedulerState
from backend.models.testing import ExecutionContext, TaskModel, ToolTestRequest
from backend.services.auth_preparation_service import AuthPreparationService
from backend.services.diagnostic_logging_service import DiagnosticLoggingService
from backend.services.task_scheduler import TaskScheduler
from backend.services.testing_service import TestingService


def _task(task_id: str = "task_auth") -> TaskModel:
    return TaskModel(
        id=task_id,
        class_name="authorization",
        subtype="bola",
        endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        params={"path_params": ["vehicleId"], "query_params": [], "body_fields": []},
        auth_context={"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
        hypothesis="Cross-role access may be possible.",
        priority=90,
        allowed_tools=["auth_test_access"],
        readiness="ready_to_test",
        hypothesis_family="object_authorization",
        resource_family="vehicle",
    )


def test_diagnostic_service_redacts_secrets_and_writes_summary(tmp_path: Path) -> None:
    service = DiagnosticLoggingService(base_dir=tmp_path)
    event = service.emit(
        event_type="worker_execution_completed",
        component="worker",
        status="success",
        summary="Worker finished.",
        run_id="run-test",
        trace_context={"trace_id": "abc", "task_id": "t1"},
        artifacts={
            "token": "abcdefghijklmnopqrstuvwxyz",
            "password": "SecretPass!123",
            "cookies": {"session": "session-secret-token"},
        },
    )

    assert event["artifacts"]["token"] == "abcdef...wxyz"
    assert event["artifacts"]["password"] == "Secret...!123"
    assert event["artifacts"]["cookies"]["session"] == "sessio...oken"

    summary = json.loads((tmp_path / "run-test" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["event_counts"]["worker_execution_completed"] == 1
    assert summary["component_counts"]["worker"] == 1


def test_scheduler_no_task_emits_structured_diagnostics(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    scheduler = TaskScheduler()

    response = scheduler.select_next_task(
        [],
        state=SchedulerState(run_id="run-scheduler", root_trace_id="run-scheduler"),
        fairness=FairnessConfig(),
    )

    assert response.should_stop is True
    events_path = tmp_path / "run-scheduler" / "scheduler_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(item["event_type"] == "scheduler_no_task" for item in lines)
    no_task_event = next(item for item in lines if item["event_type"] == "scheduler_no_task")
    assert no_task_event["counters"]["pending_count"] == 0
    assert no_task_event["reason"]["stop_reason"] == "no_tasks_available"
    run_stop_event = next(item for item in lines if item["event_type"] == "run_stop")
    assert run_stop_event["reason"]["stop_reason"] == "no_tasks_available"


def test_run_summary_tracks_blocked_by_reason_and_executability_metrics(tmp_path: Path) -> None:
    service = DiagnosticLoggingService(base_dir=tmp_path)
    service.emit(
        event_type="scheduler_stop_diagnostics",
        component="scheduler",
        status="stop",
        summary="Scheduler stopped with blocked tasks.",
        run_id="run-blocked",
        reason={"stop_reason": "missing_valid_baseline_path", "blocked_by_reason": {"missing_valid_baseline_path": 2}},
        counters={"executable_test_task_count": 0, "executable_preparation_task_count": 1},
        artifacts={"top_non_executable_tasks": [{"id": "inj-1", "reason": "missing_valid_baseline_path"}]},
    )
    summary = json.loads((tmp_path / "run-blocked" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["blocked_by_reason"]["missing_valid_baseline_path"] == 2
    assert summary["executable_test_task_count"] == 0
    assert summary["executable_preparation_task_count"] == 1
    assert summary["top_non_executable_tasks"][0]["id"] == "inj-1"


def test_run_summary_tracks_materialization_and_baseline_rates(tmp_path: Path) -> None:
    service = DiagnosticLoggingService(base_dir=tmp_path)
    service.emit(
        event_type="object_materialization_attempted",
        component="preparation",
        status="ok",
        summary="Tried to materialize an object.",
        run_id="run-rates",
    )
    service.emit(
        event_type="object_materialization_succeeded",
        component="preparation",
        status="success",
        summary="Materialized object.",
        run_id="run-rates",
        counters={"total_materialized_objects": 1},
    )
    service.emit(
        event_type="baseline_validation_result",
        component="worker",
        status="partial",
        summary="Baseline invalid.",
        run_id="run-rates",
        counters={"baseline_valid": False},
    )
    summary = json.loads((tmp_path / "run-rates" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["object_materialization_success_rate"] == 1.0
    assert summary["baseline_validation_failure_rate"] == 1.0


def test_rework_followup_generation_emits_diagnostic_event(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    scheduler = TaskScheduler()
    active_task = _task("inj_root").model_copy(
        update={
            "class_name": "injection",
            "subtype": "body_input_injection",
            "endpoint": "/workshop/api/mechanic/signup",
            "method": "POST",
            "allowed_tools": ["injection_test", "reflection_probe", "path_fuzz_probe"],
            "readiness": "ready_to_test",
            "hypothesis_family": "body_input_injection",
            "test_strategy": "direct_input_probe",
            "payload_family": "sqlish",
        }
    )

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Retry with alternate payload family.",
        max_retries=2,
        evidence={"response_summary": {"evidence_strength": "weak"}, "indicators": []},
        state=SchedulerState(run_id="run-followup", root_trace_id="run-followup"),
        fairness=FairnessConfig(),
    )

    assert updated.generated_followup_task_ids
    events_path = tmp_path / "run-followup" / "followup_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(item["event_type"] == "followup_task_generated" for item in lines)


def test_preparation_event_writes_materialization_diagnostics(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    service = AuthPreparationService()
    request = ToolTestRequest(
        execution_context=ExecutionContext(
            target_url="http://example.test",
            run_id="run-prep",
            root_trace_id="run-prep",
        ),
        task=_task("prep_task"),
        tool_name="create_test_object",
        arguments={},
    )

    service._emit_prep_event(
        request=request,
        event_type="prep_object_materialization_result",
        status="success",
        summary="Created vehicle and harvested id.",
        counters={"total_materialized_objects": 1, "total_harvested_ids": 1},
        artifacts={"resource_family": "vehicle", "harvested_object_ids": ["veh-1"]},
    )

    events_path = tmp_path / "run-prep" / "preparation_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert lines[-1]["artifacts"]["harvested_object_ids"] == ["veh-1"]
    summary = json.loads((tmp_path / "run-prep" / "run_summary.json").read_text(encoding="utf-8"))
    assert summary["total_materialized_objects"] == 1


def test_queue_update_logs_before_after_counters(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    scheduler = TaskScheduler()
    active_task = _task("auth_root")
    sibling = _task("auth_sibling").model_copy(
        update={
            "endpoint": "/workshop/api/management/users/all",
            "subtype": "vertical_privilege",
            "hypothesis_family": "privileged_function_access",
            "test_strategy": "privileged_function_replay",
        }
    )

    updated = scheduler.update_queue_after_verdict(
        tasks=[sibling],
        active_task=active_task,
        verdict="rework",
        rework_hint="Create object then replay.",
        max_retries=2,
        evidence={
            "response_summary": {"evidence_strength": "medium"},
            "indicators": [],
            "classification_hint": "bola",
        },
        state=SchedulerState(run_id="run-queue", root_trace_id="run-queue"),
        fairness=FairnessConfig(),
    )

    assert updated.generated_followup_task_ids
    events_path = tmp_path / "run-queue" / "queue_update_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    queue_event = next(item for item in lines if item["event_type"] == "queue_update_processed")
    assert queue_event["counters"]["pending_before"] == 1
    assert queue_event["counters"]["pending_after"] >= 1
    assert queue_event["artifacts"]["generated_followup_task_ids"]


def test_judge_verdict_finalized_is_persisted_in_backend(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    scheduler = TaskScheduler()
    active_task = _task("judge-task")

    scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        max_retries=1,
        evidence={
            "classification_hint": "bola",
            "indicators": ["invalid_object_id"],
            "response_summary": {"evidence_strength": "weak", "finding_type_hint": "bola"},
        },
        state=SchedulerState(run_id="run-judge", root_trace_id="run-judge"),
        fairness=FairnessConfig(),
    )

    events_path = tmp_path / "run-judge" / "judge_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    event = next(item for item in lines if item["event_type"] == "judge_verdict_finalized")
    assert event["reason"]["final_verdict"] == "rejected"
    assert event["trace_context"]["task_id"] == "judge-task"


def test_evidence_built_is_persisted_in_backend(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path))
    service = TestingService()
    request = ToolTestRequest(
        execution_context=ExecutionContext(
            target_url="http://example.test",
            run_id="run-evidence",
            root_trace_id="run-evidence",
        ),
        task=_task("evidence-task"),
        tool_name="auth_test_access",
        arguments={},
    )

    service._emit_worker_event(
        request=request,
        tool_name="auth_test_access",
        endpoint="http://example.test/identity/api/v2/vehicle/vehicles",
        method="GET",
        status="success",
        evidence_strength="medium",
        indicators=["same_status_code", "similar_response"],
        response_summary={"finding_type_hint": "generic_access_control", "evidence_strength": "medium"},
        artifacts={"raw_status": "success"},
    )

    events_path = tmp_path / "run-evidence" / "judge_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    event = next(item for item in lines if item["event_type"] == "evidence_built")
    assert event["reason"]["classification_hint"] == "generic_access_control"
    assert event["counters"]["indicator_count"] == 2


def test_safe_append_jsonl_creates_missing_nested_directory(tmp_path: Path) -> None:
    service = DiagnosticLoggingService(base_dir=tmp_path / "nested" / "diagnostics")

    event = service.emit(
        event_type="scheduler_selection",
        component="scheduler",
        status="success",
        summary="Selected a task.",
        run_id="run-nested",
        trace_context={"trace_id": "nested-trace", "task_id": "task-1"},
    )

    assert event["run_id"] == "run-nested"
    assert (tmp_path / "nested" / "diagnostics" / "run-nested" / "events.jsonl").exists()
    assert (tmp_path / "nested" / "diagnostics" / "run-nested" / "scheduler_events.jsonl").exists()


def test_logging_failure_is_swallowed(tmp_path: Path) -> None:
    service = DiagnosticLoggingService(base_dir=tmp_path)

    with patch.object(Path, "open", side_effect=OSError("disk full")):
        event = service.emit(
            event_type="planner_plan_completed",
            component="planner",
            status="success",
            summary="Planner completed.",
            run_id="run-fail-safe",
            trace_context={"trace_id": "trace-1", "task_id": "task-1"},
        )

    assert event["run_id"] == "run-fail-safe"
    assert not (tmp_path / "run-fail-safe" / "events.jsonl").exists()
