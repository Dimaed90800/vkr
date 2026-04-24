import json

import pytest
from fastapi import HTTPException

from backend.api import routes_scheduling
from backend.models.scheduling import QueueUpdateRequest, QueueUpdateResponse, SchedulerState
from backend.models.testing import TaskModel
from backend.services.diagnostic_logging_service import DiagnosticLoggingService


def _task(task_id: str = "task_auth") -> TaskModel:
    return TaskModel(
        id=task_id,
        class_name="authorization",
        subtype="bola",
        endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        hypothesis="Cross-role access may be possible.",
        priority=90,
        allowed_tools=["auth_test_access"],
        readiness="ready_to_test",
        hypothesis_family="object_authorization",
        resource_family="vehicle",
    )


def test_update_queue_route_emits_start_and_finish_diagnostics(tmp_path, monkeypatch) -> None:
    routes_scheduling.task_scheduler.diagnostics = DiagnosticLoggingService(base_dir=tmp_path)
    active_task = _task()

    def fake_update_queue_after_verdict(**kwargs):
        return QueueUpdateResponse(
            pending_tasks=[],
            scheduler_state=kwargs["state"],
            queue_update_reason="verdict_rejected",
            should_stop=True,
        )

    monkeypatch.setattr(
        routes_scheduling.task_scheduler,
        "update_queue_after_verdict",
        fake_update_queue_after_verdict,
    )

    routes_scheduling.update_queue(
        QueueUpdateRequest(
            pending_tasks=[],
            active_task=active_task,
            verdict="rejected",
            scheduler_state=SchedulerState(run_id="run-route", root_trace_id="run-route"),
        )
    )

    events_path = tmp_path / "run-route" / "scheduler_api_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert [item["event_type"] for item in lines] == ["queue_update_start", "queue_update_finish"]
    assert lines[1]["reason"]["queue_update_reason"] == "verdict_rejected"


def test_update_queue_route_emits_traceback_on_unexpected_error(tmp_path, monkeypatch) -> None:
    routes_scheduling.task_scheduler.diagnostics = DiagnosticLoggingService(base_dir=tmp_path)

    def failing_update_queue_after_verdict(**kwargs):
        raise RuntimeError("boom")

    monkeypatch.setattr(
        routes_scheduling.task_scheduler,
        "update_queue_after_verdict",
        failing_update_queue_after_verdict,
    )

    with pytest.raises(HTTPException) as exc_info:
        routes_scheduling.update_queue(
            QueueUpdateRequest(
                pending_tasks=[],
                active_task=_task(),
                verdict="rejected",
                scheduler_state=SchedulerState(run_id="run-route-error", root_trace_id="run-route-error"),
            )
        )

    assert exc_info.value.status_code == 500
    events_path = tmp_path / "run-route-error" / "scheduler_api_events.jsonl"
    lines = [json.loads(line) for line in events_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    error_event = next(item for item in lines if item["event_type"] == "queue_update_error")
    assert error_event["reason"]["exception_type"] == "RuntimeError"
    assert "RuntimeError: boom" in error_event["artifacts"]["traceback_preview"]
