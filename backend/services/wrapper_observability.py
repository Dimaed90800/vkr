from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
except ModuleNotFoundError:  # pragma: no cover
    from services.diagnostic_logging_service import DiagnosticLoggingService


diagnostic_logger = DiagnosticLoggingService()


def wrapper_trace_context(
    *,
    run_id: str | None,
    task_id: str | None = None,
    worker_role: str | None = None,
    tool_name: str | None = None,
    target_url: str | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    context = {
        "run_id": run_id,
        "root_trace_id": run_id,
        "task_id": task_id,
        "worker_role": worker_role,
        "tool_name": tool_name,
        "target_url": target_url,
    }
    if extra:
        context.update(extra)
    return context


def append_run_event(
    *,
    event_name: str,
    run_id: str | None,
    task_id: str | None = None,
    worker_role: str | None = None,
    tool_name: str | None = None,
    status: str = "info",
    summary: str | None = None,
    target_url: str | None = None,
    reason: dict[str, Any] | None = None,
    counters: dict[str, Any] | None = None,
    artifacts: dict[str, Any] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload_extra = {"event_name": event_name}
    if extra:
        payload_extra.update(extra)
    return diagnostic_logger.emit(
        event_type=event_name,
        component="wrapper",
        status=status,
        summary=summary or event_name,
        run_id=run_id,
        trace_context=wrapper_trace_context(
            run_id=run_id,
            task_id=task_id,
            worker_role=worker_role,
            tool_name=tool_name,
            target_url=target_url,
        ),
        reason=reason,
        counters=counters,
        artifacts=artifacts,
        extra=payload_extra,
    )


def run_events_path(run_id: str | None) -> Path:
    return diagnostic_logger.event_paths(run_id or "")["events"]
