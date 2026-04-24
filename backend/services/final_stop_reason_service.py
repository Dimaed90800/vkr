from __future__ import annotations

from typing import Any

try:
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from services.wrapper_observability import append_run_event


SOFT_STOP_REASONS = {
    "",
    "all_class_budgets_exhausted",
    "fallback_single_class_queue",
    "no_runnable_tasks",
    "no_tasks",
}


def resolve_final_stop_reason(state: dict[str, Any], scheduler: dict[str, Any] | None = None) -> dict[str, Any]:
    scheduler = scheduler or {}
    existing_resolution = state.get("final_stop_reason_resolution")
    if isinstance(existing_resolution, dict) and _clean(existing_resolution.get("resolved_final_stop_reason")):
        return {
            "raw_state_stop_reason": _clean(
                existing_resolution.get("raw_state_stop_reason")
                or state.get("raw_stop_reason_before_resolution")
                or state.get("stop_reason")
            ),
            "scheduler_selection_reason": _clean(existing_resolution.get("scheduler_selection_reason")),
            "transient_stop_reason": _clean(existing_resolution.get("transient_stop_reason")),
            "soft_stop_fallback_used": bool(existing_resolution.get("soft_stop_fallback_used")),
            "resolved_final_stop_reason": _clean(existing_resolution.get("resolved_final_stop_reason")),
        }

    raw_state_reason = _clean(state.get("raw_stop_reason_before_resolution") or state.get("stop_reason"))
    explicit_final_reason = _clean(state.get("final_stop_reason"))
    scheduler_selection_reason = _clean(
        state.get("scheduler_stop_reason")
        or state.get("last_scheduler_stop_reason")
        or scheduler.get("selection_reason")
        or scheduler.get("stop_reason")
    )
    transient_stop_reason = _clean(state.get("transient_stop_reason"))
    soft_stop_fallback = bool(state.get("soft_stop_fallback_used") or state.get("continued_after_soft_stop"))

    if explicit_final_reason:
        resolved = explicit_final_reason
    elif raw_state_reason == "timeout" and scheduler_selection_reason and scheduler_selection_reason != "timeout":
        resolved = scheduler_selection_reason
    elif transient_stop_reason == "timeout" and scheduler_selection_reason and scheduler_selection_reason != "timeout":
        resolved = scheduler_selection_reason
    elif soft_stop_fallback and scheduler_selection_reason and scheduler_selection_reason not in SOFT_STOP_REASONS:
        resolved = scheduler_selection_reason
    else:
        resolved = raw_state_reason or scheduler_selection_reason or "loop_finished"

    return {
        "raw_state_stop_reason": raw_state_reason,
        "scheduler_selection_reason": scheduler_selection_reason,
        "transient_stop_reason": transient_stop_reason,
        "soft_stop_fallback_used": soft_stop_fallback,
        "resolved_final_stop_reason": resolved,
    }


def log_final_stop_reason_resolution(
    *,
    run_id: str | None,
    state: dict[str, Any],
    scheduler: dict[str, Any] | None = None,
) -> dict[str, Any]:
    resolution = resolve_final_stop_reason(state, scheduler)
    append_run_event(
        event_name="final_stop_reason_resolved",
        run_id=run_id,
        status="ok",
        summary="Resolved final report stop reason.",
        reason={
            "raw_state_stop_reason": resolution["raw_state_stop_reason"],
            "scheduler_selection_reason": resolution["scheduler_selection_reason"],
            "resolved_final_stop_reason": resolution["resolved_final_stop_reason"],
        },
        extra={
            "transient_stop_reason": resolution["transient_stop_reason"],
            "soft_stop_fallback_used": resolution["soft_stop_fallback_used"],
        },
    )
    return resolution


def _clean(value: Any) -> str:
    return str(value or "").strip()
