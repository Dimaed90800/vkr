from backend.services.final_stop_reason_service import resolve_final_stop_reason


def test_timeout_transient_stop_resolves_to_scheduler_budget_exhaustion() -> None:
    resolution = resolve_final_stop_reason(
        {
            "stop_reason": "timeout",
            "scheduler_stop_reason": "all_class_budgets_exhausted",
            "soft_stop_fallback_used": True,
        }
    )

    assert resolution["raw_state_stop_reason"] == "timeout"
    assert resolution["scheduler_selection_reason"] == "all_class_budgets_exhausted"
    assert resolution["resolved_final_stop_reason"] == "all_class_budgets_exhausted"


def test_true_timeout_remains_timeout_without_later_scheduler_reason() -> None:
    resolution = resolve_final_stop_reason({"stop_reason": "timeout"})

    assert resolution["resolved_final_stop_reason"] == "timeout"


def test_transient_timeout_after_soft_fallback_resolves_to_scheduler_reason() -> None:
    resolution = resolve_final_stop_reason(
        {
            "stop_reason": "all_class_budgets_exhausted",
            "transient_stop_reason": "timeout",
            "scheduler_stop_reason": "all_class_budgets_exhausted",
            "soft_stop_fallback_used": True,
        }
    )

    assert resolution["transient_stop_reason"] == "timeout"
    assert resolution["resolved_final_stop_reason"] == "all_class_budgets_exhausted"
