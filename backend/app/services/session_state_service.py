from __future__ import annotations

import json
from typing import Any


def serialize_strategy_state(value: Any) -> str:
    return json.dumps(value or {}, ensure_ascii=False)


def deserialize_strategy_state(value: str | None) -> dict:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def can_continue_session(session_obj) -> tuple[bool, str | None]:
    if session_obj.max_rounds is not None and int(session_obj.rounds_completed or 0) >= int(session_obj.max_rounds):
        return False, "max_rounds_reached"

    if (
        session_obj.budget_requests_total is not None
        and int(session_obj.budget_requests_used or 0) >= int(session_obj.budget_requests_total)
    ):
        return False, "request_budget_exhausted"

    if (
        session_obj.budget_time_total is not None
        and int(session_obj.budget_time_used or 0) >= int(session_obj.budget_time_total)
    ):
        return False, "time_budget_exhausted"

    return True, None


def register_round(session_obj):
    session_obj.rounds_completed = int(session_obj.rounds_completed or 0) + 1


def register_requests(session_obj, request_count: int):
    session_obj.budget_requests_used = int(session_obj.budget_requests_used or 0) + int(request_count or 0)


def register_time_cost(session_obj, seconds_spent: int):
    session_obj.budget_time_used = int(session_obj.budget_time_used or 0) + int(seconds_spent or 0)


def update_strategy_state(session_obj, state: dict):
    merged = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    merged.update(state or {})
    session_obj.last_strategy_json = serialize_strategy_state(merged)
