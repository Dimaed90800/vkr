from __future__ import annotations

from ..services.agent_runtime_service import run_agent_cycle_for_session


def generate_hypotheses_for_session(db, session_id: int) -> list[dict]:
    return run_agent_cycle_for_session(db, session_id)["hypotheses"]


def generate_hypotheses_runtime_for_session(db, session_id: int) -> dict:
    return run_agent_cycle_for_session(db, session_id)
