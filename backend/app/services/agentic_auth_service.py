from __future__ import annotations

from typing import Any

from ..models import RoleCredential, TestSession
from .agentic_tool_service import execute_agentic_tool_command
from .agentic_worker_service import build_auth_worker_tasks


def _role_state_snapshot(db, session_id: int) -> list[dict[str, Any]]:
    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).order_by(RoleCredential.id.asc()).all()
    return [
        {
            "role_name": item.role_name,
            "status": item.status,
            "has_access_token": bool(item.access_token),
            "last_auth_status": item.last_auth_status,
        }
        for item in roles
    ]


def _authenticated_roles_total(db, session_id: int) -> int:
    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).all()
    return sum(1 for item in roles if getattr(item, "access_token", None))


def prepare_auth_state(db, session_id: int, *, max_steps: int = 6) -> dict[str, Any]:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise ValueError("Session not found")

    max_steps = max(1, min(int(max_steps or 6), 20))
    executed_steps: list[dict[str, Any]] = []

    for _ in range(max_steps):
        if _authenticated_roles_total(db, session_id) >= 2:
            session_obj.status = "active"
            db.commit()
            return {
                "session_id": session_id,
                "ready": True,
                "reason": "two_authenticated_roles_available",
                "executed_steps": executed_steps,
                "roles": _role_state_snapshot(db, session_id),
            }

        tasks = build_auth_worker_tasks(db, session_id, limit=10)
        if not tasks:
            return {
                "session_id": session_id,
                "ready": False,
                "reason": "no_auth_tasks_available",
                "executed_steps": executed_steps,
                "roles": _role_state_snapshot(db, session_id),
            }

        task = tasks[0]
        tool_name = (task.get("allowed_tools") or [None])[0]
        inputs = dict(task.get("inputs") or {})
        arguments = {"session_id": session_id}
        if inputs.get("role_names"):
            arguments["role_names"] = inputs["role_names"]
        if inputs.get("role_name"):
            arguments["role_name"] = inputs["role_name"]

        result = execute_agentic_tool_command(
            db,
            tool_name=tool_name,
            arguments=arguments,
        )
        executed_steps.append(
            {
                "task_id": task.get("task_id"),
                "goal": task.get("goal"),
                "tool_name": tool_name,
                "result": result,
            }
        )

    ready = _authenticated_roles_total(db, session_id) >= 2
    if ready:
        session_obj.status = "active"
        db.commit()

    return {
        "session_id": session_id,
        "ready": ready,
        "reason": "auth_step_budget_exhausted" if not ready else "two_authenticated_roles_available",
        "executed_steps": executed_steps,
        "roles": _role_state_snapshot(db, session_id),
    }
