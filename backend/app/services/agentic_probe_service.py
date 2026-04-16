from __future__ import annotations

from typing import Any

from ..models import SurfaceInventory, TestSession
from .agentic_tool_service import execute_agentic_tool_command
from .agentic_worker_service import build_probe_worker_tasks
from .discovery_service import persist_discovery_results


def _inventory_api_total(db, session_id: int) -> int:
    return db.query(SurfaceInventory).filter(
        SurfaceInventory.session_id == session_id,
        SurfaceInventory.asset_type == "api",
    ).count()


def ensure_seed_inventory(db, session_id: int) -> dict[str, Any]:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise ValueError("Session not found")

    if _inventory_api_total(db, session_id) > 0:
        return {
            "seeded": False,
            "reason": "inventory_already_present",
            "api_items_total": _inventory_api_total(db, session_id),
        }

    persisted = persist_discovery_results(
        db=db,
        session_obj=session_obj,
        urls=[],
        source_type="agentic_seed_inventory",
        confidence=0.7,
    )
    return {
        "seeded": True,
        "reason": "seed_inventory_created",
        "saved_urls": persisted.get("saved_urls", 0),
        "api_items_total": len(persisted.get("api_urls") or []),
    }


def prepare_probe_seeds(db, session_id: int, *, max_steps: int = 4) -> dict[str, Any]:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise ValueError("Session not found")

    max_steps = max(1, min(int(max_steps or 4), 20))
    seed_result = ensure_seed_inventory(db, session_id)
    executed_steps: list[dict[str, Any]] = []

    for _ in range(max_steps):
        tasks = build_probe_worker_tasks(db, session_id, limit=10)
        if not tasks:
            return {
                "session_id": session_id,
                "ready": False,
                "reason": "no_probe_tasks_available",
                "seed_inventory": seed_result,
                "executed_steps": executed_steps,
            }

        task = tasks[0]
        inputs = dict(task.get("inputs") or {})
        arguments = {
            "session_id": session_id,
            "endpoint": inputs.get("endpoint"),
            "method": inputs.get("method") or "GET",
            "role_name": inputs.get("role_name"),
            "use_role_token": bool(inputs.get("use_role_token")),
            "headers": inputs.get("headers") or {},
        }
        result = execute_agentic_tool_command(
            db,
            tool_name="replay_request",
            arguments=arguments,
        )
        executed_steps.append(
            {
                "task_id": task.get("task_id"),
                "goal": task.get("goal"),
                "tool_name": "replay_request",
                "result": result,
            }
        )

    return {
        "session_id": session_id,
        "ready": True,
        "reason": "probe_seed_budget_used",
        "seed_inventory": seed_result,
        "executed_steps": executed_steps,
    }
