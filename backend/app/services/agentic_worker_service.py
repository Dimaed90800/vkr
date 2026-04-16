from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException

from ..models import TestSession
from .session_state_service import deserialize_strategy_state
from .hypothesis_service import generate_hypotheses_runtime_for_session


def _parse_payload_json(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _load_completed_task_ids(db, session_id: int, worker_family: str) -> set[str]:
    try:
        session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    except Exception:
        return set()
    if not session_obj:
        return set()

    strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    completed = strategy_state.get("completed_worker_tasks") or {}
    family_items = completed.get(worker_family) or []
    if not isinstance(family_items, list):
        return set()
    return {str(item) for item in family_items if str(item).strip()}


def build_bola_worker_tasks(db, session_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    runtime = generate_hypotheses_runtime_for_session(db, session_id)
    hypotheses = runtime.get("hypotheses", [])
    tasks = []
    completed_task_ids = _load_completed_task_ids(db, session_id, "bola")

    for item in hypotheses:
        if item.get("hypothesis_type") not in {"bola_probe", "verify_bola"}:
            continue

        payload = item.get("payload") or {}
        endpoint = item.get("target_endpoint")
        if not endpoint:
            continue
        task_id = str(item.get("candidate_key") or item.get("description") or f"bola-task-{len(tasks)+1}")
        if task_id in completed_task_ids:
            continue

        tasks.append(
            {
                "task_id": task_id,
                "session_id": session_id,
                "worker_type": "replay_agent" if item.get("hypothesis_type") == "bola_probe" else "comparison_agent",
                "vulnerability_class": "BOLA",
                "goal": item.get("description") or "Verify cross-role object access",
                "inputs": {
                    "endpoint": endpoint,
                    "method": item.get("http_method") or "GET",
                    "owner_role": payload.get("owner_role"),
                    "other_role": payload.get("other_role"),
                    "candidate_key": item.get("candidate_key"),
                    "finding_id": payload.get("finding_id"),
                    "source_observation_id": payload.get("source_observation_id"),
                },
                "allowed_tools": (
                    ["probe_same_object_across_roles", "compare_observations", "infer_bola"]
                    if item.get("hypothesis_type") == "bola_probe"
                    else ["compare_observations", "infer_bola", "list_observations"]
                ),
                "limits": {
                    "max_tool_calls": 3,
                    "max_retries": 2,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_bopla_worker_tasks(db, session_id: int, *, limit: int = 5) -> list[dict[str, Any]]:
    runtime = generate_hypotheses_runtime_for_session(db, session_id)
    hypotheses = runtime.get("hypotheses", [])
    tasks = []
    completed_task_ids = _load_completed_task_ids(db, session_id, "bopla")

    for item in hypotheses:
        if item.get("hypothesis_type") not in {"bopla_probe", "verify_bopla"}:
            continue

        payload = item.get("payload") or {}
        endpoint = item.get("target_endpoint")
        task_id = str(item.get("candidate_key") or item.get("description") or f"bopla-task-{len(tasks)+1}")
        if task_id in completed_task_ids:
            continue

        if item.get("hypothesis_type") == "bopla_probe":
            observation_id = payload.get("observation_id")
            if not observation_id:
                continue
            worker_type = "exposure_agent"
            allowed_tools = ["infer_bopla", "list_observations"]
        else:
            if not endpoint:
                continue
            worker_type = "replay_agent"
            allowed_tools = ["replay_request", "infer_bopla", "list_observations"]

        tasks.append(
            {
                "task_id": task_id,
                "session_id": session_id,
                "worker_type": worker_type,
                "vulnerability_class": "BOPLA",
                "goal": item.get("description") or "Check excessive data exposure",
                "inputs": {
                    "endpoint": endpoint,
                    "method": item.get("http_method") or "GET",
                    "candidate_key": item.get("candidate_key"),
                    "observation_id": payload.get("observation_id"),
                    "suspected_fields": payload.get("suspected_fields") or payload.get("expected_fields") or [],
                    "finding_id": payload.get("finding_id"),
                },
                "allowed_tools": allowed_tools,
                "limits": {
                    "max_tool_calls": 3,
                    "max_retries": 2,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_auth_worker_tasks(db, session_id: int, *, limit: int = 6) -> list[dict[str, Any]]:
    runtime = generate_hypotheses_runtime_for_session(db, session_id)
    hypotheses = runtime.get("hypotheses", [])
    tasks = []
    completed_task_ids = _load_completed_task_ids(db, session_id, "auth")

    for item in hypotheses:
        if item.get("hypothesis_type") not in {"bootstrap_roles", "register_role", "login_role"}:
            continue

        payload = item.get("payload") or {}
        hypothesis_type = item.get("hypothesis_type")
        task_id = str(item.get("candidate_key") or f"auth-task-{len(tasks)+1}")
        if task_id in completed_task_ids:
            continue
        if hypothesis_type == "bootstrap_roles":
            allowed_tools = ["bootstrap_roles", "list_roles"]
            worker_type = "auth_worker"
        elif hypothesis_type == "register_role":
            allowed_tools = ["register_role", "list_roles"]
            worker_type = "auth_worker"
        else:
            allowed_tools = ["login_role", "list_roles"]
            worker_type = "auth_worker"

        tasks.append(
            {
                "task_id": task_id,
                "session_id": session_id,
                "worker_type": worker_type,
                "vulnerability_class": "AUTH_SETUP",
                "goal": item.get("description") or "Prepare authenticated testing state",
                "inputs": {
                    "role_names": payload.get("role_names"),
                    "role_name": payload.get("role_name"),
                    "candidate_key": item.get("candidate_key"),
                },
                "allowed_tools": allowed_tools,
                "limits": {
                    "max_tool_calls": 2,
                    "max_retries": 2,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_probe_worker_tasks(db, session_id: int, *, limit: int = 6) -> list[dict[str, Any]]:
    runtime = generate_hypotheses_runtime_for_session(db, session_id)
    hypotheses = runtime.get("hypotheses", [])
    tasks = []
    completed_task_ids = _load_completed_task_ids(db, session_id, "probe")

    for item in hypotheses:
        if item.get("hypothesis_type") != "authenticated_probe":
            continue

        payload = item.get("payload") or {}
        endpoint = item.get("target_endpoint")
        if not endpoint:
            continue
        task_id = str(item.get("candidate_key") or f"probe-task-{len(tasks)+1}")
        if task_id in completed_task_ids:
            continue

        tasks.append(
            {
                "task_id": task_id,
                "session_id": session_id,
                "worker_type": "replay_agent",
                "vulnerability_class": "PROBE_SEED",
                "goal": item.get("description") or "Create authenticated observations for follow-up exploitation",
                "inputs": {
                    "endpoint": endpoint,
                    "method": item.get("http_method") or "GET",
                    "role_name": payload.get("role_name"),
                    "use_role_token": bool(payload.get("use_role_token")),
                    "headers": payload.get("headers") or {},
                    "candidate_key": item.get("candidate_key"),
                },
                "allowed_tools": ["replay_request", "list_observations"],
                "limits": {
                    "max_tool_calls": 2,
                    "max_retries": 1,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_discovery_worker_tasks(db, session_id: int, *, limit: int = 6) -> list[dict[str, Any]]:
    completed_task_ids = _load_completed_task_ids(db, session_id, "discovery")
    tasks = []
    catalog = [
        {
            "task_id": "discovery::openapi_inventory",
            "worker_type": "discovery_agent",
            "vulnerability_class": "DISCOVERY",
            "goal": "Discover and parse the OpenAPI document for the target API.",
            "allowed_tools": ["discover_openapi"],
            "inputs": {},
        },
        {
            "task_id": "discovery::zap_spider",
            "worker_type": "discovery_agent",
            "vulnerability_class": "DISCOVERY",
            "goal": "Run the ZAP spider to expand API inventory and collect discovered URLs.",
            "allowed_tools": ["zap_spider"],
            "inputs": {"max_wait_sec": 60},
        },
        {
            "task_id": "discovery::zap_ajax_spider",
            "worker_type": "discovery_agent",
            "vulnerability_class": "DISCOVERY",
            "goal": "Run the ZAP AJAX spider for JavaScript-driven API surface discovery.",
            "allowed_tools": ["zap_ajax_spider"],
            "inputs": {"max_wait_sec": 60},
        },
    ]

    for item in catalog:
        if item["task_id"] in completed_task_ids:
            continue
        tasks.append(
            {
                "task_id": item["task_id"],
                "session_id": session_id,
                "worker_type": item["worker_type"],
                "vulnerability_class": item["vulnerability_class"],
                "goal": item["goal"],
                "inputs": item["inputs"],
                "allowed_tools": item["allowed_tools"],
                "limits": {
                    "max_tool_calls": 1,
                    "max_retries": 1,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_dast_worker_tasks(db, session_id: int, *, limit: int = 4) -> list[dict[str, Any]]:
    completed_task_ids = _load_completed_task_ids(db, session_id, "dast")
    tasks = []
    catalog = [
        {
            "task_id": "dast::zap_baseline_scan",
            "worker_type": "dast_agent",
            "vulnerability_class": "DAST",
            "goal": "Run the normalized ZAP baseline scan for generic API security findings.",
            "allowed_tools": ["zap_baseline_scan"],
            "inputs": {
                "profile": "mixed",
                # Keep DAST bounded enough for the main orchestration workflow.
                "max_spider_sec": 20,
                "max_active_sec": 45,
                "use_ajax_spider": False,
                "import_openapi": True,
            },
        },
        {
            "task_id": "dast::zap_active_scan",
            "worker_type": "dast_agent",
            "vulnerability_class": "DAST",
            "goal": "Run a bounded ZAP active scan against the current target.",
            "allowed_tools": ["zap_active_scan"],
            "inputs": {
                "max_wait_sec": 45,
                "recurse": False,
            },
        },
    ]

    for item in catalog:
        if item["task_id"] in completed_task_ids:
            continue
        tasks.append(
            {
                "task_id": item["task_id"],
                "session_id": session_id,
                "worker_type": item["worker_type"],
                "vulnerability_class": item["vulnerability_class"],
                "goal": item["goal"],
                "inputs": item["inputs"],
                "allowed_tools": item["allowed_tools"],
                "limits": {
                    "max_tool_calls": 1,
                    "max_retries": 1,
                },
            }
        )
        if len(tasks) >= limit:
            break

    return tasks


def build_worker_task_bundle(db, session_id: int, worker_family: str) -> dict[str, Any]:
    worker_family = str(worker_family or "").strip().lower()
    if worker_family == "bola":
        tasks = build_bola_worker_tasks(db, session_id)
    elif worker_family == "bopla":
        tasks = build_bopla_worker_tasks(db, session_id)
    elif worker_family == "auth":
        tasks = build_auth_worker_tasks(db, session_id)
    elif worker_family == "probe":
        tasks = build_probe_worker_tasks(db, session_id)
    elif worker_family == "discovery":
        tasks = build_discovery_worker_tasks(db, session_id)
    elif worker_family == "dast":
        tasks = build_dast_worker_tasks(db, session_id)
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported worker family '{worker_family}'")
    completed_task_ids = sorted(_load_completed_task_ids(db, session_id, worker_family))
    return {
        "session_id": session_id,
        "worker_family": worker_family,
        "completed_task_ids": completed_task_ids,
        "tasks_total": len(tasks),
        "tasks": tasks,
    }
