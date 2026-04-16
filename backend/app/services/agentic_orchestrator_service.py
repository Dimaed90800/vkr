from __future__ import annotations

import json
from typing import Any

from .agentic_tool_service import get_allowed_agentic_tools


ORCHESTRATOR_AGENT_CATALOG = [
    {
        "agent_name": "replay_auth_agent",
        "title": "Replay/Auth Agent",
        "role_class": "preparation",
        "responsibility": "Prepares authenticated roles, obtains tokens, and creates replay-ready probe seeds.",
        "covers": ["auth", "bola", "bopla", "bfla"],
        "worker_families": ["auth", "probe"],
        "tools": [
            "bootstrap_roles",
            "register_role",
            "login_role",
            "replay_request",
            "list_roles",
            "list_observations",
        ],
        "status": "active",
        "default_selected": True,
    },
    {
        "agent_name": "discovery_agent",
        "title": "Discovery Agent",
        "role_class": "discovery",
        "responsibility": "Expands API inventory and discovers attack surface through OpenAPI and ZAP spidering.",
        "covers": ["discovery", "inventory", "bola", "bopla", "ssrf", "injection"],
        "worker_families": ["discovery"],
        "tools": [
            "discover_openapi",
            "zap_spider",
            "zap_ajax_spider",
        ],
        "status": "active",
        "default_selected": True,
    },
    {
        "agent_name": "access_control_agent",
        "title": "Access Control Agent",
        "role_class": "exploitation",
        "responsibility": "Searches for and verifies object-level and property-level access control flaws.",
        "covers": ["bola", "bopla", "bfla", "access_control"],
        "worker_families": ["bola", "bopla"],
        "tools": [
            "replay_request",
            "probe_same_object_across_roles",
            "compare_observations",
            "infer_bola",
            "infer_bopla",
            "list_observations",
        ],
        "status": "active",
        "default_selected": True,
    },
    {
        "agent_name": "dast_agent",
        "title": "DAST Agent",
        "role_class": "scanner",
        "responsibility": "Runs generic DAST scanning to surface broad security signals and suspicious routes.",
        "covers": ["dast", "misconfiguration", "generic_api_risk"],
        "worker_families": ["dast"],
        "tools": [
            "zap_active_scan",
            "zap_baseline_scan",
        ],
        "status": "active",
        "default_selected": True,
    },
    {
        "agent_name": "ssrf_agent",
        "title": "SSRF Agent",
        "role_class": "exploitation",
        "responsibility": "Uses URL and body override techniques to probe server-side request forgery candidates.",
        "covers": ["ssrf"],
        "worker_families": ["ssrf"],
        "tools": [
            "replay_with_param_override",
            "replay_with_body_override",
        ],
        "status": "planned",
        "default_selected": False,
    },
    {
        "agent_name": "injection_agent",
        "title": "Injection Agent",
        "role_class": "exploitation",
        "responsibility": "Runs payload-based and timing-based probes for injection candidates.",
        "covers": ["injection", "sqli", "command_injection", "nosqli"],
        "worker_families": ["injection"],
        "tools": [
            "replay_with_payloads",
            "measure_timing_delta",
        ],
        "status": "planned",
        "default_selected": False,
    },
    {
        "agent_name": "stateful_workflow_agent",
        "title": "Stateful Workflow Agent",
        "role_class": "exploitation",
        "responsibility": "Future agent for multi-step business logic and stateful workflow issues.",
        "covers": ["business_logic", "stateful_flows"],
        "worker_families": ["stateful"],
        "tools": [],
        "status": "planned",
        "default_selected": False,
    },
    {
        "agent_name": "judge_agent",
        "title": "Judge Agent",
        "role_class": "verification",
        "responsibility": "Confirms or rejects candidate findings strictly from evidence.",
        "covers": ["verification"],
        "worker_families": [],
        "tools": [],
        "status": "active",
        "default_selected": True,
    },
    {
        "agent_name": "report_agent",
        "title": "Report Agent",
        "role_class": "reporting",
        "responsibility": "Builds the final report from confirmed findings.",
        "covers": ["reporting"],
        "worker_families": [],
        "tools": [],
        "status": "active",
        "default_selected": True,
    },
]


_KEYWORD_TO_AGENT = {
    "bola": "access_control_agent",
    "idor": "access_control_agent",
    "bopla": "access_control_agent",
    "bfla": "access_control_agent",
    "access control": "access_control_agent",
    "authorization": "access_control_agent",
    "discovery": "discovery_agent",
    "inventory": "discovery_agent",
    "openapi": "discovery_agent",
    "zap": "dast_agent",
    "dast": "dast_agent",
    "scan": "dast_agent",
    "ssrf": "ssrf_agent",
    "injection": "injection_agent",
    "sqli": "injection_agent",
    "sql injection": "injection_agent",
    "command injection": "injection_agent",
    "business logic": "stateful_workflow_agent",
    "stateful": "stateful_workflow_agent",
    "auth": "replay_auth_agent",
    "authentication": "replay_auth_agent",
}


def get_orchestrator_agent_catalog() -> list[dict[str, Any]]:
    available_tools = set(get_allowed_agentic_tools())
    catalog = []
    for item in ORCHESTRATOR_AGENT_CATALOG:
        agent = dict(item)
        tools = list(agent.get("tools") or [])
        agent["tools_available"] = [tool for tool in tools if tool in available_tools]
        agent["tools_missing"] = [tool for tool in tools if tool not in available_tools]
        if agent["status"] == "active" and agent["tools_missing"]:
            agent["status"] = "partial"
        catalog.append(agent)
    return catalog


def _safe_json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _prompt_to_selected_agents(user_prompt: str, allowed_test_classes: list[str] | None) -> list[str]:
    prompt = str(user_prompt or "").lower()
    allowed = {str(item or "").strip().lower() for item in (allowed_test_classes or []) if str(item or "").strip()}
    selected = {"replay_auth_agent", "judge_agent", "report_agent"}

    wants_all = any(
        marker in prompt
        for marker in [
            "find all",
            "full analysis",
            "analyze everything",
            "all vulnerabilities",
            "найди все",
            "все уязвимости",
            "полный анализ",
            "проверь все",
        ]
    )

    if wants_all:
        selected.update(["discovery_agent", "access_control_agent", "dast_agent"])

    for keyword, agent_name in _KEYWORD_TO_AGENT.items():
        if keyword in prompt:
            selected.add(agent_name)

    if "bola" in allowed or "bopla" in allowed:
        selected.add("access_control_agent")
    if "discovery" in allowed:
        selected.add("discovery_agent")
    if "ssrf" in allowed:
        selected.add("ssrf_agent")
    if "injection" in allowed:
        selected.add("injection_agent")

    order = [
        "replay_auth_agent",
        "discovery_agent",
        "access_control_agent",
        "dast_agent",
        "ssrf_agent",
        "injection_agent",
        "stateful_workflow_agent",
        "judge_agent",
        "report_agent",
    ]
    return [name for name in order if name in selected]


def build_orchestrator_plan(session_obj) -> dict[str, Any]:
    strategy_state = {}
    try:
        strategy_state = json.loads(getattr(session_obj, "last_strategy_json", None) or "{}")
    except Exception:
        strategy_state = {}

    user_prompt = str(strategy_state.get("user_prompt") or "")
    allowed_test_classes = _safe_json_list(getattr(session_obj, "allowed_test_classes_json", None))
    selected_names = _prompt_to_selected_agents(user_prompt, allowed_test_classes)
    catalog_map = {item["agent_name"]: item for item in get_orchestrator_agent_catalog()}
    selected_agents = [catalog_map[name] for name in selected_names if name in catalog_map]

    execution_plan = []
    for agent in selected_agents:
        if agent["agent_name"] == "replay_auth_agent":
            execution_plan.extend(
                [
                    {"phase": "preparation", "agent_name": agent["agent_name"], "worker_family": "auth"},
                    {"phase": "preparation", "agent_name": agent["agent_name"], "worker_family": "probe"},
                ]
            )
        elif agent["agent_name"] == "access_control_agent":
            execution_plan.extend(
                [
                    {"phase": "exploitation", "agent_name": agent["agent_name"], "worker_family": "bola"},
                    {"phase": "exploitation", "agent_name": agent["agent_name"], "worker_family": "bopla"},
                ]
            )
        elif agent.get("worker_families"):
            for family in agent["worker_families"]:
                phase = "discovery" if family in {"discovery", "dast"} else "exploitation"
                execution_plan.append(
                    {"phase": phase, "agent_name": agent["agent_name"], "worker_family": family}
                )
        else:
            execution_plan.append(
                {
                    "phase": agent.get("role_class"),
                    "agent_name": agent["agent_name"],
                    "worker_family": None,
                    "tools": agent.get("tools_available", []),
                }
            )

    return {
        "session_id": getattr(session_obj, "id", None),
        "target_name": getattr(session_obj, "target_name", None),
        "target_url": getattr(session_obj, "target_url", None),
        "user_prompt": user_prompt,
        "allowed_test_classes": allowed_test_classes,
        "selected_agent_names": selected_names,
        "selected_agents": selected_agents,
        "execution_plan": execution_plan,
        "catalog": get_orchestrator_agent_catalog(),
    }
