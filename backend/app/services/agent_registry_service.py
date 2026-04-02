from __future__ import annotations

import json


LOGICAL_AGENT_CATALOG = [
    {
        "logical_agent_name": "authentication_agent",
        "title": "Authentication Agent",
        "responsibility": "Builds authenticated session state, prepares roles and tokens, and performs support probing for follow-up attacks.",
        "role_class": "primary_attacker",
        "implementation_scope": "backend_plus_dify",
        "implementation_layers": ["backend_rule_based", "dify_workflow"],
        "internal_agents": [
            "rule_based_auth_agent",
            "rule_based_discovery_agent",
            "rule_based_probe_agent",
            "rule_based_analysis_agent",
            "dify_auth_agent",
            "rule_based_business_logic_agent",
            "rule_based_fallback_agent",
        ],
    },
    {
        "logical_agent_name": "authorization_agent",
        "title": "Authorization Agent",
        "responsibility": "Builds and verifies object-level authorization attack hypotheses (BOLA).",
        "role_class": "primary_attacker",
        "implementation_scope": "backend_plus_dify",
        "implementation_layers": ["backend_rule_based", "dify_workflow"],
        "internal_agents": [
            "rule_based_bola_agent",
            "dify_bola_agent",
        ],
    },
    {
        "logical_agent_name": "exposure_agent",
        "title": "Exposure Agent",
        "responsibility": "Detects and verifies excessive data exposure and object-property issues (BOPLA).",
        "role_class": "primary_attacker",
        "implementation_scope": "backend_plus_dify",
        "implementation_layers": ["backend_rule_based", "dify_workflow"],
        "internal_agents": [
            "rule_based_bopla_agent",
            "dify_bopla_agent",
            "rule_based_verifier_agent",
        ],
    },
    {
        "logical_agent_name": "judge_agent",
        "title": "Judge Agent",
        "responsibility": "Arbitrates between competing hypotheses and selects the next step.",
        "role_class": "judge_agent",
        "implementation_scope": "backend_plus_dify",
        "implementation_layers": ["backend_rule_based", "dify_workflow", "backend_unified"],
        "internal_agents": [],
    },
]


AGENT_CATALOG = [
    {
        "agent_name": "rule_based_auth_agent",
        "title": "Authentication Agent",
        "responsibility": "Creates roles, registers accounts, and obtains access tokens.",
        "role_class": "primary_attacker",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "auth",
        "logical_agent_name": "authentication_agent",
        "default_enabled": True,
        "hypothesis_types": [
            "bootstrap_roles",
            "register_role",
            "login_role",
            "login",
            "anonymous_probe",
            "tokenless_replay_probe",
            "auth_boundary_probe",
            "verify_auth_boundary",
        ],
        "test_classes": ["auth"],
    },
    {
        "agent_name": "rule_based_discovery_agent",
        "title": "Discovery Agent",
        "responsibility": "Expands API surface coverage through discovery follow-up actions.",
        "role_class": "supporting_agent",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "discovery",
        "logical_agent_name": "authentication_agent",
        "default_enabled": True,
        "hypothesis_types": ["discovery"],
        "test_classes": ["discovery"],
    },
    {
        "agent_name": "rule_based_probe_agent",
        "title": "Probe Agent",
        "responsibility": "Performs broad authenticated probing of high-value API endpoints.",
        "role_class": "supporting_agent",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "probe",
        "logical_agent_name": "authentication_agent",
        "default_enabled": True,
        "hypothesis_types": ["authenticated_probe"],
        "test_classes": ["auth", "access"],
    },
    {
        "agent_name": "rule_based_analysis_agent",
        "title": "Analysis Agent",
        "responsibility": "Compares collected observations and proposes cross-role analysis actions.",
        "role_class": "supporting_agent",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "analysis",
        "logical_agent_name": "authentication_agent",
        "default_enabled": True,
        "hypothesis_types": ["compare_roles"],
        "test_classes": ["auth", "access"],
    },
    {
        "agent_name": "rule_based_bola_agent",
        "title": "BOLA Agent",
        "responsibility": "Builds object-level authorization attack hypotheses from discovered identifiers.",
        "role_class": "primary_attacker",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "bola",
        "logical_agent_name": "authorization_agent",
        "default_enabled": True,
        "hypothesis_types": ["bola_probe"],
        "test_classes": ["bola"],
    },
    {
        "agent_name": "dify_bola_agent",
        "title": "Dify BOLA Agent",
        "responsibility": "Generates additional BOLA and verify-BOLA hypotheses through Dify workflow orchestration.",
        "role_class": "primary_attacker",
        "implementation_type": "dify",
        "provider": "dify",
        "adapter_key": "dify_bola",
        "logical_agent_name": "authorization_agent",
        "default_enabled": True,
        "hypothesis_types": ["bola_probe", "verify_bola"],
        "test_classes": ["bola"],
    },
    {
        "agent_name": "rule_based_bopla_agent",
        "title": "BOPLA Agent",
        "responsibility": "Detects excessive data exposure and object-property authorization issues.",
        "role_class": "primary_attacker",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "bopla",
        "logical_agent_name": "exposure_agent",
        "default_enabled": True,
        "hypothesis_types": ["bopla_probe"],
        "test_classes": ["bopla"],
    },
    {
        "agent_name": "dify_bopla_agent",
        "title": "Dify BOPLA Agent",
        "responsibility": "Future Dify-based agent for excessive data exposure and BOPLA hypotheses.",
        "role_class": "primary_attacker",
        "implementation_type": "dify",
        "provider": "dify",
        "adapter_key": "dify_bopla",
        "logical_agent_name": "exposure_agent",
        "default_enabled": False,
        "hypothesis_types": ["bopla_probe", "verify_bopla"],
        "test_classes": ["bopla"],
    },
    {
        "agent_name": "dify_auth_agent",
        "title": "Dify Auth Agent",
        "responsibility": "Generates authentication-boundary and token-misuse hypotheses through Dify workflow orchestration.",
        "role_class": "primary_attacker",
        "implementation_type": "dify",
        "provider": "dify",
        "adapter_key": "dify_auth",
        "logical_agent_name": "authentication_agent",
        "default_enabled": True,
        "hypothesis_types": [
            "bootstrap_roles",
            "register_role",
            "login_role",
            "login",
            "anonymous_probe",
            "tokenless_replay_probe",
            "auth_boundary_probe",
            "verify_auth_boundary",
        ],
        "test_classes": ["auth"],
    },
    {
        "agent_name": "rule_based_business_logic_agent",
        "title": "Business Logic Agent",
        "responsibility": "Future rule-based agent for workflow and business-logic abuse patterns.",
        "role_class": "primary_attacker",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "business_logic",
        "logical_agent_name": "authentication_agent",
        "default_enabled": False,
        "hypothesis_types": ["business_logic_probe"],
        "test_classes": ["business_logic"],
    },
    {
        "agent_name": "rule_based_verifier_agent",
        "title": "Verifier Agent",
        "responsibility": "Confirms candidate BOLA and BOPLA findings through repeat verification.",
        "role_class": "supporting_agent",
        "implementation_type": "rule_based",
        "provider": "local",
        "adapter_key": "verifier",
        "logical_agent_name": "exposure_agent",
        "default_enabled": True,
        "hypothesis_types": ["verify_bola", "verify_bopla"],
        "test_classes": ["bola", "bopla"],
    },
]

DEFAULT_ENABLED_AGENTS = [item["agent_name"] for item in AGENT_CATALOG if item.get("default_enabled", True)]


def get_agent_catalog() -> list[dict]:
    return AGENT_CATALOG.copy()


def get_logical_agent_catalog() -> list[dict]:
    return LOGICAL_AGENT_CATALOG.copy()


def get_agent_catalog_map() -> dict:
    return {item["agent_name"]: item for item in AGENT_CATALOG}


def get_logical_agent_catalog_map() -> dict:
    return {item["logical_agent_name"]: item for item in LOGICAL_AGENT_CATALOG}


def get_logical_agent_name(agent_name: str | None) -> str:
    catalog_map = get_agent_catalog_map()
    item = catalog_map.get(str(agent_name or "").strip())
    if item:
        return item.get("logical_agent_name", "authentication_agent")
    if agent_name == "rule_based_fallback_agent":
        return "authentication_agent"
    return "authentication_agent"


def normalize_enabled_agents(agent_names: list[str] | None) -> list[str]:
    catalog = get_agent_catalog_map()
    if not agent_names:
        return DEFAULT_ENABLED_AGENTS.copy()

    normalized = []
    seen = set()
    for name in agent_names:
        value = str(name or "").strip()
        if not value or value not in catalog or value in seen:
            continue
        seen.add(value)
        normalized.append(value)

    return normalized or DEFAULT_ENABLED_AGENTS.copy()


def load_enabled_agents_from_strategy_json(strategy_json: str | None) -> list[str]:
    if not strategy_json:
        return DEFAULT_ENABLED_AGENTS.copy()
    try:
        payload = json.loads(strategy_json)
    except Exception:
        return DEFAULT_ENABLED_AGENTS.copy()
    return normalize_enabled_agents(payload.get("enabled_agents"))


def build_session_agent_plan(session_obj) -> dict:
    enabled = load_enabled_agents_from_strategy_json(getattr(session_obj, "last_strategy_json", None))
    catalog_map = get_agent_catalog_map()
    logical_catalog_map = get_logical_agent_catalog_map()

    enabled_items = [catalog_map[name] for name in enabled if name in catalog_map]
    disabled_items = [
        item for item in AGENT_CATALOG
        if item["agent_name"] not in set(enabled)
    ]
    logical_enabled_names = sorted(
        {
            get_logical_agent_name(item["agent_name"])
            for item in enabled_items
        }
    )
    logical_enabled_agents = [
        logical_catalog_map[name]
        for name in logical_enabled_names
        if name in logical_catalog_map and name != "judge_agent"
    ]

    return {
        "session_id": getattr(session_obj, "id", None),
        "target_name": getattr(session_obj, "target_name", None),
        "enabled_agents": enabled_items,
        "disabled_agents": disabled_items,
        "enabled_agent_names": enabled,
        "enabled_agents_total": len(enabled_items),
        "logical_enabled_agents": logical_enabled_agents,
        "logical_enabled_agent_names": logical_enabled_names,
        "logical_enabled_agents_total": len(logical_enabled_agents),
    }
