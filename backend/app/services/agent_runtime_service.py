from __future__ import annotations

import logging
from collections import Counter

from ..models import Finding, Observation, RoleCredential, SurfaceInventory, TestSession
from ..services.agent_hypothesis_service import (
    generate_fallback_agent_hypotheses,
    safe_load_json,
    unique_hypotheses,
)
from ..services.agent_adapter_service import generate_hypotheses_for_agent
from ..services.agent_judge_feedback_service import apply_judge_feedback_to_hypotheses
from ..services.agent_memory_service import apply_agent_memory_to_hypotheses
from ..services.agent_registry_service import (
    get_agent_catalog,
    get_agent_catalog_map,
    get_logical_agent_catalog_map,
    get_logical_agent_name,
    load_enabled_agents_from_strategy_json,
)

logger = logging.getLogger(__name__)


def build_session_context(db, session_id: int) -> dict:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    inventory_items = db.query(SurfaceInventory).filter(
        SurfaceInventory.session_id == session_id
    ).all()
    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).order_by(Observation.id.asc()).all()
    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).order_by(RoleCredential.id.asc()).all()
    findings = db.query(Finding).filter(
        Finding.session_id == session_id
    ).order_by(Finding.id.asc()).all()

    return {
        "session": session_obj,
        "inventory_items": inventory_items,
        "api_items": [item for item in inventory_items if item.asset_type == "api"],
        "observations": observations,
        "roles": roles,
        "authenticated_roles": [role for role in roles if role.access_token],
        "findings": findings,
    }


def get_runtime_agent_specs() -> list[dict]:
    return get_agent_catalog()


def run_agent_cycle_for_session(db, session_id: int) -> dict:
    context = build_session_context(db, session_id)
    session_obj = context["session"]
    enabled_agents = load_enabled_agents_from_strategy_json(
        getattr(session_obj, "last_strategy_json", None)
    )
    specs_by_name = {spec["agent_name"]: spec for spec in get_runtime_agent_specs()}
    logical_catalog_map = get_logical_agent_catalog_map()

    raw_hypotheses = []
    agent_invocations = []

    for agent_name in enabled_agents:
        spec = specs_by_name.get(agent_name)
        if not spec:
            agent_invocations.append(
                {
                    "agent_name": agent_name,
                    "logical_agent_name": get_logical_agent_name(agent_name),
                    "title": agent_name,
                    "responsibility": "Unknown agent configuration",
                    "status": "skipped_unknown_agent",
                    "generated_hypotheses": 0,
                    "eligible_hypotheses": 0,
                    "hypothesis_types": [],
                }
            )
            continue

        try:
            generated = generate_hypotheses_for_agent(spec, context) or []
            status = "ok"
            error = None
        except Exception as exc:
            logger.warning("Agent %s failed for session %s: %s", agent_name, session_id, exc)
            generated = []
            status = "error"
            error = str(exc)

        raw_hypotheses.extend(generated)
        agent_invocations.append(
            {
                "agent_name": spec["agent_name"],
                "logical_agent_name": spec.get("logical_agent_name", get_logical_agent_name(spec["agent_name"])),
                "title": spec["title"],
                "responsibility": spec["responsibility"],
                "implementation_type": spec.get("implementation_type"),
                "provider": spec.get("provider"),
                "role_class": spec.get("role_class"),
                "status": status,
                "generated_hypotheses": len(generated),
                "eligible_hypotheses": 0,
                "hypothesis_types": sorted(
                    {item.get("hypothesis_type") for item in generated if item.get("hypothesis_type")}
                ),
                "error": error,
            }
        )

    if not raw_hypotheses:
        fallback_hypotheses = generate_fallback_agent_hypotheses()
        raw_hypotheses.extend(fallback_hypotheses)
        agent_invocations.append(
            {
                "agent_name": "rule_based_fallback_agent",
                "logical_agent_name": "authentication_agent",
                "title": "Fallback Agent",
                "responsibility": "Provides a safe discovery continuation when no agents produced hypotheses.",
                "implementation_type": "rule_based",
                "provider": "local",
                "role_class": "supporting_agent",
                "status": "system_fallback",
                "generated_hypotheses": len(fallback_hypotheses),
                "eligible_hypotheses": 0,
                "hypothesis_types": sorted(
                    {item.get("hypothesis_type") for item in fallback_hypotheses if item.get("hypothesis_type")}
                ),
                "error": None,
            }
        )

    hypotheses = _filter_allowed_hypotheses(
        raw_hypotheses,
        safe_load_json(getattr(session_obj, "allowed_test_classes_json", None)) or [],
    )
    hypotheses = apply_agent_memory_to_hypotheses(db, session_id, hypotheses)
    hypotheses = apply_judge_feedback_to_hypotheses(db, session_id, hypotheses)
    hypotheses = _annotate_hypotheses_with_orchestration(
        hypotheses,
        context=context,
        enabled_agents=enabled_agents,
        specs_by_name=specs_by_name,
    )
    hypotheses = unique_hypotheses(hypotheses)

    eligible_counts = Counter(item.get("agent_name") for item in hypotheses)
    for invocation in agent_invocations:
        invocation["eligible_hypotheses"] = eligible_counts.get(invocation["agent_name"], 0)
        invocation["participated"] = invocation["eligible_hypotheses"] > 0
        invocation["logical_title"] = (
            logical_catalog_map.get(invocation.get("logical_agent_name"), {}).get("title")
        )

    return {
        "session_context": context,
        "enabled_agents": enabled_agents,
        "enabled_logical_agents": sorted({get_logical_agent_name(name) for name in enabled_agents}),
        "agent_invocations": agent_invocations,
        "logical_agent_summary": _build_logical_agent_summary(agent_invocations, logical_catalog_map),
        "hypotheses": hypotheses,
    }


def _annotate_hypotheses_with_orchestration(
    hypotheses: list[dict],
    *,
    context: dict,
    enabled_agents: list[str],
    specs_by_name: dict,
) -> list[dict]:
    orchestration_context = {
        "enabled_agents": enabled_agents,
        "observations_total": len(context.get("observations") or []),
        "findings_total": len(context.get("findings") or []),
        "authenticated_roles_total": len(context.get("authenticated_roles") or []),
    }

    annotated = []
    for item in hypotheses:
        payload = dict(item.get("payload", {}))
        payload["orchestration_context"] = orchestration_context

        spec = specs_by_name.get(item.get("agent_name")) or {}
        if spec:
            payload["agent_role_class"] = spec.get("role_class")
            payload["agent_provider"] = spec.get("provider")
            payload["agent_implementation_type"] = spec.get("implementation_type")
            payload["logical_agent_name"] = spec.get("logical_agent_name", get_logical_agent_name(item.get("agent_name")))

        annotated.append(
            {
                **item,
                "payload": payload,
            }
        )
    return annotated


def _filter_allowed_hypotheses(hypotheses: list[dict], allowed_classes: list[str]) -> list[dict]:
    if not allowed_classes:
        return hypotheses

    filtered = []
    for item in hypotheses:
        hypothesis_type = item.get("hypothesis_type")

        if hypothesis_type == "discovery" and "discovery" in allowed_classes:
            filtered.append(item)
            continue
        if hypothesis_type in {"bola_probe", "verify_bola"} and "bola" in allowed_classes:
            filtered.append(item)
            continue
        if hypothesis_type in {"bopla_probe", "verify_bopla"} and "bopla" in allowed_classes:
            filtered.append(item)
            continue
        if hypothesis_type in {
            "register_role",
            "login_role",
            "login",
            "authenticated_probe",
            "compare_roles",
            "anonymous_probe",
            "tokenless_replay_probe",
            "auth_boundary_probe",
            "verify_auth_boundary",
        }:
            if "auth" in allowed_classes or "access" in allowed_classes:
                filtered.append(item)
                continue
        if hypothesis_type == "bootstrap_roles" and ("auth" in allowed_classes or "access" in allowed_classes):
            filtered.append(item)
            continue
        if "business_logic" in allowed_classes:
            filtered.append(item)

    return filtered


def _build_logical_agent_summary(agent_invocations: list[dict], logical_catalog_map: dict) -> dict:
    grouped = {}
    for item in agent_invocations or []:
        logical_agent_name = item.get("logical_agent_name") or get_logical_agent_name(item.get("agent_name"))
        logical_catalog = logical_catalog_map.get(logical_agent_name, {})
        entry = grouped.setdefault(
            logical_agent_name,
            {
                "logical_agent_name": logical_agent_name,
                "title": logical_catalog.get("title", logical_agent_name),
                "responsibility": logical_catalog.get("responsibility"),
                "role_class": logical_catalog.get("role_class", "primary_attacker"),
                "implementation_scope": logical_catalog.get("implementation_scope"),
                "implementation_layers": logical_catalog.get("implementation_layers", []),
                "internal_agents": [],
                "generated_hypotheses": 0,
                "eligible_hypotheses": 0,
                "participating_internal_agents": 0,
            },
        )
        entry["internal_agents"].append(item["agent_name"])
        entry["generated_hypotheses"] += int(item.get("generated_hypotheses", 0) or 0)
        entry["eligible_hypotheses"] += int(item.get("eligible_hypotheses", 0) or 0)
        if item.get("participated"):
            entry["participating_internal_agents"] += 1

    logical_agents = []
    for item in sorted(grouped.values(), key=lambda x: x["logical_agent_name"]):
        item["internal_agents"] = sorted(set(item["internal_agents"]))
        item["participated"] = item["eligible_hypotheses"] > 0
        logical_agents.append(item)

    return {
        "logical_agents_total": len(logical_agents),
        "logical_agents": logical_agents,
    }
