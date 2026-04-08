from __future__ import annotations

import json

from .agent_registry_service import (
    get_agent_catalog_map,
    get_logical_agent_catalog_map,
    get_logical_agent_name,
)
from .agent_judge_feedback_service import build_agent_judge_feedback_summary
from .judge_trace_service import classify_dify_issue


def _safe_load_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return value


def _safe_list(value):
    if isinstance(value, list):
        return value
    return []


def _sanitize_headers(headers, role_name: str | None = None):
    if not isinstance(headers, dict):
        return {}

    sanitized = {}
    for key, value in headers.items():
        key_str = str(key)
        if key_str.lower() == "authorization" and value:
            token_label = (role_name or "ROLE").upper()
            sanitized[key_str] = f"Bearer <{token_label}_TOKEN>"
        else:
            sanitized[key_str] = value
    return sanitized


def _load_observation_ids(finding, evidence: dict):
    observation_ids = []
    related_ids = _safe_load_json(getattr(finding, "related_observation_ids", None))
    if isinstance(related_ids, list):
        observation_ids.extend(related_ids)

    for key in [
        "observation_id",
        "source_observation_id",
        "observation_owner_id",
        "observation_other_id",
        "observation_a_id",
        "observation_b_id",
    ]:
        value = evidence.get(key)
        if value not in (None, ""):
            observation_ids.append(value)

    normalized = []
    seen = set()
    for item in observation_ids:
        try:
            item_int = int(item)
        except Exception:
            continue
        if item_int in seen:
            continue
        seen.add(item_int)
        normalized.append(item_int)
    return normalized


def _build_replay_requests(observations_by_id, observation_ids):
    replay_requests = []
    for observation_id in observation_ids:
        obs = observations_by_id.get(observation_id)
        if not obs:
            continue

        request_headers = _safe_load_json(getattr(obs, "request_headers", None)) or {}
        request_params = _safe_load_json(getattr(obs, "request_params", None)) or {}
        request_body = _safe_load_json(getattr(obs, "request_body", None)) or {}

        replay_requests.append(
            {
                "observation_id": getattr(obs, "id", None),
                "role_name": getattr(obs, "role_name", None),
                "method": getattr(obs, "method", None),
                "endpoint": getattr(obs, "endpoint", None),
                "status_code": getattr(obs, "status_code", None),
                "request_headers": _sanitize_headers(request_headers, getattr(obs, "role_name", None)),
                "request_params": request_params if isinstance(request_params, dict) else {},
                "request_body": request_body if isinstance(request_body, (dict, list)) else request_body,
                "curl_template": (
                    f"curl -X {(getattr(obs, 'method', None) or 'GET').upper()} "
                    f"'{getattr(obs, 'endpoint', '')}'"
                ),
            }
        )
    return replay_requests


def _build_evidence_bundle(finding, observations):
    evidence = _safe_load_json(getattr(finding, "evidence_json", None)) or {}
    observations_by_id = {
        getattr(obs, "id", None): obs
        for obs in (observations or [])
        if getattr(obs, "id", None) is not None
    }
    observation_ids = _load_observation_ids(finding, evidence)
    replay_requests = _build_replay_requests(observations_by_id, observation_ids)

    compact_evidence = {
        "signals": _safe_list(evidence.get("signals"))[:8],
        "exposed_fields": _safe_list(evidence.get("exposed_fields"))[:8],
        "owner_role": evidence.get("owner_role"),
        "other_role": evidence.get("other_role"),
        "status_owner": evidence.get("status_owner"),
        "status_other": evidence.get("status_other"),
        "owner_object_id": evidence.get("owner_object_id"),
        "other_object_id": evidence.get("other_object_id"),
        "suspected_fields": _safe_list(evidence.get("suspected_fields"))[:8],
        "status_code": evidence.get("status_code"),
        "action_executed": evidence.get("action_executed"),
        "inference": evidence.get("inference"),
    }

    return {
        "finding_id": getattr(finding, "id", None),
        "finding_type": getattr(finding, "finding_type", None),
        "verification_status": getattr(finding, "verification_status", None),
        "endpoint": getattr(finding, "endpoint", None),
        "observation_ids": observation_ids,
        "replay_requests": replay_requests,
        "evidence": compact_evidence,
        "reproducibility": {
            "has_replay_requests": bool(replay_requests),
            "replay_request_count": len(replay_requests),
            "has_comparison_roles": bool(
                compact_evidence.get("owner_role") or compact_evidence.get("other_role")
            ),
            "has_sensitive_fields": bool(compact_evidence.get("exposed_fields")),
        },
    }


def build_agent_activity_summary(hypotheses, judge_decisions):
    generated_by_agent = {}
    selected_by_agent = {}

    hypotheses_by_id = {h.id: h for h in hypotheses}

    for hypothesis in hypotheses:
        agent_name = getattr(hypothesis, "agent_name", "unknown_agent")
        generated_by_agent[agent_name] = generated_by_agent.get(agent_name, 0) + 1

    for decision in judge_decisions:
        hypothesis = hypotheses_by_id.get(getattr(decision, "selected_hypothesis_id", None))
        if not hypothesis:
            continue
        agent_name = getattr(hypothesis, "agent_name", "unknown_agent")
        selected_by_agent[agent_name] = selected_by_agent.get(agent_name, 0) + 1

    agent_names = sorted(set(generated_by_agent.keys()) | set(selected_by_agent.keys()))
    return {
        "agents_total": len(agent_names),
        "agents": [
            {
                "agent_name": agent_name,
                "generated_hypotheses": generated_by_agent.get(agent_name, 0),
                "selected_hypotheses": selected_by_agent.get(agent_name, 0),
            }
            for agent_name in agent_names
        ],
    }


def build_logical_agent_activity_summary(hypotheses, judge_decisions):
    generated_by_agent = {}
    selected_by_agent = {}

    hypotheses_by_id = {h.id: h for h in hypotheses}

    for hypothesis in hypotheses:
        logical_agent_name = get_logical_agent_name(getattr(hypothesis, "agent_name", None))
        generated_by_agent[logical_agent_name] = generated_by_agent.get(logical_agent_name, 0) + 1

    for decision in judge_decisions:
        hypothesis = hypotheses_by_id.get(getattr(decision, "selected_hypothesis_id", None))
        if not hypothesis:
            continue
        logical_agent_name = get_logical_agent_name(getattr(hypothesis, "agent_name", None))
        selected_by_agent[logical_agent_name] = selected_by_agent.get(logical_agent_name, 0) + 1

    logical_catalog_map = get_logical_agent_catalog_map()
    logical_agent_names = sorted(set(generated_by_agent.keys()) | set(selected_by_agent.keys()))
    return {
        "logical_agents_total": len(logical_agent_names),
        "logical_agents": [
            {
                "logical_agent_name": logical_agent_name,
                "title": logical_catalog_map.get(logical_agent_name, {}).get("title"),
                "implementation_scope": logical_catalog_map.get(logical_agent_name, {}).get("implementation_scope"),
                "implementation_layers": logical_catalog_map.get(logical_agent_name, {}).get("implementation_layers", []),
                "generated_hypotheses": generated_by_agent.get(logical_agent_name, 0),
                "selected_hypotheses": selected_by_agent.get(logical_agent_name, 0),
            }
            for logical_agent_name in logical_agent_names
        ],
    }


def build_agent_learning_summary(memory_rows):
    if not memory_rows:
        return {
            "agents_total": 0,
            "agents": [],
        }

    grouped = {}
    for row in memory_rows:
        item = grouped.setdefault(
            row.agent_name,
            {
                "agent_name": row.agent_name,
                "memory_patterns": 0,
                "attempts": 0,
                "selected_count": 0,
                "confirmed_count": 0,
                "rejected_count": 0,
                "avg_cost": 0.0,
            },
        )
        item["memory_patterns"] += 1
        item["attempts"] += int(getattr(row, "attempts", 0) or 0)
        item["selected_count"] += int(getattr(row, "selected_count", 0) or 0)
        item["confirmed_count"] += int(getattr(row, "confirmed_count", 0) or 0)
        item["rejected_count"] += int(getattr(row, "rejected_count", 0) or 0)
        item["avg_cost"] += float(getattr(row, "avg_cost", 0.0) or 0.0)

    agents = []
    for item in sorted(grouped.values(), key=lambda x: x["agent_name"]):
        memory_patterns = max(item["memory_patterns"], 1)
        attempts = max(item["attempts"], 1)
        agents.append(
            {
                **item,
                "avg_cost": round(item["avg_cost"] / memory_patterns, 4),
                "confirmation_rate": round(item["confirmed_count"] / attempts, 4),
                "rejection_rate": round(item["rejected_count"] / attempts, 4),
            }
        )

    return {
        "agents_total": len(agents),
        "agents": agents,
    }


def build_logical_agent_learning_summary(memory_rows):
    agent_summary = build_agent_learning_summary(memory_rows)
    if not agent_summary["agents"]:
        return {
            "logical_agents_total": 0,
            "logical_agents": [],
        }

    logical_catalog_map = get_logical_agent_catalog_map()
    grouped = {}
    for row in agent_summary["agents"]:
        logical_agent_name = get_logical_agent_name(row.get("agent_name"))
        item = grouped.setdefault(
            logical_agent_name,
            {
                "logical_agent_name": logical_agent_name,
                "title": logical_catalog_map.get(logical_agent_name, {}).get("title"),
                "memory_patterns": 0,
                "attempts": 0,
                "selected_count": 0,
                "confirmed_count": 0,
                "rejected_count": 0,
                "avg_cost_total": 0.0,
            },
        )
        item["memory_patterns"] += int(row.get("memory_patterns", 0) or 0)
        item["attempts"] += int(row.get("attempts", 0) or 0)
        item["selected_count"] += int(row.get("selected_count", 0) or 0)
        item["confirmed_count"] += int(row.get("confirmed_count", 0) or 0)
        item["rejected_count"] += int(row.get("rejected_count", 0) or 0)
        item["avg_cost_total"] += float(row.get("avg_cost", 0.0) or 0.0)

    logical_agents = []
    for item in sorted(grouped.values(), key=lambda x: x["logical_agent_name"]):
        memory_patterns = max(item["memory_patterns"], 1)
        attempts = max(item["attempts"], 1)
        logical_agents.append(
            {
                "logical_agent_name": item["logical_agent_name"],
                "title": item["title"],
                "implementation_scope": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_scope"),
                "implementation_layers": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_layers", []),
                "memory_patterns": item["memory_patterns"],
                "attempts": item["attempts"],
                "selected_count": item["selected_count"],
                "confirmed_count": item["confirmed_count"],
                "rejected_count": item["rejected_count"],
                "avg_cost": round(item["avg_cost_total"] / memory_patterns, 4),
                "confirmation_rate": round(item["confirmed_count"] / attempts, 4),
                "rejection_rate": round(item["rejected_count"] / attempts, 4),
            }
        )

    return {
        "logical_agents_total": len(logical_agents),
        "logical_agents": logical_agents,
    }


def build_agent_effectiveness_summary(hypotheses, judge_decisions, findings, memory_rows=None):
    hypotheses = hypotheses or []
    judge_decisions = judge_decisions or []
    findings = findings or []
    memory_rows = memory_rows or []

    catalog_map = get_agent_catalog_map()
    memory_by_agent = {
        item["agent_name"]: item
        for item in build_agent_learning_summary(memory_rows)["agents"]
    }
    hypotheses_by_id = {h.id: h for h in hypotheses}

    generated_by_agent = {}
    selected_by_agent = {}
    findings_by_agent = {}
    confirmed_by_agent = {}
    candidate_by_agent = {}
    rejected_by_agent = {}

    for hypothesis in hypotheses:
        agent_name = getattr(hypothesis, "agent_name", "unknown_agent")
        generated_by_agent[agent_name] = generated_by_agent.get(agent_name, 0) + 1

    for decision in judge_decisions:
        hypothesis = hypotheses_by_id.get(getattr(decision, "selected_hypothesis_id", None))
        if not hypothesis:
            continue
        agent_name = getattr(hypothesis, "agent_name", "unknown_agent")
        selected_by_agent[agent_name] = selected_by_agent.get(agent_name, 0) + 1

    for finding in findings:
        hypothesis = hypotheses_by_id.get(getattr(finding, "related_hypothesis_id", None))
        if not hypothesis:
            continue
        agent_name = getattr(hypothesis, "agent_name", "unknown_agent")
        findings_by_agent[agent_name] = findings_by_agent.get(agent_name, 0) + 1
        verification_status = getattr(finding, "verification_status", "candidate")
        if verification_status == "confirmed":
            confirmed_by_agent[agent_name] = confirmed_by_agent.get(agent_name, 0) + 1
        elif verification_status == "rejected":
            rejected_by_agent[agent_name] = rejected_by_agent.get(agent_name, 0) + 1
        else:
            candidate_by_agent[agent_name] = candidate_by_agent.get(agent_name, 0) + 1

    agent_names = sorted(
        set(generated_by_agent.keys())
        | set(selected_by_agent.keys())
        | set(findings_by_agent.keys())
        | set(memory_by_agent.keys())
    )

    agents = []
    for agent_name in agent_names:
        generated = generated_by_agent.get(agent_name, 0)
        selected = selected_by_agent.get(agent_name, 0)
        linked_findings = findings_by_agent.get(agent_name, 0)
        confirmed = confirmed_by_agent.get(agent_name, 0)
        learning = memory_by_agent.get(agent_name, {})
        catalog = catalog_map.get(agent_name, {})

        agents.append(
            {
                "agent_name": agent_name,
                "title": catalog.get("title"),
                "role_class": catalog.get("role_class", "supporting_agent"),
                "generated_hypotheses": generated,
                "selected_hypotheses": selected,
                "linked_findings": linked_findings,
                "confirmed_findings": confirmed,
                "candidate_findings": candidate_by_agent.get(agent_name, 0),
                "rejected_findings": rejected_by_agent.get(agent_name, 0),
                "selection_rate": round(selected / generated, 4) if generated else 0.0,
                "finding_yield": round(linked_findings / selected, 4) if selected else 0.0,
                "confirmation_rate": round(confirmed / linked_findings, 4) if linked_findings else 0.0,
                "learning_attempts": learning.get("attempts", 0),
                "learning_confirmation_rate": learning.get("confirmation_rate", 0.0),
            }
        )

    primary_agents = [item for item in agents if item["role_class"] == "primary_attacker"]
    supporting_agents = [item for item in agents if item["role_class"] != "primary_attacker"]

    return {
        "agents_total": len(agents),
        "primary_attackers_total": len(primary_agents),
        "supporting_agents_total": len(supporting_agents),
        "agents": agents,
        "primary_attackers": primary_agents,
        "supporting_agents": supporting_agents,
    }


def build_logical_agent_judge_feedback_summary(feedback_rows):
    agent_summary = build_agent_judge_feedback_summary(feedback_rows or [])
    if not agent_summary["agents"]:
        return {
            "logical_agents_total": 0,
            "logical_agents": [],
        }

    logical_catalog_map = get_logical_agent_catalog_map()
    grouped = {}
    for row in agent_summary["agents"]:
        logical_agent_name = get_logical_agent_name(row.get("agent_name"))
        item = grouped.setdefault(
            logical_agent_name,
            {
                "logical_agent_name": logical_agent_name,
                "title": logical_catalog_map.get(logical_agent_name, {}).get("title"),
                "proposals_seen_by_judge": 0,
                "selected_by_judge": 0,
                "judge_round_coverage_total": 0.0,
                "items": 0,
            },
        )
        item["proposals_seen_by_judge"] += int(row.get("proposals_seen_by_judge", 0) or 0)
        item["selected_by_judge"] += int(row.get("selected_by_judge", 0) or 0)
        item["judge_round_coverage_total"] += float(row.get("judge_round_coverage", 0.0) or 0.0)
        item["items"] += 1

    logical_agents = []
    for item in sorted(grouped.values(), key=lambda x: x["logical_agent_name"]):
        proposals_seen = max(item["proposals_seen_by_judge"], 1)
        items = max(item["items"], 1)
        logical_agents.append(
            {
                "logical_agent_name": item["logical_agent_name"],
                "title": item["title"],
                "implementation_scope": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_scope"),
                "implementation_layers": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_layers", []),
                "proposals_seen_by_judge": item["proposals_seen_by_judge"],
                "selected_by_judge": item["selected_by_judge"],
                "judge_selection_rate": round(item["selected_by_judge"] / proposals_seen, 4),
                "judge_round_coverage": round(item["judge_round_coverage_total"] / items, 4),
            }
        )

    return {
        "logical_agents_total": len(logical_agents),
        "logical_agents": logical_agents,
    }


def build_logical_agent_effectiveness_summary(hypotheses, judge_decisions, findings, memory_rows=None):
    agent_summary = build_agent_effectiveness_summary(hypotheses, judge_decisions, findings, memory_rows=memory_rows)
    if not agent_summary["agents"]:
        return {
            "logical_agents_total": 0,
            "logical_agents": [],
            "primary_attackers_total": 0,
            "supporting_agents_total": 0,
            "primary_attackers": [],
            "supporting_agents": [],
        }

    logical_catalog_map = get_logical_agent_catalog_map()
    grouped = {}
    for row in agent_summary["agents"]:
        logical_agent_name = get_logical_agent_name(row.get("agent_name"))
        item = grouped.setdefault(
            logical_agent_name,
            {
                "logical_agent_name": logical_agent_name,
                "title": logical_catalog_map.get(logical_agent_name, {}).get("title"),
                "role_class": logical_catalog_map.get(logical_agent_name, {}).get("role_class", "primary_attacker"),
                "generated_hypotheses": 0,
                "selected_hypotheses": 0,
                "linked_findings": 0,
                "confirmed_findings": 0,
                "candidate_findings": 0,
                "rejected_findings": 0,
                "learning_attempts": 0,
                "learning_confirmation_rate_total": 0.0,
                "items": 0,
            },
        )
        for key in [
            "generated_hypotheses",
            "selected_hypotheses",
            "linked_findings",
            "confirmed_findings",
            "candidate_findings",
            "rejected_findings",
            "learning_attempts",
        ]:
            item[key] += int(row.get(key, 0) or 0)
        item["learning_confirmation_rate_total"] += float(row.get("learning_confirmation_rate", 0.0) or 0.0)
        item["items"] += 1

    logical_agents = []
    for item in sorted(grouped.values(), key=lambda x: x["logical_agent_name"]):
        generated = item["generated_hypotheses"]
        selected = item["selected_hypotheses"]
        linked_findings = item["linked_findings"]
        logical_agents.append(
            {
                "logical_agent_name": item["logical_agent_name"],
                "title": item["title"],
                "role_class": item["role_class"],
                "implementation_scope": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_scope"),
                "implementation_layers": logical_catalog_map.get(item["logical_agent_name"], {}).get("implementation_layers", []),
                "generated_hypotheses": generated,
                "selected_hypotheses": selected,
                "linked_findings": linked_findings,
                "confirmed_findings": item["confirmed_findings"],
                "candidate_findings": item["candidate_findings"],
                "rejected_findings": item["rejected_findings"],
                "selection_rate": round(selected / generated, 4) if generated else 0.0,
                "finding_yield": round(linked_findings / selected, 4) if selected else 0.0,
                "confirmation_rate": round(item["confirmed_findings"] / linked_findings, 4) if linked_findings else 0.0,
                "learning_attempts": item["learning_attempts"],
                "learning_confirmation_rate": round(
                    item["learning_confirmation_rate_total"] / max(item["items"], 1),
                    4,
                ),
            }
        )

    primary_agents = [item for item in logical_agents if item["role_class"] == "primary_attacker"]
    supporting_agents = [item for item in logical_agents if item["role_class"] != "primary_attacker"]
    return {
        "logical_agents_total": len(logical_agents),
        "primary_attackers_total": len(primary_agents),
        "supporting_agents_total": len(supporting_agents),
        "logical_agents": logical_agents,
        "primary_attackers": primary_agents,
        "supporting_agents": supporting_agents,
    }


def build_session_report(
    session_obj,
    roles,
    findings,
    judge_decisions,
    observations,
    hypotheses=None,
    agent_memory_rows=None,
    agent_judge_feedback_rows=None,
):
    high_findings = [f for f in findings if (f.severity or "").lower() == "high"]
    medium_findings = [f for f in findings if (f.severity or "").lower() == "medium"]
    low_findings = [f for f in findings if (f.severity or "").lower() == "low"]

    authenticated_roles = [r for r in roles if r.access_token]
    recent_observations = observations[-10:] if len(observations) > 10 else observations
    recent_decisions = judge_decisions[-10:] if len(judge_decisions) > 10 else judge_decisions
    dify_issue_summary = _build_dify_issue_summary(judge_decisions)
    hypotheses_by_id = {h.id: h for h in (hypotheses or [])}
    strategy_state = _safe_load_json(getattr(session_obj, "last_strategy_json", None)) or {}

    report = {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
            "status": session_obj.status,
            "created_at": str(session_obj.created_at),
        },
        "summary": {
            "roles_total": len(roles),
            "authenticated_roles": len(authenticated_roles),
            "observations_total": len(observations),
            "judge_decisions_total": len(judge_decisions),
            "findings_total": len(findings),
            "high_findings_total": len(high_findings),
            "medium_findings_total": len(medium_findings),
            "low_findings_total": len(low_findings),
            "rounds_completed": getattr(session_obj, "rounds_completed", 0),
            "max_rounds": getattr(session_obj, "max_rounds", None),
            "budget_requests_used": getattr(session_obj, "budget_requests_used", 0),
            "budget_requests_total": getattr(session_obj, "budget_requests_total", None),
            "stop_reason": getattr(session_obj, "stop_reason", None),
        },
        "key_conclusion": _build_key_conclusion(findings),
        "judge_trace_summary": dify_issue_summary,
        "agent_orchestration": {
            "enabled_agents": strategy_state.get("enabled_agents", []),
            "enabled_logical_agents": sorted(
                {
                    get_logical_agent_name(item)
                    for item in strategy_state.get("enabled_agents", [])
                }
            ),
            "agents_invoked": strategy_state.get("agents_invoked", []),
            "logical_agents_invoked": sorted(
                {
                    get_logical_agent_name(item)
                    for item in strategy_state.get("agents_invoked", [])
                }
            ),
            "active_agents": strategy_state.get("active_agents", []),
            "active_logical_agents": sorted(
                {
                    get_logical_agent_name(item)
                    for item in strategy_state.get("active_agents", [])
                }
            ),
            "selected_agent": strategy_state.get("selected_agent"),
            "selected_logical_agent": get_logical_agent_name(strategy_state.get("selected_agent")),
        },
        "agent_learning_summary": build_agent_learning_summary(agent_memory_rows or []),
        "logical_agent_learning_summary": build_logical_agent_learning_summary(agent_memory_rows or []),
        "agent_judge_feedback_summary": build_agent_judge_feedback_summary(agent_judge_feedback_rows or []),
        "logical_agent_judge_feedback_summary": build_logical_agent_judge_feedback_summary(
            agent_judge_feedback_rows or []
        ),
        "agent_effectiveness_summary": build_agent_effectiveness_summary(
            hypotheses or [],
            judge_decisions,
            findings,
            memory_rows=agent_memory_rows or [],
        ),
        "logical_agent_effectiveness_summary": build_logical_agent_effectiveness_summary(
            hypotheses or [],
            judge_decisions,
            findings,
            memory_rows=agent_memory_rows or [],
        ),
        "logical_agent_activity_summary": build_logical_agent_activity_summary(
            hypotheses or [],
            judge_decisions,
        ),
        "roles": [
            {
                "role_name": r.role_name,
                "email": r.email,
                "status": r.status,
                "last_auth_status": r.last_auth_status,
                "has_access_token": bool(r.access_token),
            }
            for r in roles
        ],
        "findings": [
            {
                "id": f.id,
                "finding_type": f.finding_type,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "endpoint": f.endpoint,
                "verification_status": f.verification_status,
                "related_hypothesis_id": f.related_hypothesis_id,
                "related_observation_ids": _safe_load_json(f.related_observation_ids),
                "evidence": _safe_load_json(f.evidence_json),
                "created_at": str(f.created_at),
            }
            for f in findings
        ],
        "recent_judge_decisions": [
            {
                "id": d.id,
                "round_no": d.round_no,
                "decision_type": d.decision_type,
                "selected_hypothesis_id": d.selected_hypothesis_id,
                "selected_agent_name": getattr(
                    hypotheses_by_id.get(getattr(d, "selected_hypothesis_id", None)),
                    "agent_name",
                    None,
                ),
                "selected_logical_agent_name": get_logical_agent_name(
                    getattr(
                        hypotheses_by_id.get(getattr(d, "selected_hypothesis_id", None)),
                        "agent_name",
                        None,
                    )
                ),
                "priority_score": d.priority_score,
                "resolution_mode": getattr(d, "resolution_mode", None),
                "raw_selected_key": getattr(d, "raw_selected_key", None),
                "raw_score": getattr(d, "raw_score", None),
                "raw_reason": getattr(d, "raw_reason", None),
                "dify_issue_type": classify_dify_issue(
                    getattr(d, "resolution_mode", None),
                    getattr(d, "raw_reason", None),
                    getattr(d, "reasoning_summary", None),
                ),
                "reasoning_summary": d.reasoning_summary,
                "required_evidence": _safe_load_json(d.required_evidence_json),
                "stop_condition": _safe_load_json(d.stop_condition_json),
                "created_at": str(d.created_at),
            }
            for d in recent_decisions
        ],
        "recent_observations": [
            {
                "id": o.id,
                "endpoint": o.endpoint,
                "method": o.method,
                "role_name": o.role_name,
                "status_code": o.status_code,
                "body_preview": o.body_preview[:500] if o.body_preview else None,
                "created_at": str(o.created_at),
            }
            for o in recent_observations
        ],
    }

    return report


def _build_dify_issue_summary(judge_decisions):
    summary = {
        "direct_matches": 0,
        "recoveries": 0,
        "fallbacks": 0,
        "rule_based_overrides": 0,
        "issue_breakdown": {
            "provider_credit_limit": 0,
            "empty_outputs": 0,
            "invalid_candidate_key": 0,
            "provider_timeout": 0,
            "provider_error": 0,
            "exception_fallback_other": 0,
        },
    }

    for decision in judge_decisions:
        issue_type = classify_dify_issue(
            getattr(decision, "resolution_mode", None),
            getattr(decision, "raw_reason", None),
            getattr(decision, "reasoning_summary", None),
        )
        if issue_type == "direct_match":
            summary["direct_matches"] += 1
        elif issue_type == "semantic_recovery":
            summary["recoveries"] += 1
        elif issue_type == "rule_based_override":
            summary["rule_based_overrides"] += 1
        elif issue_type in summary["issue_breakdown"]:
            summary["fallbacks"] += 1
            summary["issue_breakdown"][issue_type] += 1

    return summary


def _build_key_conclusion(findings):
    if not findings:
        return {
            "status": "no_findings",
            "message": "No findings were recorded for the session."
        }

    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]
    bopla_findings = [f for f in findings if f.finding_type == "possible_bopla"]
    auth_findings = [f for f in findings if f.finding_type == "possible_authentication_bypass"]
    auth_signals = [f for f in findings if f.finding_type == "auth_boundary_signal"]
    if bola_findings:
        return {
            "status": "security_issue_candidates_found",
            "message": (
                f"Session contains {len(bola_findings)} possible BOLA candidate(s). "
                f"Manual verification is recommended for object ownership and business context."
            )
        }
    if bopla_findings:
        return {
            "status": "security_issue_candidates_found",
            "message": (
                f"Session contains {len(bopla_findings)} possible BOPLA candidate(s). "
                f"Manual verification is recommended for exposed attributes and business need."
            )
        }
    if auth_findings:
        return {
            "status": "security_issue_candidates_found",
            "message": (
                f"Session contains {len(auth_findings)} possible authentication bypass candidate(s). "
                f"Manual verification is recommended for authentication boundary handling."
            )
        }
    if auth_signals:
        return {
            "status": "auth_boundary_signals_found",
            "message": (
                f"Session contains {len(auth_signals)} authentication-boundary signal(s). "
                "They do not prove a bypass, but they are useful for manual auth-surface review."
            )
        }

    return {
        "status": "findings_present",
        "message": f"Session contains {len(findings)} finding(s), but no BOLA candidate was recorded."
    }


def build_session_summary_text(session_obj, roles, findings, judge_decisions, observations):
    roles_total = len(roles)
    authenticated_roles = len([r for r in roles if r.access_token])
    findings_total = len(findings)
    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]
    bopla_findings = [f for f in findings if f.finding_type == "possible_bopla"]
    auth_findings = [f for f in findings if f.finding_type == "possible_authentication_bypass"]
    auth_signals = [f for f in findings if f.finding_type == "auth_boundary_signal"]

    base = (
        f"В рамках сессии тестирования #{session_obj.id} для цели '{session_obj.target_name}' "
        f"({session_obj.target_url}) система выполнила автоматизированную кампанию анализа API. "
        f"В ходе кампании было подготовлено {roles_total} ролей, из которых успешно аутентифицированы "
        f"{authenticated_roles}. Всего накоплено {len(observations)} наблюдений, принято "
        f"{len(judge_decisions)} решений арбитража и зафиксировано {findings_total} результатов анализа."
    )

    if bola_findings:
        finding = bola_findings[0]
        evidence = _safe_load_json(finding.evidence_json) or {}
        endpoint = finding.endpoint or "N/A"
        owner_role = evidence.get("owner_role", "unknown")
        other_role = evidence.get("other_role", "unknown")
        status_owner = evidence.get("status_owner", "unknown")
        status_other = evidence.get("status_other", "unknown")

        bola_text = (
            f" Наиболее значимым результатом стал кандидат на Broken Object Level Authorization. "
            f"Система автоматически выбрала гипотезу проверки объектного доступа и выполнила запрос "
            f"к endpoint '{endpoint}' от имени ролей {owner_role} и {other_role}. "
            f"Обе роли получили успешные ответы ({status_owner} и {status_other}), "
            f"а содержимое ответов было интерпретировано как эквивалентное, что дало основание "
            f"классифицировать результат как 'possible_bola'. "
            f"Найденный результат сохранён в виде finding с уровнем критичности '{finding.severity}' "
            f"и статусом верификации '{finding.verification_status}'."
        )
        return base + bola_text

    if bopla_findings:
        finding = bopla_findings[0]
        evidence = _safe_load_json(finding.evidence_json) or {}
        endpoint = finding.endpoint or "N/A"
        exposed_fields = evidence.get("exposed_fields", [])

        bopla_text = (
            f" Наиболее значимым результатом стал кандидат на Broken Object Property Level Authorization "
            f"или excessive data exposure. На endpoint '{endpoint}' были выявлены потенциально "
            f"чувствительные поля: {', '.join(exposed_fields[:5]) or 'N/A'}. "
            f"Результат сохранён как finding со статусом '{finding.verification_status}' "
            f"и уровнем критичности '{finding.severity}'."
        )
        return base + bopla_text

    if auth_findings:
        finding = auth_findings[0]
        evidence = _safe_load_json(finding.evidence_json) or {}
        endpoint = finding.endpoint or "N/A"
        action_executed = evidence.get("action_executed", "auth probe")
        status_code = evidence.get("status_code", "unknown")

        auth_text = (
            f" Наиболее значимым результатом стал кандидат на нарушение границы аутентификации. "
            f"Для endpoint '{endpoint}' шаг '{action_executed}' получил успешный ответ ({status_code}), "
            f"что может указывать на некорректное применение требований аутентификации. "
            f"Результат сохранён как finding со статусом '{finding.verification_status}' "
            f"и уровнем критичности '{finding.severity}'."
        )
        return base + auth_text

    if auth_signals:
        finding = auth_signals[0]
        evidence = _safe_load_json(finding.evidence_json) or {}
        endpoint = finding.endpoint or "N/A"
        status_code = evidence.get("status_code", "unknown")

        signal_text = (
            f" Существенных кандидатов на обход аутентификации не выявлено, однако зафиксирован "
            f"диагностический auth-signal для endpoint '{endpoint}' со статусом ответа {status_code}. "
            f"Такой результат не является подтверждением уязвимости, но полезен для последующей "
            f"ручной проверки поведения маршрута и границы аутентификации."
        )
        return base + signal_text

    no_bola_text = (
        " По итогам кампании кандидаты на BOLA/BOPLA не были зафиксированы, однако собранные observations "
        "и judge trace могут быть использованы для последующего ручного анализа и расширения набора проверок."
    )
    return base + no_bola_text


def build_session_executive_summary(session_obj, findings):
    bola_findings = [f for f in findings if f.finding_type == "possible_bola"]
    bopla_findings = [f for f in findings if f.finding_type == "possible_bopla"]
    auth_findings = [f for f in findings if f.finding_type == "possible_authentication_bypass"]
    auth_signals = [f for f in findings if f.finding_type == "auth_boundary_signal"]

    if bola_findings:
        return {
            "risk_level": "high",
            "headline": "Обнаружен кандидат на нарушение объектного разграничения доступа",
            "message": (
                f"Для цели '{session_obj.target_name}' автоматизированная кампания выявила "
                f"{len(bola_findings)} кандидат(а/ов) на Broken Object Level Authorization."
            )
        }

    if bopla_findings:
        return {
            "risk_level": "medium",
            "headline": "Обнаружен кандидат на избыточную выдачу свойств объекта",
            "message": (
                f"Для цели '{session_obj.target_name}' автоматизированная кампания выявила "
                f"{len(bopla_findings)} кандидат(а/ов) на Broken Object Property Level Authorization."
            )
        }

    if auth_findings:
        return {
            "risk_level": "medium",
            "headline": "Обнаружен кандидат на обход границы аутентификации",
            "message": (
                f"Для цели '{session_obj.target_name}' автоматизированная кампания выявила "
                f"{len(auth_findings)} кандидат(а/ов) на possible authentication bypass."
            )
        }

    if auth_signals:
        return {
            "risk_level": "low",
            "headline": "Зафиксированы сигналы поведения границы аутентификации",
            "message": (
                f"Для цели '{session_obj.target_name}' автоматизированная кампания выявила "
                f"{len(auth_signals)} auth boundary signal(s), требующих ручного анализа."
            )
        }

    return {
        "risk_level": "low",
        "headline": "Критические кандидаты не обнаружены",
        "message": (
            f"Для цели '{session_obj.target_name}' автоматизированная кампания не выявила "
            "критических кандидатов на BOLA и BOPLA."
        )
    }


def build_final_session_report(
    session_obj,
    roles,
    findings,
    judge_decisions,
    observations,
    hypotheses=None,
    agent_memory_rows=None,
    agent_judge_feedback_rows=None,
):
    report = build_session_report(
        session_obj=session_obj,
        roles=roles,
        findings=findings,
        judge_decisions=judge_decisions,
        observations=observations,
        hypotheses=hypotheses,
        agent_memory_rows=agent_memory_rows,
        agent_judge_feedback_rows=agent_judge_feedback_rows,
    )

    severity_breakdown = {
        "high": len([f for f in findings if (f.severity or "").lower() == "high"]),
        "medium": len([f for f in findings if (f.severity or "").lower() == "medium"]),
        "low": len([f for f in findings if (f.severity or "").lower() == "low"]),
    }

    confirmed_findings = [f for f in findings if getattr(f, "verification_status", "candidate") == "confirmed"]
    candidate_findings = [f for f in findings if getattr(f, "verification_status", "candidate") == "candidate"]
    prioritized_main_findings = confirmed_findings[:5]
    diagnostic_candidate_findings = candidate_findings[:5]

    top_findings = []
    for finding in prioritized_main_findings:
        evidence = _safe_load_json(finding.evidence_json) or {}
        evidence_bundle = _build_evidence_bundle(finding, observations)
        top_findings.append({
            "id": finding.id,
            "type": finding.finding_type,
            "severity": finding.severity,
            "endpoint": finding.endpoint,
            "verification_status": finding.verification_status,
            "title": finding.title,
            "description": finding.description,
            "evidence_preview": {
                "signals": evidence.get("signals", [])[:5],
                "exposed_fields": evidence.get("exposed_fields", [])[:5],
                "owner_role": evidence.get("owner_role"),
                "other_role": evidence.get("other_role"),
                "status_owner": evidence.get("status_owner"),
                "status_other": evidence.get("status_other"),
            },
            "evidence_bundle": evidence_bundle,
        })

    candidate_finding_details = []
    for finding in diagnostic_candidate_findings:
        evidence = _safe_load_json(finding.evidence_json) or {}
        evidence_bundle = _build_evidence_bundle(finding, observations)
        candidate_finding_details.append({
            "id": finding.id,
            "type": finding.finding_type,
            "severity": finding.severity,
            "endpoint": finding.endpoint,
            "verification_status": finding.verification_status,
            "title": finding.title,
            "description": finding.description,
            "evidence_preview": {
                "signals": evidence.get("signals", [])[:5],
                "exposed_fields": evidence.get("exposed_fields", [])[:5],
                "owner_role": evidence.get("owner_role"),
                "other_role": evidence.get("other_role"),
                "status_owner": evidence.get("status_owner"),
                "status_other": evidence.get("status_other"),
            },
            "evidence_bundle": evidence_bundle,
        })

    return {
        "session": report["session"],
        "executive_summary": build_session_executive_summary(session_obj, findings),
        "summary_text": build_session_summary_text(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
        ),
        "risk_summary": {
            "total_findings": len(findings),
            "severity_breakdown": severity_breakdown,
            "confirmed_findings": len([f for f in findings if f.verification_status == "confirmed"]),
            "candidate_findings": len([f for f in findings if f.verification_status == "candidate"]),
            "bola_findings": len([f for f in findings if f.finding_type == "possible_bola"]),
            "bopla_findings": len([f for f in findings if f.finding_type == "possible_bopla"]),
        },
        "campaign_summary": report["summary"],
        "judge_trace_summary": report["judge_trace_summary"],
        "agent_orchestration": report["agent_orchestration"],
        "logical_agent_activity_summary": report["logical_agent_activity_summary"],
        "logical_agent_learning_summary": report["logical_agent_learning_summary"],
        "logical_agent_judge_feedback_summary": report["logical_agent_judge_feedback_summary"],
        "logical_agent_effectiveness_summary": report["logical_agent_effectiveness_summary"],
        "internal_agent_activity_summary": build_agent_activity_summary(hypotheses or [], judge_decisions),
        "internal_agent_learning_summary": report["agent_learning_summary"],
        "internal_agent_judge_feedback_summary": report["agent_judge_feedback_summary"],
        "internal_agent_effectiveness_summary": report["agent_effectiveness_summary"],
        "key_conclusion": report["key_conclusion"],
        "top_findings": top_findings,
        "candidate_findings_for_review": candidate_finding_details,
    }


def build_session_markdown_report(
    session_obj,
    roles,
    findings,
    judge_decisions,
    observations,
    hypotheses=None,
    agent_memory_rows=None,
    agent_judge_feedback_rows=None,
):
    final_report = build_final_session_report(
        session_obj=session_obj,
        roles=roles,
        findings=findings,
        judge_decisions=judge_decisions,
        observations=observations,
        hypotheses=hypotheses,
        agent_memory_rows=agent_memory_rows,
        agent_judge_feedback_rows=agent_judge_feedback_rows,
    )

    lines = [
        f"# Pentest Report: Session {final_report['session']['id']}",
        "",
        f"- Target: `{final_report['session']['target_name']}`",
        f"- Base URL: `{final_report['session']['target_url']}`",
        f"- Status: `{final_report['session']['status']}`",
        "",
        "## Executive Summary",
        "",
        f"**{final_report['executive_summary']['headline']}**",
        "",
        final_report["executive_summary"]["message"],
        "",
        "## Risk Summary",
        "",
        f"- Total findings: {final_report['risk_summary']['total_findings']}",
        f"- Confirmed findings: {final_report['risk_summary']['confirmed_findings']}",
        f"- Candidate findings: {final_report['risk_summary']['candidate_findings']}",
        f"- BOLA findings: {final_report['risk_summary']['bola_findings']}",
        f"- BOPLA findings: {final_report['risk_summary']['bopla_findings']}",
        f"- High severity: {final_report['risk_summary']['severity_breakdown']['high']}",
        f"- Medium severity: {final_report['risk_summary']['severity_breakdown']['medium']}",
        f"- Low severity: {final_report['risk_summary']['severity_breakdown']['low']}",
        "",
        "## Narrative Summary",
        "",
        final_report["summary_text"],
        "",
        "## Top Findings",
        "",
    ]

    if not final_report["top_findings"]:
        lines.extend([
            "No confirmed findings were recorded.",
            "",
        ])
    else:
        for finding in final_report["top_findings"]:
            lines.extend([
                f"### {finding['title']}",
                "",
                f"- Type: `{finding['type']}`",
                f"- Severity: `{finding['severity']}`",
                f"- Endpoint: `{finding['endpoint']}`",
                f"- Verification: `{finding['verification_status']}`",
                f"- Description: {finding['description']}",
                "",
            ])

            signals = finding["evidence_preview"].get("signals") or []
            exposed_fields = finding["evidence_preview"].get("exposed_fields") or []
            if signals:
                lines.append(f"- Evidence signals: {', '.join(signals)}")
            if exposed_fields:
                lines.append(f"- Exposed fields: {', '.join(exposed_fields)}")

            if finding["evidence_preview"].get("owner_role") or finding["evidence_preview"].get("other_role"):
                lines.append(
                    f"- Roles compared: {finding['evidence_preview'].get('owner_role')} vs "
                    f"{finding['evidence_preview'].get('other_role')}"
                )
            if finding["evidence_preview"].get("status_owner") or finding["evidence_preview"].get("status_other"):
                lines.append(
                    f"- Response status pair: {finding['evidence_preview'].get('status_owner')} / "
                    f"{finding['evidence_preview'].get('status_other')}"
                )
            evidence_bundle = finding.get("evidence_bundle") or {}
            reproducibility = evidence_bundle.get("reproducibility") or {}
            replay_requests = evidence_bundle.get("replay_requests") or []
            if reproducibility.get("has_replay_requests"):
                lines.append(
                    f"- Evidence bundle: {reproducibility.get('replay_request_count', 0)} replay request(s) captured"
                )
                for replay in replay_requests[:2]:
                    lines.append(
                        f"  - Replay: `{replay.get('method')}` `{replay.get('endpoint')}` as "
                        f"`{replay.get('role_name') or 'anonymous'}` -> HTTP `{replay.get('status_code')}`"
                    )
            lines.append("")

    lines.extend([
        "## Candidate Findings Requiring Manual Review",
        "",
    ])

    if not final_report["candidate_findings_for_review"]:
        lines.extend([
            "No candidate findings require additional manual review.",
            "",
        ])
    else:
        for finding in final_report["candidate_findings_for_review"]:
            lines.extend([
                f"### {finding['title']}",
                "",
                f"- Type: `{finding['type']}`",
                f"- Severity: `{finding['severity']}`",
                f"- Endpoint: `{finding['endpoint']}`",
                f"- Verification: `{finding['verification_status']}`",
                f"- Description: {finding['description']}",
                "",
            ])

            signals = finding["evidence_preview"].get("signals") or []
            exposed_fields = finding["evidence_preview"].get("exposed_fields") or []
            if signals:
                lines.append(f"- Evidence signals: {', '.join(signals)}")
            if exposed_fields:
                lines.append(f"- Exposed fields: {', '.join(exposed_fields)}")

            if finding["evidence_preview"].get("owner_role") or finding["evidence_preview"].get("other_role"):
                lines.append(
                    f"- Roles compared: {finding['evidence_preview'].get('owner_role')} vs "
                    f"{finding['evidence_preview'].get('other_role')}"
                )
            if finding["evidence_preview"].get("status_owner") or finding["evidence_preview"].get("status_other"):
                lines.append(
                    f"- Response status pair: {finding['evidence_preview'].get('status_owner')} / "
                    f"{finding['evidence_preview'].get('status_other')}"
                )
            evidence_bundle = finding.get("evidence_bundle") or {}
            reproducibility = evidence_bundle.get("reproducibility") or {}
            replay_requests = evidence_bundle.get("replay_requests") or []
            if reproducibility.get("has_replay_requests"):
                lines.append(
                    f"- Evidence bundle: {reproducibility.get('replay_request_count', 0)} replay request(s) captured"
                )
                for replay in replay_requests[:2]:
                    lines.append(
                        f"  - Replay: `{replay.get('method')}` `{replay.get('endpoint')}` as "
                        f"`{replay.get('role_name') or 'anonymous'}` -> HTTP `{replay.get('status_code')}`"
                    )
            lines.append("")

    lines.extend([
        "## Judge Trace",
        "",
        f"- Direct matches: {final_report['judge_trace_summary']['direct_matches']}",
        f"- Recoveries: {final_report['judge_trace_summary']['recoveries']}",
        f"- Fallbacks: {final_report['judge_trace_summary']['fallbacks']}",
        "",
        "## Logical Agent Activity",
        "",
    ])

    if not final_report["logical_agent_activity_summary"]["logical_agents"]:
        lines.extend([
            "No logical agent activity recorded.",
            "",
        ])
    else:
        for agent in final_report["logical_agent_activity_summary"]["logical_agents"]:
            lines.append(
                f"- `{agent['logical_agent_name']}`: generated {agent['generated_hypotheses']}, "
                f"selected {agent['selected_hypotheses']}"
            )
        lines.append("")

    lines.extend([
        "## Logical Agent Learning",
        "",
    ])

    if not final_report["logical_agent_learning_summary"]["logical_agents"]:
        lines.extend([
            "No logical agent learning records recorded.",
            "",
        ])
    else:
        for agent in final_report["logical_agent_learning_summary"]["logical_agents"]:
            lines.append(
                f"- `{agent['logical_agent_name']}`: attempts {agent['attempts']}, "
                f"confirmed {agent['confirmed_count']}, rejected {agent['rejected_count']}, "
                f"confirmation_rate {agent['confirmation_rate']:.2f}"
            )
        lines.append("")

    lines.extend([
        "## Logical Judge Feedback",
        "",
    ])

    if not final_report["logical_agent_judge_feedback_summary"]["logical_agents"]:
        lines.extend([
            "No logical judge feedback records recorded.",
            "",
        ])
    else:
        for agent in final_report["logical_agent_judge_feedback_summary"]["logical_agents"]:
            lines.append(
                f"- `{agent['logical_agent_name']}`: proposals_seen {agent['proposals_seen_by_judge']}, "
                f"selected_by_judge {agent['selected_by_judge']}, "
                f"judge_selection_rate {agent['judge_selection_rate']:.2f}"
            )
        lines.append("")

    lines.extend([
        "## Logical Agent Effectiveness",
        "",
    ])

    if not final_report["logical_agent_effectiveness_summary"]["logical_agents"]:
        lines.extend([
            "No logical agent effectiveness records recorded.",
            "",
        ])
    else:
        for agent in final_report["logical_agent_effectiveness_summary"]["logical_agents"]:
            lines.append(
                f"- `{agent['logical_agent_name']}` ({agent['role_class']}): selected {agent['selected_hypotheses']}, "
                f"linked_findings {agent['linked_findings']}, confirmed {agent['confirmed_findings']}, "
                f"selection_rate {agent['selection_rate']:.2f}, confirmation_rate {agent['confirmation_rate']:.2f}"
            )
        lines.append("")

    return "\n".join(lines)
