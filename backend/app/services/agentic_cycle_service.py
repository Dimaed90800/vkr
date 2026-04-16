from __future__ import annotations

import json
from typing import Any

from ..models import Finding
from .agent_registry_service import get_logical_agent_name


_PROMPT_CLASS_HINTS = {
    "bola": ["bola", "idor", "object", "authorization", "owner"],
    "bopla": ["bopla", "property", "field", "exposure", "data exposure", "sensitive"],
    "auth": ["auth", "authentication", "token", "anonymous", "invalid token", "login"],
    "discovery": ["discover", "discovery", "swagger", "openapi", "surface", "inventory"],
}

_CLASS_TO_LOGICAL_AGENT = {
    "bola": "authorization_agent",
    "bopla": "exposure_agent",
    "auth": "authentication_agent",
    "discovery": "authentication_agent",
}

_VERIFY_TYPES = {"verify_bola", "verify_bopla", "verify_auth_boundary"}
_EVIDENCE_PRODUCING_TYPES = {
    "bola_probe",
    "bopla_probe",
    "compare_roles",
    "anonymous_probe",
    "tokenless_replay_probe",
    "auth_boundary_probe",
}


def get_agentic_strategy_limits(strategy_state: dict[str, Any] | None) -> dict[str, int]:
    strategy_config = (strategy_state or {}).get("strategy_config", {})
    strategy_config = strategy_config if isinstance(strategy_config, dict) else {}
    return {
        "max_retries_per_candidate": int(
            strategy_config.get("agentic_max_retries_per_candidate", 2) or 2
        ),
        "max_tasks_per_logical_agent": int(
            strategy_config.get("agentic_max_tasks_per_logical_agent", 4) or 4
        ),
        "max_judge_history_items": int(
            strategy_config.get("agentic_max_judge_history_items", 20) or 20
        ),
    }


def get_user_prompt_from_strategy(strategy_state: dict[str, Any] | None) -> str:
    return str((strategy_state or {}).get("user_prompt") or "").strip()


def ensure_agentic_state(strategy_state: dict[str, Any] | None) -> dict[str, Any]:
    state = dict(strategy_state or {})
    agentic_state = state.get("agentic_state", {})
    agentic_state = dict(agentic_state) if isinstance(agentic_state, dict) else {}
    agentic_state.setdefault("candidate_retry_counts", {})
    agentic_state.setdefault("logical_agent_attempt_counts", {})
    agentic_state.setdefault("logical_agent_success_counts", {})
    agentic_state.setdefault("judge_history", [])
    agentic_state.setdefault("confirmed_finding_ids", [])
    state["agentic_state"] = agentic_state
    return state


def get_candidate_key(hypothesis) -> str:
    payload = {}
    try:
        payload = json.loads(getattr(hypothesis, "payload_json", "") or "{}")
    except Exception:
        payload = {}
    candidate_key = str(payload.get("candidate_key") or "").strip()
    if candidate_key:
        return candidate_key
    return f"{getattr(hypothesis, 'hypothesis_type', 'candidate')}::{getattr(hypothesis, 'id', 'unknown')}"


def extract_prompt_focus(user_prompt: str, allowed_test_classes: list[str] | None = None) -> dict[str, Any]:
    prompt = str(user_prompt or "").lower()
    detected_classes = []
    for test_class, keywords in _PROMPT_CLASS_HINTS.items():
        if any(keyword in prompt for keyword in keywords):
            detected_classes.append(test_class)

    allowed = [str(item or "").strip() for item in (allowed_test_classes or []) if str(item or "").strip()]
    if allowed:
        detected_classes = [item for item in detected_classes if item in allowed]

    if not detected_classes:
        detected_classes = allowed or ["bola", "bopla", "auth", "discovery"]

    preferred_logical_agents = []
    for test_class in detected_classes:
        logical_agent = _CLASS_TO_LOGICAL_AGENT.get(test_class)
        if logical_agent and logical_agent not in preferred_logical_agents:
            preferred_logical_agents.append(logical_agent)

    return {
        "requested_test_classes": detected_classes,
        "preferred_logical_agents": preferred_logical_agents,
    }


def choose_agentic_candidate(
    saved_candidates,
    *,
    user_prompt: str,
    allowed_test_classes: list[str] | None,
    strategy_state: dict[str, Any] | None,
):
    state = ensure_agentic_state(strategy_state)
    agentic_state = state["agentic_state"]
    limits = get_agentic_strategy_limits(state)
    focus = extract_prompt_focus(user_prompt, allowed_test_classes)

    ranked = []
    for candidate in saved_candidates or []:
        candidate_key = get_candidate_key(candidate)
        logical_agent_name = get_logical_agent_name(getattr(candidate, "agent_name", None))
        retry_count = int(agentic_state["candidate_retry_counts"].get(candidate_key, 0) or 0)
        logical_attempts = int(
            agentic_state["logical_agent_attempt_counts"].get(logical_agent_name, 0) or 0
        )
        if retry_count >= limits["max_retries_per_candidate"]:
            continue
        if logical_attempts >= limits["max_tasks_per_logical_agent"]:
            continue

        base_score = (
            float(getattr(candidate, "confidence", 0.0) or 0.0) * 0.30
            + float(getattr(candidate, "coverage_gain", 0.0) or 0.0) * 0.20
            + float(getattr(candidate, "evidence_readiness", 0.0) or 0.0) * 0.25
            + (1.0 - float(getattr(candidate, "false_positive_risk", 0.5) or 0.5)) * 0.15
            + (1.0 / (1.0 + float(getattr(candidate, "estimated_cost", 1.0) or 1.0))) * 0.10
        )
        if getattr(candidate, "hypothesis_type", None) in _VERIFY_TYPES:
            base_score += 0.40
        if logical_agent_name in focus["preferred_logical_agents"]:
            base_score += 0.25
        if getattr(candidate, "hypothesis_type", None) == "discovery" and "discovery" in focus["requested_test_classes"]:
            base_score += 0.10

        base_score -= retry_count * 0.20
        base_score -= logical_attempts * 0.05
        ranked.append((candidate, base_score, candidate_key, logical_agent_name))

    ranked.sort(key=lambda item: item[1], reverse=True)
    if not ranked:
        return None, {
            "preferred_logical_agents": focus["preferred_logical_agents"],
            "requested_test_classes": focus["requested_test_classes"],
            "selection_reason": "No candidate remained within router retry/task limits.",
            "resolution_mode": "agentic_task_space_exhausted",
        }

    selected, score, candidate_key, logical_agent_name = ranked[0]
    return selected, {
        "candidate_key": candidate_key,
        "logical_agent_name": logical_agent_name,
        "priority_score": round(score, 4),
        "preferred_logical_agents": focus["preferred_logical_agents"],
        "requested_test_classes": focus["requested_test_classes"],
        "selection_reason": (
            f"Router prioritized logical agent '{logical_agent_name}' for prompt-driven scope "
            f"and selected '{getattr(selected, 'hypothesis_type', 'unknown')}'."
        ),
        "resolution_mode": "agentic_router_select",
    }


def judge_agentic_execution(db, session_id: int, selected, execution_result: dict[str, Any] | None) -> dict[str, Any]:
    execution_result = execution_result or {}
    candidate_key = get_candidate_key(selected)
    linked_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.related_hypothesis_id == getattr(selected, "id", None),
    ).all()

    confirmed = [item for item in linked_findings if getattr(item, "verification_status", None) == "confirmed"]
    candidate = [item for item in linked_findings if getattr(item, "verification_status", None) == "candidate"]
    explicit_verification_status = str(execution_result.get("verification_status") or "").strip().lower()

    if explicit_verification_status == "confirmed" or confirmed:
        return {
            "status": "confirmed",
            "resolution_mode": "agentic_judge_confirmed",
            "reasoning_summary": "Judge accepted the result because the execution produced confirmed exploit evidence.",
            "retry_same_candidate": False,
            "candidate_key": candidate_key,
            "confirmed_finding_ids": [int(item.id) for item in confirmed],
            "candidate_finding_ids": [int(item.id) for item in candidate],
        }

    follow_up = None
    hypothesis_type = str(getattr(selected, "hypothesis_type", "") or "")
    if hypothesis_type == "bola_probe":
        follow_up = "verify_bola"
    elif hypothesis_type == "bopla_probe":
        follow_up = "verify_bopla"
    elif hypothesis_type in {"anonymous_probe", "tokenless_replay_probe", "auth_boundary_probe"}:
        follow_up = "verify_auth_boundary"

    if explicit_verification_status == "rejected":
        return {
            "status": "rejected",
            "resolution_mode": "agentic_judge_rejected",
            "reasoning_summary": "Judge rejected the result because verification explicitly failed.",
            "retry_same_candidate": False,
            "candidate_key": candidate_key,
            "confirmed_finding_ids": [],
            "candidate_finding_ids": [int(item.id) for item in candidate],
            "follow_up_hypothesis_type": follow_up,
        }

    if candidate or hypothesis_type in _EVIDENCE_PRODUCING_TYPES:
        return {
            "status": "needs_retry",
            "resolution_mode": "agentic_judge_needs_retry",
            "reasoning_summary": (
                "Judge did not receive exact confirmed exploit evidence yet. "
                "The worker should refine the task or execute a verification follow-up."
            ),
            "retry_same_candidate": True,
            "candidate_key": candidate_key,
            "confirmed_finding_ids": [],
            "candidate_finding_ids": [int(item.id) for item in candidate],
            "follow_up_hypothesis_type": follow_up,
        }

    return {
        "status": "progress",
        "resolution_mode": "agentic_judge_progress",
        "reasoning_summary": (
            "Judge classified the result as setup or exploration progress, but not as confirmed exploitation."
        ),
        "retry_same_candidate": False,
        "candidate_key": candidate_key,
        "confirmed_finding_ids": [],
        "candidate_finding_ids": [int(item.id) for item in candidate],
    }


def build_agentic_strategy_update(
    *,
    previous_state: dict[str, Any] | None,
    selected,
    router_trace: dict[str, Any],
    judge_verdict: dict[str, Any],
) -> dict[str, Any]:
    state = ensure_agentic_state(previous_state)
    agentic_state = state["agentic_state"]
    limits = get_agentic_strategy_limits(state)

    candidate_key = str(router_trace.get("candidate_key") or get_candidate_key(selected))
    logical_agent_name = str(
        router_trace.get("logical_agent_name") or get_logical_agent_name(getattr(selected, "agent_name", None))
    )

    candidate_retry_counts = dict(agentic_state.get("candidate_retry_counts") or {})
    logical_attempt_counts = dict(agentic_state.get("logical_agent_attempt_counts") or {})
    logical_success_counts = dict(agentic_state.get("logical_agent_success_counts") or {})
    judge_history = list(agentic_state.get("judge_history") or [])
    confirmed_finding_ids = [
        int(item)
        for item in (agentic_state.get("confirmed_finding_ids") or [])
        if str(item).strip().isdigit()
    ]

    logical_attempt_counts[logical_agent_name] = int(logical_attempt_counts.get(logical_agent_name, 0) or 0) + 1
    if judge_verdict.get("status") == "needs_retry":
        candidate_retry_counts[candidate_key] = int(candidate_retry_counts.get(candidate_key, 0) or 0) + 1
    elif judge_verdict.get("status") == "confirmed":
        logical_success_counts[logical_agent_name] = int(
            logical_success_counts.get(logical_agent_name, 0) or 0
        ) + 1
        candidate_retry_counts.pop(candidate_key, None)
    else:
        candidate_retry_counts.pop(candidate_key, None)

    for finding_id in judge_verdict.get("confirmed_finding_ids", []) or []:
        finding_id = int(finding_id)
        if finding_id not in confirmed_finding_ids:
            confirmed_finding_ids.append(finding_id)

    judge_history.append(
        {
            "candidate_key": candidate_key,
            "logical_agent_name": logical_agent_name,
            "agent_name": getattr(selected, "agent_name", None),
            "hypothesis_type": getattr(selected, "hypothesis_type", None),
            "judge_status": judge_verdict.get("status"),
            "resolution_mode": judge_verdict.get("resolution_mode"),
            "follow_up_hypothesis_type": judge_verdict.get("follow_up_hypothesis_type"),
        }
    )
    judge_history = judge_history[-limits["max_judge_history_items"] :]

    return {
        "agentic_state": {
            "candidate_retry_counts": candidate_retry_counts,
            "logical_agent_attempt_counts": logical_attempt_counts,
            "logical_agent_success_counts": logical_success_counts,
            "judge_history": judge_history,
            "confirmed_finding_ids": confirmed_finding_ids,
        }
    }
