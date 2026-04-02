from __future__ import annotations

from ..models import AgentStrategyMemory


def build_context_signature_from_hypothesis(hypothesis) -> str:
    endpoint = _extract_endpoint(hypothesis)
    hypothesis_type = _extract_hypothesis_type(hypothesis)

    if "/identity/api/v2/vehicle/" in endpoint and "/location" in endpoint:
        return "vehicle_location"
    if "/community/api/v2/community/posts/recent" in endpoint:
        return "community_recent_posts"
    if "/identity/api/auth/" in endpoint:
        return "auth_flow"
    if "/workshop/api/" in endpoint:
        return "workshop_api"
    if hypothesis_type in {"verify_bola", "verify_bopla", "verify_auth_boundary"}:
        return f"verify::{hypothesis_type}"
    if hypothesis_type in {
        "register_role",
        "login_role",
        "login",
        "bootstrap_roles",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    }:
        return "auth_flow"
    if endpoint:
        return endpoint
    return hypothesis_type or "generic_context"


def build_pattern_type_from_hypothesis(hypothesis) -> str:
    hypothesis_type = _extract_hypothesis_type(hypothesis)
    if hypothesis_type == "bola_probe":
        return "bola_object_access"
    if hypothesis_type == "verify_bola":
        return "bola_verification"
    if hypothesis_type == "bopla_probe":
        return "bopla_property_exposure"
    if hypothesis_type == "verify_bopla":
        return "bopla_verification"
    if hypothesis_type == "verify_auth_boundary":
        return "auth_boundary_verification"
    if hypothesis_type in {"register_role", "login_role", "login", "bootstrap_roles"}:
        return "auth_bootstrap"
    if hypothesis_type in {"anonymous_probe", "tokenless_replay_probe", "auth_boundary_probe"}:
        return "auth_boundary"
    if hypothesis_type == "authenticated_probe":
        return "authenticated_probe"
    return hypothesis_type or "generic_pattern"


def list_agent_memory_rows(db, session_id: int) -> list[AgentStrategyMemory]:
    if db is None:
        return []
    return db.query(AgentStrategyMemory).filter(
        AgentStrategyMemory.session_id == session_id
    ).all()


def build_agent_memory_index(db, session_id: int) -> dict:
    rows = list_agent_memory_rows(db, session_id)
    return {
        (
            row.agent_name,
            row.context_signature,
            row.pattern_type,
        ): row
        for row in rows
    }


def compute_agent_adjustment(memory_row: AgentStrategyMemory | None) -> float:
    if not memory_row:
        return 0.0

    attempts = int(memory_row.attempts or 0)
    confirmed = int(memory_row.confirmed_count or 0)
    rejected = int(memory_row.rejected_count or 0)

    if attempts <= 0:
        return 0.0

    success_rate = confirmed / attempts
    rejection_rate = rejected / attempts
    adjustment = (success_rate * 0.12) - (rejection_rate * 0.10)
    return round(max(min(adjustment, 0.20), -0.20), 4)


def apply_agent_memory_to_hypotheses(db, session_id: int, hypotheses: list[dict]) -> list[dict]:
    memory_index = build_agent_memory_index(db, session_id)
    adjusted = []

    for item in hypotheses:
        context_signature = build_context_signature_from_hypothesis(item)
        pattern_type = build_pattern_type_from_hypothesis(item)
        memory_row = memory_index.get(
            (
                item.get("agent_name"),
                context_signature,
                pattern_type,
            )
        )
        adjustment = compute_agent_adjustment(memory_row)
        base_confidence = float(item.get("confidence", 0.5) or 0.5)

        payload = dict(item.get("payload", {}))
        payload["agent_memory_context"] = context_signature
        payload["agent_memory_pattern"] = pattern_type
        payload["agent_memory_adjustment"] = adjustment
        if memory_row:
            payload["agent_memory_stats"] = {
                "attempts": int(memory_row.attempts or 0),
                "confirmed_count": int(memory_row.confirmed_count or 0),
                "rejected_count": int(memory_row.rejected_count or 0),
                "last_result": memory_row.last_result,
            }

        adjusted_item = {
            **item,
            "payload": payload,
            "confidence": round(max(min(base_confidence + adjustment, 0.99), 0.01), 4),
        }
        adjusted.append(adjusted_item)

    return adjusted


def record_agent_result(
    db,
    *,
    session_id: int,
    agent_name: str,
    hypothesis,
    execution_result: dict | None,
    request_count: int,
):
    context_signature = build_context_signature_from_hypothesis(hypothesis)
    pattern_type = build_pattern_type_from_hypothesis(hypothesis)
    memory_row = db.query(AgentStrategyMemory).filter(
        AgentStrategyMemory.session_id == session_id,
        AgentStrategyMemory.agent_name == agent_name,
        AgentStrategyMemory.context_signature == context_signature,
        AgentStrategyMemory.pattern_type == pattern_type,
    ).first()

    if not memory_row:
        memory_row = AgentStrategyMemory(
            session_id=session_id,
            agent_name=agent_name,
            context_signature=context_signature,
            pattern_type=pattern_type,
            attempts=0,
            selected_count=0,
            confirmed_count=0,
            rejected_count=0,
            avg_cost=0.0,
        )
        db.add(memory_row)
        db.flush()

    memory_row.attempts = int(memory_row.attempts or 0) + 1
    memory_row.selected_count = int(memory_row.selected_count or 0) + 1

    current_attempts = int(memory_row.attempts or 0)
    previous_avg_cost = float(memory_row.avg_cost or 0.0)
    memory_row.avg_cost = round(
        ((previous_avg_cost * max(current_attempts - 1, 0)) + float(request_count or 0)) / current_attempts,
        4,
    )

    last_result = _classify_agent_result(hypothesis, execution_result or {})
    memory_row.last_result = last_result
    if last_result == "confirmed":
        memory_row.confirmed_count = int(memory_row.confirmed_count or 0) + 1
    elif last_result == "rejected":
        memory_row.rejected_count = int(memory_row.rejected_count or 0) + 1

    return memory_row


def _classify_agent_result(hypothesis, execution_result: dict) -> str:
    verification_status = execution_result.get("verification_status")
    if verification_status == "confirmed":
        return "confirmed"
    if verification_status == "rejected":
        return "rejected"

    status = execution_result.get("status")
    if status == "rejected":
        return "rejected"

    analysis = execution_result.get("analysis") or {}
    inference = analysis.get("inference")
    hypothesis_type = _extract_hypothesis_type(hypothesis)

    if hypothesis_type == "bola_probe":
        return "candidate" if inference == "possible_bola" else "no_signal"
    if hypothesis_type == "bopla_probe":
        return "candidate" if inference == "possible_bopla" else "no_signal"
    if hypothesis_type == "compare_roles":
        if inference in {"possible_access_control_difference", "possible_role_based_response_difference"}:
            return "candidate"
        return "no_signal"

    if status == "executed":
        return "executed"
    return "no_signal"


def _extract_endpoint(hypothesis) -> str:
    if isinstance(hypothesis, dict):
        return str(hypothesis.get("target_endpoint") or "")
    return str(getattr(hypothesis, "target_endpoint", "") or "")


def _extract_hypothesis_type(hypothesis) -> str:
    if isinstance(hypothesis, dict):
        return str(hypothesis.get("hypothesis_type") or "")
    return str(getattr(hypothesis, "hypothesis_type", "") or "")
