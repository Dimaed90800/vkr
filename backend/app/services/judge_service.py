from __future__ import annotations

import json
import re


UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)


def _payload_json(h):
    if getattr(h, "payload_json", None):
        try:
            return json.loads(h.payload_json)
        except Exception:
            return {}
    return {}


def _endpoint_value(h) -> str:
    return str(getattr(h, "target_endpoint", "") or "").lower()


def _is_auth_endpoint(h) -> bool:
    return "/identity/api/auth/" in _endpoint_value(h)


def _is_high_value_endpoint(h) -> bool:
    endpoint = _endpoint_value(h)
    if _is_auth_endpoint(h):
        return False
    return any(
        marker in endpoint
        for marker in [
            "/community/api/",
            "/identity/api/v2/user",
            "/identity/api/v2/vehicle",
            "/workshop/api/",
        ]
    )


def _role_name_from_payload(h) -> str | None:
    payload = _payload_json(h)
    role_name = payload.get("role_name")
    return str(role_name) if role_name else None


def _has_authenticated_role_gap(h) -> bool:
    payload = _payload_json(h)
    roles_state = payload.get("roles_state") or {}
    if not isinstance(roles_state, dict):
        return False
    statuses = [str(value or "") for value in roles_state.values()]
    if not statuses:
        return False
    return any(status != "authenticated" for status in statuses)


def _is_object_style_endpoint_value(endpoint: str) -> bool:
    endpoint = str(endpoint or "").lower()
    return any(
        marker in endpoint
        for marker in [
            "/vehicle/",
            "/order/",
            "/video/",
            "/merchant/",
            "/mechanic/",
            "/location",
            "/report",
        ]
    ) or bool(UUID_RE.search(endpoint))


def _infer_coverage_buckets_for_hypothesis(h) -> set[str]:
    hypothesis_type = str(getattr(h, "hypothesis_type", "") or "")
    endpoint = _endpoint_value(h)
    buckets = set()

    if hypothesis_type == "discovery":
        buckets.add("discovery")

    if hypothesis_type in {
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
        "verify_auth_boundary",
        "register_role",
        "login_role",
    }:
        buckets.add("auth_boundary")

    if hypothesis_type in {"bola_probe", "verify_bola", "compare_roles"} or _is_object_style_endpoint_value(endpoint):
        buckets.add("object_access")

    if hypothesis_type in {"bopla_probe", "verify_bopla"} or "/community/api/" in endpoint:
        buckets.add("data_exposure")

    if _is_high_value_endpoint(h):
        buckets.add("high_value_api")

    return buckets


def _infer_coverage_buckets_for_observation(obs) -> set[str]:
    endpoint = str(getattr(obs, "endpoint", "") or "").lower()
    buckets = set()

    if _is_object_style_endpoint_value(endpoint):
        buckets.add("object_access")

    if "/community/api/" in endpoint:
        buckets.add("data_exposure")

    if any(
        marker in endpoint
        for marker in [
            "/identity/api/v2/user",
            "/dashboard",
            "/identity/api/auth/",
        ]
    ):
        buckets.add("auth_boundary")

    if any(
        marker in endpoint
        for marker in [
            "/community/api/",
            "/identity/api/v2/user",
            "/identity/api/v2/vehicle",
            "/workshop/api/",
        ]
    ):
        buckets.add("high_value_api")

    return buckets


def _compute_coverage_bonus(h, recent_observations) -> float:
    candidate_buckets = _infer_coverage_buckets_for_hypothesis(h)
    if not candidate_buckets:
        return 0.0

    observation_window = list(recent_observations or [])[-25:]
    coverage_counts = {bucket: 0 for bucket in candidate_buckets}
    for obs in observation_window:
        observed_buckets = _infer_coverage_buckets_for_observation(obs)
        for bucket in candidate_buckets:
            if bucket in observed_buckets:
                coverage_counts[bucket] += 1

    bonus = 0.0
    for bucket, count in coverage_counts.items():
        if bucket == "discovery":
            continue
        if count == 0:
            bonus += 0.08
        elif count == 1:
            bonus += 0.04
        elif count == 2:
            bonus += 0.02

    if "high_value_api" in candidate_buckets and coverage_counts.get("high_value_api", 0) == 0:
        bonus += 0.02

    return round(min(bonus, 0.12), 4)


def calculate_dynamic_priority(h, recent_observations=None) -> float:
    score = calculate_priority_score(h)
    recent_observations = recent_observations or []
    payload = _payload_json(h)

    score += float(payload.get("judge_feedback_adjustment", 0.0) or 0.0)
    score += _compute_coverage_bonus(h, recent_observations)

    if getattr(h, "hypothesis_type", None) in {"register_role", "login_role"} and _has_authenticated_role_gap(h):
        score += 0.12

    if getattr(h, "hypothesis_type", None) in {"verify_bola", "verify_bopla", "verify_auth_boundary"}:
        score += 0.12

    if getattr(h, "hypothesis_type", None) == "bopla_probe" and _is_high_value_endpoint(h):
        score += 0.08

    if getattr(h, "hypothesis_type", None) == "authenticated_probe":
        role_name = _role_name_from_payload(h)
        endpoint = getattr(h, "target_endpoint", None)
        method = getattr(h, "http_method", "GET")

        duplicate_count = 0
        for obs in recent_observations[-10:]:
            if (
                (obs.endpoint or "") == (endpoint or "")
                and (obs.method or "").upper() == (method or "").upper()
                and (obs.role_name or None) == (role_name or None)
            ):
                duplicate_count += 1

        if duplicate_count >= 1:
            score -= min(0.08 * duplicate_count, 0.30)

    if getattr(h, "hypothesis_type", None) == "compare_roles" and _is_auth_endpoint(h):
        score -= 0.20

    if getattr(h, "hypothesis_type", None) == "bola_probe":
        endpoint = getattr(h, "target_endpoint", None)
        duplicate_count = 0
        for obs in recent_observations[-12:]:
            if (
                (obs.endpoint or "") == (endpoint or "")
                and (obs.method or "").upper() == (getattr(h, "http_method", "GET") or "GET").upper()
            ):
                duplicate_count += 1

        if duplicate_count >= 2:
            score -= min(0.10 * (duplicate_count - 1), 0.35)

    return round(score, 4)


def calculate_priority_score(h) -> float:
    confidence = float(h.confidence or 0)
    coverage_gain = float(h.coverage_gain or 0)
    evidence_readiness = float(h.evidence_readiness or 0)
    false_positive_risk = float(h.false_positive_risk or 0)
    estimated_cost = float(h.estimated_cost or 1)

    normalized_cost = min(estimated_cost / 5.0, 1.0)

    score = (
        0.30 * confidence +
        0.25 * coverage_gain +
        0.25 * evidence_readiness -
        0.10 * false_positive_risk -
        0.10 * normalized_cost
    )

    if getattr(h, "hypothesis_type", None) in {
        "authenticated_probe",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    } and _is_high_value_endpoint(h):
        score += 0.09

    if getattr(h, "hypothesis_type", None) == "compare_roles" and _is_auth_endpoint(h):
        score -= 0.25

    if getattr(h, "hypothesis_type", None) == "compare_roles" and _is_high_value_endpoint(h):
        score += 0.04

    if getattr(h, "hypothesis_type", None) == "bopla_probe" and _is_auth_endpoint(h):
        score -= 0.20

    if getattr(h, "hypothesis_type", None) == "bopla_probe" and _is_high_value_endpoint(h):
        score += 0.08

    if getattr(h, "hypothesis_type", None) == "bola_probe":
        score += 0.06

    if getattr(h, "hypothesis_type", None) in {"verify_bola", "verify_bopla", "verify_auth_boundary"}:
        score += 0.10

    if getattr(h, "hypothesis_type", None) == "verify_bopla" and _is_high_value_endpoint(h):
        score += 0.06

    payload = _payload_json(h)
    if getattr(h, "hypothesis_type", None) == "authenticated_probe" and payload.get("role_name"):
        score += 0.01
    if getattr(h, "hypothesis_type", None) in {"anonymous_probe", "tokenless_replay_probe", "auth_boundary_probe"}:
        score += 0.03

    return round(score, 4)


def classify_decision_type(hypothesis_type: str) -> str:
    if hypothesis_type in {"discovery"}:
        return "discovery"
    if hypothesis_type in {
        "probe",
        "login",
        "bootstrap_roles",
        "authenticated_probe",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
        "register_role",
        "login_role",
        "bola",
        "bola_probe",
        "bopla_probe",
        "auth",
    }:
        return "attack"
    if hypothesis_type in {"compare_roles", "verify_bola", "verify_bopla", "verify_auth_boundary"}:
        return "verify"
    return "verify"


def build_reasoning_summary(h, score: float) -> str:
    return (
        f"Selected hypothesis '{h.hypothesis_type}' with score {score}. "
        f"Confidence={h.confidence}, coverage_gain={h.coverage_gain}, "
        f"evidence_readiness={h.evidence_readiness}, "
        f"false_positive_risk={h.false_positive_risk}, estimated_cost={h.estimated_cost}."
    )


def build_required_evidence(h) -> list[str]:
    if h.hypothesis_type in {"login", "login_role"}:
        return [
            "successful authentication response",
            "presence of access token or session artifact",
            "ability to reuse token in subsequent request",
        ]
    if h.hypothesis_type == "register_role":
        return [
            "successful registration response",
            "credential pair stored for role",
            "role status updated",
        ]
    if h.hypothesis_type == "bootstrap_roles":
        return [
            "default role records created",
            "roles available for subsequent registration",
            "session can proceed to auth flow",
        ]
    if h.hypothesis_type in {
        "probe",
        "authenticated_probe",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    }:
        return [
            "valid HTTP response",
            "status code and body shape recorded",
            "evidence of API behavior consistency",
        ]
    if h.hypothesis_type == "compare_roles":
        return [
            "paired observations for at least two roles",
            "response body or status code comparison",
            "interpretable difference signal",
        ]
    if h.hypothesis_type == "bola_probe":
        return [
            "same object id accessed under two different roles",
            "successful response for non-owner role or identical shared response",
            "interpretation indicates possible broken object level authorization",
        ]
    if h.hypothesis_type == "bopla_probe":
        return [
            "response contains potentially sensitive fields",
            "field names suggest excessive data exposure",
            "evidence indicates possible object/property overexposure",
        ]
    if h.hypothesis_type == "discovery":
        return [
            "new API endpoints discovered",
            "improved surface coverage",
            "inventory updated with actionable entries",
        ]
    if h.hypothesis_type == "verify_bola":
        return [
            "repeated cross-role access reproduces object-level authorization issue",
            "non-owner role still receives successful response",
            "finding can be upgraded from candidate to confirmed",
        ]

    if h.hypothesis_type == "verify_bopla":
        return [
            "repeated request reproduces excessive data exposure",
            "sensitive fields remain visible in response",
            "finding can be upgraded from candidate to confirmed",
        ]
    if h.hypothesis_type == "verify_auth_boundary":
        return [
            "repeated auth-boundary probe reproduces the observed route behavior",
            "status code remains consistent with the original signal",
            "finding can be retained as a confirmed auth-boundary signal or rejected",
        ]
    return [
        "response recorded",
        "observation stored",
    ]


def build_stop_condition(h) -> dict:
    if h.hypothesis_type in {"login", "login_role"}:
        return {
            "stop_if": [
                "authentication endpoint repeatedly fails with same payload",
                "no token/session artifact is returned",
            ]
        }
    if h.hypothesis_type == "register_role":
        return {
            "stop_if": [
                "registration repeatedly fails for generated credentials",
            ]
        }
    if h.hypothesis_type == "bootstrap_roles":
        return {
            "stop_if": [
                "roles already exist in session",
                "role bootstrap does not create any usable accounts",
            ]
        }
    if h.hypothesis_type in {
        "probe",
        "authenticated_probe",
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    }:
        return {
            "stop_if": [
                "endpoint repeatedly returns identical non-informative response",
                "response does not improve evidence state",
            ]
        }
    if h.hypothesis_type == "compare_roles":
        return {
            "stop_if": [
                "paired observations are unavailable",
                "comparison produces no useful difference signal",
            ]
        }
    if h.hypothesis_type == "bola_probe":
        return {
            "stop_if": [
                "object id is invalid",
                "both roles receive inconclusive not-found response",
                "evidence remains insufficient for BOLA interpretation",
            ]
        }
    if h.hypothesis_type == "bopla_probe":
        return {
            "stop_if": [
                "response body is not JSON",
                "no suspicious fields are present",
                "exposed fields are already expected public attributes",
            ]
        }
    if h.hypothesis_type == "discovery":
        return {
            "stop_if": [
                "no new endpoints discovered after additional discovery round",
            ]
        }
    if h.hypothesis_type == "verify_bola":
        return {
            "stop_if": [
                "repeated request no longer reproduces the issue",
                "roles or tokens are unavailable",
                "evidence is insufficient to confirm BOLA",
            ]
        }

    if h.hypothesis_type == "verify_bopla":
        return {
            "stop_if": [
                "response no longer contains exposed sensitive fields",
                "endpoint behavior changed",
                "evidence is insufficient to confirm BOPLA",
            ]
        }
    if h.hypothesis_type == "verify_auth_boundary":
        return {
            "stop_if": [
                "route behavior no longer reproduces the auth-boundary signal",
                "endpoint no longer returns the observed status code",
                "evidence is insufficient to keep the auth-boundary signal",
            ]
        }
    return {"stop_if": ["no useful evidence obtained"]}


def serialize_hypothesis(h):
    payload = {}
    if getattr(h, "payload_json", None):
        try:
            payload = json.loads(h.payload_json)
        except Exception:
            payload = {}

    candidate_key = payload.get("candidate_key")
    if not candidate_key:
        candidate_key = f"{h.hypothesis_type}::{h.target_endpoint or 'none'}::{h.http_method or 'none'}"

    return {
        "id": h.id,
        "agent_name": h.agent_name,
        "candidate_key": candidate_key,
        "type": h.hypothesis_type,
        "endpoint": h.target_endpoint,
        "method": h.http_method,
        "description": h.description,
        "confidence": h.confidence,
        "coverage_gain": h.coverage_gain,
        "evidence_readiness": h.evidence_readiness,
        "false_positive_risk": h.false_positive_risk,
        "estimated_cost": h.estimated_cost,
        "judge_feedback_adjustment": payload.get("judge_feedback_adjustment", 0.0),
        "judge_feedback_stats": payload.get("judge_feedback_stats"),
        "agent_role_class": payload.get("agent_role_class"),
        "agent_provider": payload.get("agent_provider"),
    }
