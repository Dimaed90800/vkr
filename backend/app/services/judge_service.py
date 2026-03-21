import json


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
    return round(score, 4)


def classify_decision_type(hypothesis_type: str) -> str:
    if hypothesis_type in {"discovery"}:
        return "discovery"
    if hypothesis_type in {
        "probe",
        "login",
        "authenticated_probe",
        "register_role",
        "login_role",
        "bola",
        "bola_probe",
        "bopla_probe",
        "auth",
    }:
        return "attack"
    if hypothesis_type in {"compare_roles"}:
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
    if h.hypothesis_type in {"probe", "authenticated_probe"}:
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
    if h.hypothesis_type in {"probe", "authenticated_probe"}:
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
    }