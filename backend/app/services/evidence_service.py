from __future__ import annotations

import json

from ..models import Finding


def build_compare_roles_interpretation(comparison: dict) -> dict:
    inference = comparison.get("inference")
    signals = comparison.get("signals", [])

    if inference == "possible_access_control_difference":
        return {
            "finding_type": "access_control_difference",
            "severity": "medium",
            "title": "Possible role-based access control difference",
            "description": (
                "Different roles received materially different responses for the same endpoint "
                "and method."
            ),
            "signals": signals,
        }

    if inference == "possible_role_based_response_difference":
        return {
            "finding_type": "possible_bopla",
            "severity": "medium",
            "title": "Possible role-based property exposure difference",
            "description": (
                "Response structure differs across roles for the same endpoint, which may indicate "
                "property-level exposure or inconsistent filtering."
            ),
            "signals": signals,
        }

    return {}


def maybe_create_finding_from_comparison(
    db,
    session_id: int,
    selected_id: int,
    comparison: dict,
    endpoint: str | None = None,
):
    finding_data = build_compare_roles_interpretation(comparison)
    if not finding_data:
        return None

    finding = Finding(
        session_id=session_id,
        finding_type=finding_data["finding_type"],
        severity=finding_data["severity"],
        endpoint=endpoint,
        related_hypothesis_id=selected_id,
        related_observation_ids=json.dumps(
            [
                comparison.get("observation_a_id"),
                comparison.get("observation_b_id"),
            ],
            ensure_ascii=False,
        ),
        title=finding_data["title"],
        description=finding_data["description"],
        evidence_json=json.dumps(comparison, ensure_ascii=False),
        verification_status="candidate",
    )
    db.add(finding)
    return finding


def _is_high_value_auth_target(endpoint: str | None) -> bool:
    value = (endpoint or "").lower()
    if "/identity/api/auth/" in value:
        return False
    return any(
        marker in value
        for marker in [
            "/community/api/",
            "/identity/api/v2/user",
            "/identity/api/v2/vehicle",
            "/workshop/api/",
        ]
    )


def build_auth_probe_interpretation(
    action_executed: str,
    status_code: int | None,
    endpoint: str | None,
    *,
    source_observation_id: int | None = None,
) -> dict:
    if not _is_high_value_auth_target(endpoint):
        return {}

    if status_code is None:
        return {}

    status_code = int(status_code)

    if 200 <= status_code < 300:
        severity = "medium"
        if action_executed == "auth_boundary_probe":
            severity = "high"

        probe_label = {
            "anonymous_probe": "anonymous request",
            "tokenless_replay_probe": "request replay without bearer token",
            "auth_boundary_probe": "request with invalid bearer token",
        }.get(action_executed, action_executed)

        return {
            "finding_type": "possible_authentication_bypass",
            "severity": severity,
            "title": "Possible authentication boundary bypass",
            "description": (
                f"A high-value endpoint returned a successful response for a {probe_label}, "
                "which may indicate broken authentication or missing authentication enforcement."
            ),
        }

    if status_code not in {404, 405}:
        return {}

    return {
        "finding_type": "auth_boundary_signal",
        "severity": "low",
        "title": "Authentication boundary response signal",
        "description": (
            f"A known high-value endpoint returned HTTP {status_code} during an authentication-boundary probe. "
            "This is not a confirmed bypass, but it is a useful signal for manual review of route exposure, "
            "method handling, and authentication gating."
        ),
    }


def maybe_create_auth_finding_from_execution(
    db,
    session_id: int,
    selected_id: int,
    action_executed: str,
    status_code: int | None,
    endpoint: str | None = None,
    observation_id: int | None = None,
    source_role: str | None = None,
    source_observation_id: int | None = None,
):
    finding_data = build_auth_probe_interpretation(
        action_executed,
        status_code,
        endpoint,
        source_observation_id=source_observation_id,
    )
    if not finding_data:
        return None

    existing = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == finding_data["finding_type"],
        Finding.endpoint == endpoint,
        Finding.verification_status.in_(["candidate", "confirmed"]),
    ).first()
    if existing:
        return existing

    evidence = {
        "action_executed": action_executed,
        "status_code": status_code,
        "endpoint": endpoint,
        "observation_id": observation_id,
        "source_role": source_role,
        "source_observation_id": source_observation_id,
    }

    finding = Finding(
        session_id=session_id,
        finding_type=finding_data["finding_type"],
        severity=finding_data["severity"],
        endpoint=endpoint,
        related_hypothesis_id=selected_id,
        related_observation_ids=json.dumps([observation_id] if observation_id else [], ensure_ascii=False),
        title=finding_data["title"],
        description=finding_data["description"],
        evidence_json=json.dumps(evidence, ensure_ascii=False),
        verification_status="candidate",
    )
    db.add(finding)
    return finding
