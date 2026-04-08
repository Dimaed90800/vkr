from __future__ import annotations

import logging

from ..services.agent_hypothesis_service import (
    find_recent_posts_observations,
    generate_analysis_agent_hypotheses,
    generate_auth_agent_hypotheses,
    generate_bola_agent_hypotheses,
    generate_bopla_agent_hypotheses,
    generate_discovery_agent_hypotheses,
    generate_probe_agent_hypotheses,
    generate_verifier_agent_hypotheses,
)
from ..services.dify_service import (
    call_dify_auth_agent,
    call_dify_bola_agent,
    call_dify_bopla_agent,
)
from ..services.bopla_service import extract_sensitive_field_paths, filter_expected_bopla_fields
from ..services.extraction_service import extract_vehicle_ids_from_text

logger = logging.getLogger(__name__)


def generate_hypotheses_for_agent(spec: dict, context: dict) -> list[dict]:
    implementation_type = spec.get("implementation_type")
    adapter_key = spec.get("adapter_key")

    if implementation_type == "rule_based":
        generator = _RULE_BASED_GENERATORS.get(adapter_key)
        if not generator:
            return []
        return generator(context)

    if implementation_type == "dify":
        generator = _DIFY_GENERATORS.get(adapter_key)
        if not generator:
            return []
        return generator(context)

    return []


def _generate_auth(context: dict) -> list[dict]:
    return generate_auth_agent_hypotheses(
        context["roles"],
        context["observations"],
        context["findings"],
        context["api_items"],
        getattr(context["session"], "target_url", None),
    )


def _generate_discovery(context: dict) -> list[dict]:
    return generate_discovery_agent_hypotheses(context["api_items"])


def _generate_probe(context: dict) -> list[dict]:
    return generate_probe_agent_hypotheses(
        context["api_items"],
        context["observations"],
        context["authenticated_roles"],
        getattr(context["session"], "target_url", None),
    )


def _generate_analysis(context: dict) -> list[dict]:
    return generate_analysis_agent_hypotheses(context["observations"])


def _generate_bola(context: dict) -> list[dict]:
    return generate_bola_agent_hypotheses(
        context["observations"],
        context["findings"],
        context["authenticated_roles"],
        context["api_items"],
        getattr(context["session"], "target_url", None),
    )


def _generate_bopla(context: dict) -> list[dict]:
    return generate_bopla_agent_hypotheses(
        context["observations"],
        context["findings"],
    )


def _generate_verifier(context: dict) -> list[dict]:
    return generate_verifier_agent_hypotheses(context["findings"])


def _generate_business_logic(context: dict) -> list[dict]:
    return []


def _generate_dify_bola(context: dict) -> list[dict]:
    authenticated_roles = context["authenticated_roles"]
    observations = context["observations"]
    findings = context["findings"]
    session_obj = context["session"]

    if len(authenticated_roles) < 2:
        return []

    roles_compact = [role.role_name for role in authenticated_roles[:2]]
    known_vehicle_ids = []
    seen_object_ids = set()
    recent_observations_compact = []
    seen_observation_ids = set()
    for obs in find_recent_posts_observations(observations):
        object_ids = extract_vehicle_ids_from_text(obs.body_preview or "")[:3]
        if object_ids and getattr(obs, "id", None) not in seen_observation_ids:
            recent_observations_compact.append(
                {
                    "id": getattr(obs, "id", None),
                    "endpoint": getattr(obs, "endpoint", None),
                    "method": getattr(obs, "method", None),
                    "role_name": getattr(obs, "role_name", None),
                    "status_code": getattr(obs, "status_code", None),
                    "object_ids": object_ids,
                }
            )
            seen_observation_ids.add(getattr(obs, "id", None))

        for object_id in object_ids:
            if object_id in seen_object_ids:
                continue
            seen_object_ids.add(object_id)
            known_vehicle_ids.append(
                {
                    "object_type": "vehicle",
                    "object_id": object_id,
                    "source_endpoint": getattr(obs, "endpoint", None),
                    "source_role": getattr(obs, "role_name", None),
                }
            )

    for obs in observations[-20:]:
        endpoint = str(getattr(obs, "endpoint", "") or "")
        if "/identity/api/v2/vehicle/" not in endpoint or "/location" not in endpoint:
            continue
        if getattr(obs, "id", None) in seen_observation_ids:
            continue
        object_ids = extract_vehicle_ids_from_text(getattr(obs, "body_preview", "") or "")
        endpoint_object_id = endpoint.rstrip("/").split("/")[-2] if "/" in endpoint else None
        if endpoint_object_id and endpoint_object_id not in object_ids:
            object_ids = [endpoint_object_id, *object_ids]
        recent_observations_compact.append(
            {
                "id": getattr(obs, "id", None),
                "endpoint": endpoint,
                "method": getattr(obs, "method", None),
                "role_name": getattr(obs, "role_name", None),
                "status_code": getattr(obs, "status_code", None),
                "object_ids": object_ids[:3],
            }
        )
        seen_observation_ids.add(getattr(obs, "id", None))

    candidate_findings_compact = []
    for finding in findings:
        if finding.finding_type != "possible_bola":
            continue
        if getattr(finding, "verification_status", "candidate") != "candidate":
            continue
        candidate_findings_compact.append(
            {
                "id": finding.id,
                "finding_type": finding.finding_type,
                "endpoint": finding.endpoint,
                "verification_status": finding.verification_status,
            }
        )

    if not known_vehicle_ids and not candidate_findings_compact:
        logger.warning(
            "Dify BOLA agent skipped for session %s: no known vehicle ids and no candidate findings",
            getattr(session_obj, "id", None),
        )
        return []

    try:
        return call_dify_bola_agent(
            session_id=session_obj.id,
            roles_compact=roles_compact,
            recent_observations_compact=recent_observations_compact,
            known_object_ids=known_vehicle_ids,
            candidate_findings_compact=candidate_findings_compact,
            target_base_url=session_obj.target_url,
        )
    except Exception as exc:
        logger.warning(
            "Dify BOLA agent hypotheses generation failed for session %s: %s",
            getattr(session_obj, "id", None),
            exc,
        )
        return []


def _generate_dify_bopla(context: dict) -> list[dict]:
    observations = context["observations"]
    findings = context["findings"]
    session_obj = context["session"]

    recent_observations_compact = []
    for obs in observations[-20:]:
        endpoint = str(getattr(obs, "endpoint", "") or "")
        if not endpoint:
            continue
        suspected_fields = extract_sensitive_field_paths(getattr(obs, "body_preview", "") or "")
        suspected_fields, _, _ = filter_expected_bopla_fields(endpoint, suspected_fields)
        if not suspected_fields:
            continue
        recent_observations_compact.append(
            {
                "id": getattr(obs, "id", None),
                "endpoint": endpoint,
                "method": getattr(obs, "method", None),
                "role_name": getattr(obs, "role_name", None),
                "status_code": getattr(obs, "status_code", None),
                "suspected_fields": suspected_fields,
            }
        )

    candidate_findings_compact = []
    for finding in findings:
        if finding.finding_type != "possible_bopla":
            continue
        if getattr(finding, "verification_status", "candidate") != "candidate":
            continue
        evidence = {}
        try:
            import json
            evidence = json.loads(getattr(finding, "evidence_json", "") or "{}")
        except Exception:
            evidence = {}
        candidate_findings_compact.append(
            {
                "id": finding.id,
                "finding_type": finding.finding_type,
                "endpoint": finding.endpoint,
                "verification_status": finding.verification_status,
                "exposed_fields": evidence.get("exposed_fields", []),
            }
        )

    if not recent_observations_compact and not candidate_findings_compact:
        return []

    return call_dify_bopla_agent(
        session_id=session_obj.id,
        recent_observations_compact=recent_observations_compact,
        candidate_findings_compact=candidate_findings_compact,
        target_base_url=session_obj.target_url,
    )


def _generate_dify_auth(context: dict) -> list[dict]:
    observations = context["observations"]
    findings = context["findings"]
    roles = context["roles"]
    session_obj = context["session"]

    roles_compact = []
    for role in roles[:4]:
        roles_compact.append(
            {
                "role_name": getattr(role, "role_name", None),
                "status": getattr(role, "status", None),
                "has_access_token": bool(getattr(role, "access_token", None)),
                "last_auth_status": getattr(role, "last_auth_status", None),
            }
        )

    recent_observations_compact = []
    for obs in observations[-25:]:
        endpoint = str(getattr(obs, "endpoint", "") or "").strip()
        if not endpoint:
            continue
        recent_observations_compact.append(
            {
                "id": getattr(obs, "id", None),
                "endpoint": endpoint,
                "method": getattr(obs, "method", None),
                "role_name": getattr(obs, "role_name", None),
                "status_code": getattr(obs, "status_code", None),
                "request_headers": getattr(obs, "request_headers", None),
            }
        )

    candidate_findings_compact = []
    for finding in findings:
        if getattr(finding, "verification_status", "candidate") != "candidate":
            continue
        if finding.finding_type not in {"possible_authentication_bypass", "auth_boundary_signal"}:
            continue
        evidence = {}
        try:
            import json
            evidence = json.loads(getattr(finding, "evidence_json", "") or "{}")
        except Exception:
            evidence = {}
        candidate_findings_compact.append(
            {
                "id": finding.id,
                "finding_type": finding.finding_type,
                "endpoint": finding.endpoint,
                "verification_status": finding.verification_status,
                "expected_status_code": evidence.get("status_code"),
                "source_role": evidence.get("source_role"),
            }
        )

    if not recent_observations_compact and not candidate_findings_compact:
        return []

    try:
        return call_dify_auth_agent(
            session_id=session_obj.id,
            roles_compact=roles_compact,
            recent_observations_compact=recent_observations_compact,
            candidate_findings_compact=candidate_findings_compact,
            target_base_url=session_obj.target_url,
        )
    except Exception as exc:
        logger.warning(
            "Dify Auth agent hypotheses generation failed for session %s: %s",
            getattr(session_obj, "id", None),
            exc,
        )
        return []


_RULE_BASED_GENERATORS = {
    "auth": _generate_auth,
    "discovery": _generate_discovery,
    "probe": _generate_probe,
    "analysis": _generate_analysis,
    "bola": _generate_bola,
    "bopla": _generate_bopla,
    "verifier": _generate_verifier,
    "business_logic": _generate_business_logic,
}

_DIFY_GENERATORS = {
    "dify_bola": _generate_dify_bola,
    "dify_bopla": _generate_dify_bopla,
    "dify_auth": _generate_dify_auth,
}
