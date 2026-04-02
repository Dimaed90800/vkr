from __future__ import annotations

import json
import os
import logging
import re
import requests

from .bopla_service import extract_sensitive_field_paths, filter_expected_bopla_fields

logger = logging.getLogger(__name__)
VEHICLE_LOCATION_RE = re.compile(r"/identity/api/v2/(?P<object_type>[^/]+)/(?P<object_id>[^/]+)/location/?$")

DIFY_API_URL = os.getenv("DIFY_API_URL", "http://host.docker.internal/v1/workflows/run")
DIFY_API_KEY = os.getenv("DIFY_API_KEY", "")
BOLA_AGENT_DIFY_API_URL = os.getenv("BOLA_AGENT_DIFY_API_URL", DIFY_API_URL)
BOLA_AGENT_DIFY_API_KEY = os.getenv("BOLA_AGENT_DIFY_API_KEY", DIFY_API_KEY)
BOPLA_AGENT_DIFY_API_URL = os.getenv("BOPLA_AGENT_DIFY_API_URL", DIFY_API_URL)
BOPLA_AGENT_DIFY_API_KEY = os.getenv("BOPLA_AGENT_DIFY_API_KEY", DIFY_API_KEY)
AUTH_AGENT_DIFY_API_URL = os.getenv("AUTH_AGENT_DIFY_API_URL", DIFY_API_URL)
AUTH_AGENT_DIFY_API_KEY = os.getenv("AUTH_AGENT_DIFY_API_KEY", DIFY_API_KEY)
REPORT_AGENT_DIFY_API_URL = os.getenv("REPORT_AGENT_DIFY_API_URL", DIFY_API_URL)
REPORT_AGENT_DIFY_API_KEY = os.getenv("REPORT_AGENT_DIFY_API_KEY", DIFY_API_KEY)
JUDGE_INSTRUCTIONS = (
    "You are a judge agent for adaptive REST API security testing. "
    "Select exactly one candidate_key from the provided hypotheses. "
    "Prefer actions with high expected security value, high evidence_readiness, and high coverage_gain. "
    "Avoid redundant repeated actions and avoid low-value auth-only comparisons. "
    "Prefer verify_bola or verify_bopla when a candidate finding already exists. "
    "Return strict JSON only with fields selected_key, score, reason."
)


def _normalize_possible_json_string(value):
    if isinstance(value, dict):
        return value

    if isinstance(value, str):
        value = value.strip()
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None

    return None


def _normalize_possible_json_list(value):
    if isinstance(value, list):
        return value

    if isinstance(value, str):
        value = value.strip()
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return parsed
        except json.JSONDecodeError:
            return None

    return None


def _safe_int(value, default: int | None = None) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _parse_outputs(outputs: dict) -> dict:
    if not isinstance(outputs, dict):
        raise Exception(f"Dify outputs is not an object: {outputs}")

    # 1. Уже нормальный structured output
    if "selected_key" in outputs:
        nested = _normalize_possible_json_string(outputs.get("selected_key"))
        if nested and "selected_key" in nested:
            return {
                "selected_key": nested["selected_key"],
                "score": nested.get("score", outputs.get("score", 0.5)),
                "reason": nested.get("reason", outputs.get("reason", "Dify workflow selection")),
            }
        return {
            "selected_key": outputs["selected_key"],
            "score": outputs.get("score", 0.5),
            "reason": outputs.get("reason", "Dify workflow selection"),
        }

    # 2. Одно из полей содержит JSON-строку
    for key in ("text", "result", "answer", "output"):
        value = outputs.get(key)
        parsed = _normalize_possible_json_string(value)
        if parsed and "selected_key" in parsed:
            return {
                "selected_key": parsed["selected_key"],
                "score": parsed.get("score", 0.5),
                "reason": parsed.get("reason", "Dify workflow selection"),
            }

    raise Exception(f"Could not extract selected_key from Dify workflow outputs: {outputs}")


def _extract_candidate_list(outputs: dict, *, agent_label: str) -> list[dict]:
    if not isinstance(outputs, dict):
        raise Exception(f"{agent_label} outputs is not an object: {outputs}")

    candidates = _normalize_possible_json_list(outputs.get("candidates"))
    if isinstance(candidates, list):
        return candidates

    structured_output = outputs.get("structured_output")
    structured_output = _normalize_possible_json_string(structured_output) or structured_output
    if isinstance(structured_output, dict):
        candidates = _normalize_possible_json_list(structured_output.get("candidates"))
        if isinstance(candidates, list):
            return candidates

    raise Exception(f"{agent_label} outputs missing candidate list: {outputs}")


def _extract_report_text(outputs: dict, *, agent_label: str) -> str:
    if not isinstance(outputs, dict):
        raise Exception(f"{agent_label} outputs is not an object: {outputs}")

    for key in ("report_markdown", "report_text", "text", "result", "answer", "output"):
        value = outputs.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    structured_output = outputs.get("structured_output")
    structured_output = _normalize_possible_json_string(structured_output) or structured_output
    if isinstance(structured_output, dict):
        for key in ("report_markdown", "report_text", "text"):
            value = structured_output.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    raise Exception(f"{agent_label} outputs missing textual report: {outputs}")


def _compact_hypotheses(hypotheses: list[dict]) -> list[dict]:
    compact = []
    for item in hypotheses:
        compact.append({
            "candidate_key": item.get("candidate_key"),
            "type": item.get("type"),
            "endpoint": item.get("endpoint"),
            "method": item.get("method"),
            "confidence": item.get("confidence"),
            "coverage_gain": item.get("coverage_gain"),
            "evidence_readiness": item.get("evidence_readiness"),
            "false_positive_risk": item.get("false_positive_risk"),
            "estimated_cost": item.get("estimated_cost"),
            "description": item.get("description"),
        })
    return compact


def _safe_float(value, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_object_from_endpoint(endpoint: str) -> tuple[str | None, str | None]:
    match = VEHICLE_LOCATION_RE.search(endpoint or "")
    if not match:
        return None, None
    return match.group("object_type"), match.group("object_id")


def _extract_int_from_text(value: str) -> int | None:
    match = re.search(r"(\d+)", value or "")
    if not match:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def _looks_like_uuid(value: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value or ""))


def _normalize_bola_candidate(
    candidate: dict,
    *,
    target_base_url: str,
    roles_compact: list[str],
    known_object_ids: list[dict],
    candidate_findings_compact: list[dict],
) -> dict | None:
    if not isinstance(candidate, dict):
        return None

    hypothesis_type = str(candidate.get("hypothesis_type", "")).strip()
    if hypothesis_type not in {"bola_probe", "verify_bola"}:
        return None

    payload = candidate.get("payload")
    if not isinstance(payload, dict):
        payload = {}

    agent_name = str(candidate.get("agent_name", "dify_bola_agent")).strip() or "dify_bola_agent"
    fallback_owner_role = str(roles_compact[0]).strip() if len(roles_compact) >= 1 else ""
    fallback_other_role = str(roles_compact[1]).strip() if len(roles_compact) >= 2 else ""

    def _candidate_description(default: str) -> str:
        value = str(candidate.get("description", "")).strip()
        return value or default

    if hypothesis_type == "bola_probe":
        endpoint = str(candidate.get("target_endpoint", "")).strip()
        owner_role = str(payload.get("owner_role", "")).strip() or fallback_owner_role
        other_role = str(payload.get("other_role", "")).strip() or fallback_other_role
        object_type = str(payload.get("object_type", "")).strip()
        object_id = str(payload.get("object_id", "")).strip()

        endpoint_object_type, endpoint_object_id = _extract_object_from_endpoint(endpoint)
        if endpoint_object_type:
            object_type = endpoint_object_type
        if endpoint_object_id:
            object_id = endpoint_object_id
        if not object_type and endpoint_object_type:
            object_type = endpoint_object_type

        if not object_id:
            for item in known_object_ids:
                if not isinstance(item, dict):
                    continue
                candidate_object_id = str(item.get("object_id", "")).strip()
                if candidate_object_id:
                    object_id = candidate_object_id
                    object_type = str(item.get("object_type", "")).strip() or object_type or "vehicle"
                    break

        object_type = object_type or "vehicle"
        if endpoint and not endpoint_object_id and object_id:
            endpoint = f"{target_base_url.rstrip('/')}/identity/api/v2/{object_type}/{object_id}/location"
        if not endpoint and object_id:
            endpoint = f"{target_base_url.rstrip('/')}/identity/api/v2/{object_type}/{object_id}/location"

        if owner_role == other_role:
            return None
        if not owner_role or not other_role or not object_id or not endpoint:
            return None
        if not _looks_like_uuid(object_id):
            return None
        if not VEHICLE_LOCATION_RE.search(endpoint):
            return None

        return {
            "candidate_key": f"bola_probe::{object_type}::{object_id}::{owner_role}::{other_role}",
            "agent_name": agent_name,
            "hypothesis_type": "bola_probe",
            "target_endpoint": endpoint,
            "http_method": str(candidate.get("http_method", "GET")).strip() or "GET",
            "description": _candidate_description(
                f"Probe shared {object_type} object across roles {owner_role} and {other_role}"
            ),
            "payload": {
                "owner_role": owner_role,
                "other_role": other_role,
                "object_type": object_type,
                "object_id": object_id,
            },
            "confidence": _safe_float(candidate.get("confidence"), 0.96),
            "estimated_cost": _safe_float(candidate.get("estimated_cost"), 1.0),
            "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.08),
            "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.95),
            "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.97),
        }

    finding_id = payload.get("finding_id")
    endpoint = str(candidate.get("target_endpoint", payload.get("endpoint", ""))).strip()

    if finding_id in (None, "") and endpoint:
        for finding in candidate_findings_compact:
            if not isinstance(finding, dict):
                continue
            if str(finding.get("endpoint", "")).strip() == endpoint:
                finding_id = finding.get("id")
                break

    if finding_id in (None, ""):
        finding_id = _extract_int_from_text(str(candidate.get("candidate_key", "")))

    if finding_id in (None, "") or not endpoint:
        return None

    finding_id_int = int(finding_id)
    normalized_payload = {
        "finding_id": finding_id_int,
        "owner_role": str(payload.get("owner_role", "")).strip() or fallback_owner_role,
        "other_role": str(payload.get("other_role", "")).strip() or fallback_other_role,
        "endpoint": endpoint,
    }

    return {
        "candidate_key": f"verify_bola::{finding_id_int}",
        "agent_name": agent_name,
        "hypothesis_type": "verify_bola",
        "target_endpoint": endpoint,
        "http_method": str(candidate.get("http_method", "GET")).strip() or "GET",
        "description": _candidate_description(f"Verify BOLA candidate finding #{finding_id_int}"),
        "payload": normalized_payload,
        "confidence": _safe_float(candidate.get("confidence"), 0.99),
        "estimated_cost": _safe_float(candidate.get("estimated_cost"), 0.2),
        "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.03),
        "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.95),
        "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.99),
    }


def _normalize_bopla_candidate(
    candidate: dict,
    *,
    candidate_findings_compact: list[dict],
    recent_observations_compact: list[dict],
) -> dict | None:
    if not isinstance(candidate, dict):
        return None

    hypothesis_type = str(candidate.get("hypothesis_type", "")).strip()
    if hypothesis_type not in {"bopla_probe", "verify_bopla"}:
        return None

    payload = candidate.get("payload")
    if not isinstance(payload, dict):
        payload = {}

    agent_name = str(candidate.get("agent_name", "dify_bopla_agent")).strip() or "dify_bopla_agent"

    def _candidate_description(default: str) -> str:
        value = str(candidate.get("description", "")).strip()
        return value or default

    if hypothesis_type == "bopla_probe":
        endpoint = str(candidate.get("target_endpoint", "")).strip()
        observation_id = payload.get("observation_id")
        suspected_fields = payload.get("suspected_fields")
        if not isinstance(suspected_fields, list):
            suspected_fields = []

        matched_observation = None
        if observation_id not in (None, ""):
            for item in recent_observations_compact:
                if int(item.get("id", 0) or 0) == int(observation_id):
                    matched_observation = item
                    break
        if matched_observation is None and endpoint:
            for item in recent_observations_compact:
                if str(item.get("endpoint", "")).strip() == endpoint:
                    matched_observation = item
                    break

        if matched_observation:
            endpoint = endpoint or str(matched_observation.get("endpoint", "")).strip()
            observation_id = matched_observation.get("id")
            if not suspected_fields:
                suspected_fields = list(matched_observation.get("suspected_fields") or [])

        suspected_fields, _, _ = filter_expected_bopla_fields(endpoint, suspected_fields)

        if not endpoint or observation_id in (None, ""):
            return None
        if not suspected_fields:
            return None

        return {
            "candidate_key": f"bopla_probe::{int(observation_id)}",
            "agent_name": agent_name,
            "hypothesis_type": "bopla_probe",
            "target_endpoint": endpoint,
            "http_method": str(candidate.get("http_method", "GET")).strip() or "GET",
            "description": _candidate_description(
                f"Check excessive data exposure on {endpoint}: {', '.join(suspected_fields[:5])}"
            ),
            "payload": {
                "observation_id": int(observation_id),
                "suspected_fields": suspected_fields,
            },
            "confidence": _safe_float(candidate.get("confidence"), 0.95),
            "estimated_cost": _safe_float(candidate.get("estimated_cost"), 0.3),
            "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.10),
            "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.86),
            "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.97),
        }

    finding_id = payload.get("finding_id")
    endpoint = str(candidate.get("target_endpoint", payload.get("endpoint", ""))).strip()
    expected_fields = payload.get("expected_fields")
    if not isinstance(expected_fields, list):
        expected_fields = []

    if finding_id in (None, "") and endpoint:
        for finding in candidate_findings_compact:
            if str(finding.get("endpoint", "")).strip() == endpoint:
                finding_id = finding.get("id")
                if not expected_fields:
                    expected_fields = list(finding.get("exposed_fields") or [])
                break

    if finding_id in (None, ""):
        finding_id = _extract_int_from_text(str(candidate.get("candidate_key", "")))

    if finding_id in (None, "") or not endpoint:
        return None

    finding_id_int = int(finding_id)
    return {
        "candidate_key": f"verify_bopla::{finding_id_int}",
        "agent_name": agent_name,
        "hypothesis_type": "verify_bopla",
        "target_endpoint": endpoint,
        "http_method": str(candidate.get("http_method", "GET")).strip() or "GET",
        "description": _candidate_description(f"Verify BOPLA candidate finding #{finding_id_int}"),
        "payload": {
            "finding_id": finding_id_int,
            "observation_id": payload.get("observation_id"),
            "expected_fields": expected_fields,
            "endpoint": endpoint,
        },
        "confidence": _safe_float(candidate.get("confidence"), 0.99),
        "estimated_cost": _safe_float(candidate.get("estimated_cost"), 0.2),
        "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.03),
        "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.95),
        "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.99),
    }


def _normalize_auth_candidate(
    candidate: dict,
    *,
    recent_observations_compact: list[dict],
    candidate_findings_compact: list[dict],
    target_base_url: str,
) -> dict | None:
    if not isinstance(candidate, dict):
        return None

    hypothesis_type = str(candidate.get("hypothesis_type", "")).strip()
    if hypothesis_type not in {
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
        "verify_auth_boundary",
    }:
        return None

    payload = candidate.get("payload")
    if not isinstance(payload, dict):
        payload = {}

    endpoint = str(candidate.get("target_endpoint", payload.get("endpoint", ""))).strip()
    if endpoint and endpoint.startswith("/"):
        endpoint = f"{target_base_url.rstrip('/')}{endpoint}"

    matched_observation = None
    source_observation_id = payload.get("source_observation_id")
    if source_observation_id not in (None, ""):
        for item in recent_observations_compact:
            if int(item.get("id", 0) or 0) == int(source_observation_id):
                matched_observation = item
                break
    if matched_observation is None and endpoint:
        for item in recent_observations_compact:
            if str(item.get("endpoint", "")).strip() == endpoint:
                matched_observation = item
                break

    if matched_observation and not endpoint:
        endpoint = str(matched_observation.get("endpoint", "")).strip()

    if not endpoint:
        return None

    http_method = str(candidate.get("http_method", payload.get("method", "GET"))).strip() or "GET"
    if matched_observation:
        http_method = str(matched_observation.get("method", http_method)).strip() or http_method

    def _candidate_description(default: str) -> str:
        value = str(candidate.get("description", "")).strip()
        return value or default

    agent_name = str(candidate.get("agent_name", "dify_auth_agent")).strip() or "dify_auth_agent"
    source_role = str(payload.get("source_role", "")).strip()
    if matched_observation and not source_role:
        source_role = str(matched_observation.get("role_name", "")).strip()

    if hypothesis_type == "verify_auth_boundary":
        candidate_finding_ids = {
            _safe_int(finding.get("id"))
            for finding in candidate_findings_compact
            if _safe_int(finding.get("id")) is not None
        }

        finding_id = _safe_int(payload.get("finding_id"))
        if finding_id not in candidate_finding_ids:
            finding_id = None

        if finding_id is None and endpoint:
            for finding in candidate_findings_compact:
                if str(finding.get("endpoint", "")).strip() == endpoint:
                    finding_id = _safe_int(finding.get("id"))
                    if payload.get("expected_status_code") in (None, ""):
                        payload["expected_status_code"] = finding.get("expected_status_code")
                    if finding_id is not None:
                        break

        if finding_id is None:
            extracted_finding_id = _extract_int_from_text(str(candidate.get("candidate_key", "")))
            if extracted_finding_id in candidate_finding_ids:
                finding_id = extracted_finding_id

        if finding_id is None:
            return None

        expected_status_code = payload.get("expected_status_code")
        try:
            expected_status_code = int(expected_status_code)
        except (TypeError, ValueError):
            expected_status_code = None

        return {
            "candidate_key": f"verify_auth_boundary::{int(finding_id)}",
            "agent_name": agent_name,
            "hypothesis_type": "verify_auth_boundary",
            "target_endpoint": endpoint,
            "http_method": http_method,
            "description": _candidate_description(
                f"Verify auth-boundary signal finding #{int(finding_id)} on {endpoint}"
            ),
            "payload": {
                "finding_id": int(finding_id),
                "endpoint": endpoint,
                "source_role": source_role,
                "expected_status_code": expected_status_code,
            },
            "confidence": _safe_float(candidate.get("confidence"), 0.98),
            "estimated_cost": _safe_float(candidate.get("estimated_cost"), 0.2),
            "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.05),
            "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.75),
            "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.98),
        }

    headers = payload.get("headers")
    if not isinstance(headers, dict):
        headers = {}
    params = payload.get("params")
    if not isinstance(params, dict):
        params = {}
    json_body = payload.get("json_body")
    if not isinstance(json_body, dict):
        json_body = {}

    if hypothesis_type == "auth_boundary_probe":
        headers = {
            **headers,
            "Authorization": str(
                headers.get("Authorization", "Bearer invalid-auth-boundary-token")
            ),
            "Content-Type": str(headers.get("Content-Type", "application/json")),
        }
    elif hypothesis_type == "anonymous_probe":
        headers = {k: v for k, v in headers.items() if str(k).lower() != "authorization"}
        headers.setdefault("Content-Type", "application/json")
    elif hypothesis_type == "tokenless_replay_probe":
        headers = {k: v for k, v in headers.items() if str(k).lower() != "authorization"}
        headers.setdefault("Content-Type", "application/json")

    candidate_key = str(candidate.get("candidate_key", "")).strip()
    if not candidate_key:
        candidate_key = f"{hypothesis_type}::{http_method.upper()}::{endpoint}"

    return {
        "candidate_key": candidate_key,
        "agent_name": agent_name,
        "hypothesis_type": hypothesis_type,
        "target_endpoint": endpoint,
        "http_method": http_method,
        "description": _candidate_description(
            f"Probe authentication boundary for {http_method} {endpoint}"
        ),
        "payload": {
            "headers": headers,
            "params": params,
            "json_body": json_body,
            "source_role": source_role,
            "source_observation_id": source_observation_id,
        },
        "confidence": _safe_float(candidate.get("confidence"), 0.9),
        "estimated_cost": _safe_float(candidate.get("estimated_cost"), 0.4),
        "false_positive_risk": _safe_float(candidate.get("false_positive_risk"), 0.12),
        "coverage_gain": _safe_float(candidate.get("coverage_gain"), 0.85),
        "evidence_readiness": _safe_float(candidate.get("evidence_readiness"), 0.9),
    }


def call_dify_bola_agent(
    *,
    session_id: int,
    roles_compact: list[str],
    recent_observations_compact: list[dict],
    known_object_ids: list[dict],
    candidate_findings_compact: list[dict],
    target_base_url: str,
) -> list[dict]:
    if not BOLA_AGENT_DIFY_API_KEY:
        logger.warning("BOLA Agent Dify call skipped: BOLA_AGENT_DIFY_API_KEY is empty")
        return []

    payload = {
        "inputs": {
            "session_id": str(session_id),
            "roles": json.dumps(roles_compact, ensure_ascii=False),
            "recent_observations": json.dumps(recent_observations_compact, ensure_ascii=False),
            "candidate_findings": json.dumps(candidate_findings_compact, ensure_ascii=False),
            "known_object_ids": json.dumps(known_object_ids, ensure_ascii=False),
            "target_base_url": target_base_url,
        },
        "response_mode": "blocking",
        "user": f"bola-agent-session-{session_id}",
    }

    headers = {
        "Authorization": f"Bearer {BOLA_AGENT_DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        BOLA_AGENT_DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"BOLA Agent Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"BOLA Agent workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    candidates = _extract_candidate_list(outputs, agent_label="BOLA Agent")

    logger.warning(
        "BOLA Agent Dify raw outputs for session %s: candidates_count=%s outputs=%s",
        session_id,
        len(candidates),
        outputs,
    )

    normalized = []
    for candidate in candidates:
        normalized_candidate = _normalize_bola_candidate(
            candidate,
            target_base_url=target_base_url,
            roles_compact=roles_compact,
            known_object_ids=known_object_ids,
            candidate_findings_compact=candidate_findings_compact,
        )
        if normalized_candidate:
            normalized.append(normalized_candidate)
        else:
            logger.warning(
                "BOLA Agent candidate normalization dropped candidate for session %s: %s",
                session_id,
                candidate,
            )

    logger.warning(
        "BOLA Agent normalized candidates for session %s: normalized_count=%s",
        session_id,
        len(normalized),
    )

    return normalized


def call_dify_bopla_agent(
    *,
    session_id: int,
    recent_observations_compact: list[dict],
    candidate_findings_compact: list[dict],
    target_base_url: str,
) -> list[dict]:
    if not BOPLA_AGENT_DIFY_API_KEY:
        logger.warning("BOPLA Agent Dify call skipped: BOPLA_AGENT_DIFY_API_KEY is empty")
        return []

    payload = {
        "inputs": {
            "session_id": str(session_id),
            "recent_observations": json.dumps(recent_observations_compact, ensure_ascii=False),
            "candidate_findings": json.dumps(candidate_findings_compact, ensure_ascii=False),
            "target_base_url": target_base_url,
        },
        "response_mode": "blocking",
        "user": f"bopla-agent-session-{session_id}",
    }

    headers = {
        "Authorization": f"Bearer {BOPLA_AGENT_DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        BOPLA_AGENT_DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"BOPLA Agent Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"BOPLA Agent workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    candidates = _extract_candidate_list(outputs, agent_label="BOPLA Agent")

    normalized = []
    for candidate in candidates:
        normalized_candidate = _normalize_bopla_candidate(
            candidate,
            candidate_findings_compact=candidate_findings_compact,
            recent_observations_compact=recent_observations_compact,
        )
        if normalized_candidate:
            normalized.append(normalized_candidate)
        else:
            logger.warning(
                "BOPLA Agent candidate normalization dropped candidate for session %s: %s",
                session_id,
                candidate,
            )

    return normalized


def call_dify_auth_agent(
    *,
    session_id: int,
    roles_compact: list[dict],
    recent_observations_compact: list[dict],
    candidate_findings_compact: list[dict],
    target_base_url: str,
) -> list[dict]:
    if not AUTH_AGENT_DIFY_API_KEY:
        logger.warning("Auth Agent Dify call skipped: AUTH_AGENT_DIFY_API_KEY is empty")
        return []

    payload = {
        "inputs": {
            "session_id": str(session_id),
            "roles": json.dumps(roles_compact, ensure_ascii=False),
            "recent_observations": json.dumps(recent_observations_compact, ensure_ascii=False),
            "candidate_findings": json.dumps(candidate_findings_compact, ensure_ascii=False),
            "target_base_url": target_base_url,
        },
        "response_mode": "blocking",
        "user": f"auth-agent-session-{session_id}",
    }

    headers = {
        "Authorization": f"Bearer {AUTH_AGENT_DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        AUTH_AGENT_DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"Auth Agent Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"Auth Agent workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    candidates = _extract_candidate_list(outputs, agent_label="Auth Agent")

    normalized = []
    for candidate in candidates:
        normalized_candidate = _normalize_auth_candidate(
            candidate,
            recent_observations_compact=recent_observations_compact,
            candidate_findings_compact=candidate_findings_compact,
            target_base_url=target_base_url,
        )
        if normalized_candidate:
            normalized.append(normalized_candidate)
        else:
            logger.warning(
                "Auth Agent candidate normalization dropped candidate for session %s: %s",
                session_id,
                candidate,
            )

    return normalized


def call_dify_judge(hypotheses: list, context: dict) -> dict:
    if not DIFY_API_KEY:
        raise Exception("DIFY_API_KEY is not configured")

    valid_candidate_keys = [
        str(item.get("candidate_key", "")).strip()
        for item in hypotheses
        if item.get("candidate_key")
    ]

    session_id = context.get("session_id", "unknown")
    round_no = context.get("round_no", "unknown")
    request_user = f"judge-agent-session-{session_id}-round-{round_no}"

    payload = {
        "inputs": {
            "judge_instructions": JUDGE_INSTRUCTIONS,
            "hypotheses": json.dumps(hypotheses, ensure_ascii=False),
            "hypotheses_compact": json.dumps(_compact_hypotheses(hypotheses), ensure_ascii=False),
            "context": json.dumps(context, ensure_ascii=False),
            "valid_candidate_keys": json.dumps(valid_candidate_keys, ensure_ascii=False),
        },
        "response_mode": "blocking",
        "user": request_user,
    }

    headers = {
        "Authorization": f"Bearer {DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"Dify workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    parsed = _parse_outputs(outputs)

    # Финальная нормализация типов
    selected_key = str(parsed.get("selected_key", "")).strip()
    reason = str(parsed.get("reason", "Dify workflow selection")).strip()

    try:
        score = float(parsed.get("score", 0.5))
    except (TypeError, ValueError):
        score = 0.5
    score = max(0.0, min(score, 1.0))

    return {
        "selected_key": selected_key,
        "score": score,
        "reason": reason,
    }


def call_dify_report_agent(
    *,
    session_id: int,
    target_name: str,
    target_url: str,
    executive_summary: dict,
    risk_summary: dict,
    key_conclusion: dict,
    top_findings: list[dict],
) -> dict:
    if not REPORT_AGENT_DIFY_API_KEY:
        raise Exception("REPORT_AGENT_DIFY_API_KEY is not configured")

    payload = {
        "inputs": {
            "session_id": str(session_id),
            "target_name": target_name,
            "target_url": target_url,
            "executive_summary": json.dumps(executive_summary, ensure_ascii=False),
            "risk_summary": json.dumps(risk_summary, ensure_ascii=False),
            "key_conclusion": json.dumps(key_conclusion, ensure_ascii=False),
            "top_findings": json.dumps(top_findings, ensure_ascii=False),
        },
        "response_mode": "blocking",
        "user": f"report-agent-session-{session_id}",
    }

    headers = {
        "Authorization": f"Bearer {REPORT_AGENT_DIFY_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        REPORT_AGENT_DIFY_API_URL,
        json=payload,
        headers=headers,
        timeout=60,
    )

    if response.status_code != 200:
        raise Exception(f"Report Agent Dify error: {response.status_code} {response.text}")

    raw = response.json()
    data = raw.get("data")
    if not isinstance(data, dict):
        raise Exception(f"Report Agent workflow response missing data object: {raw}")

    outputs = data.get("outputs", {})
    report_text = _extract_report_text(outputs, agent_label="Report Agent")

    return {
        "report_text": report_text,
        "provider": "dify",
    }
