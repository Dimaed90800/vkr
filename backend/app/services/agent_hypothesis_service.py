from __future__ import annotations

import json
from urllib.parse import urlparse

from ..services.bopla_service import (
    build_bopla_hypothesis_from_observation,
    extract_sensitive_field_paths,
)
from ..services.discovery_service import build_crapi_seed_urls
from ..services.extraction_service import UUID_RE, extract_vehicle_ids_from_text


def safe_load_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def is_auth_endpoint(endpoint: str | None) -> bool:
    value = (endpoint or "").lower()
    return "/identity/api/auth/" in value


def is_high_value_api_endpoint(endpoint: str | None) -> bool:
    value = (endpoint or "").lower()
    if is_auth_endpoint(value):
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


def to_absolute_endpoint(endpoint: str | None, target_url: str | None = None) -> str | None:
    if not endpoint:
        return endpoint
    endpoint = str(endpoint).strip()
    parsed = urlparse(endpoint)
    if parsed.scheme and parsed.netloc:
        return endpoint
    if target_url:
        return f"{str(target_url).rstrip('/')}/{endpoint.lstrip('/')}"
    return endpoint


def find_cross_role_pairs(observations):
    grouped = {}

    for obs in observations:
        if not obs.role_name:
            continue
        key = (obs.endpoint, obs.method)
        grouped.setdefault(key, []).append(obs)

    pairs = []
    for (_, _), items in grouped.items():
        by_role = {}
        for item in items:
            by_role.setdefault(item.role_name, item)

        if len(by_role) >= 2:
            role_names = list(by_role.keys())[:2]
            pairs.append((by_role[role_names[0]], by_role[role_names[1]]))

    return pairs


def find_recent_posts_observations(observations):
    return [
        obs for obs in observations
        if obs.endpoint and "/community/api/v2/community/posts/recent" in obs.endpoint and obs.status_code == 200
    ]


def _is_object_style_endpoint(endpoint: str | None) -> bool:
    value = str(endpoint or "").lower()
    return bool(UUID_RE.search(value)) or any(
        marker in value
        for marker in [
            "/vehicle/",
            "/order/",
            "/video/",
            "/merchant/",
            "/mechanic/",
            "/report/",
            "/location",
        ]
    )


def _is_collection_or_profile_endpoint(endpoint: str | None) -> bool:
    value = str(endpoint or "").lower()
    return any(
        marker in value
        for marker in [
            "/community/api/",
            "/posts/recent",
            "/identity/api/v2/user/dashboard",
            "/identity/api/v2/user/",
        ]
    ) and not _is_object_style_endpoint(endpoint)


def _try_parse_json_body(value: str | None):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _extract_object_id_from_endpoint(endpoint: str | None) -> str | None:
    value = str(endpoint or "").strip().rstrip("/")
    if not value:
        return None
    parts = [item for item in value.split("/") if item]
    if len(parts) < 2:
        return None
    for index in range(len(parts) - 1, -1, -1):
        part = parts[index]
        if UUID_RE.fullmatch(part):
            return part
    tail = parts[-1]
    if tail in {"location", "report", "details"} and len(parts) >= 2:
        return parts[-2]
    return None


def _has_sensitive_field_asymmetry(obs_a, obs_b) -> bool:
    fields_a = set(extract_sensitive_field_paths(getattr(obs_a, "body_preview", "") or ""))
    fields_b = set(extract_sensitive_field_paths(getattr(obs_b, "body_preview", "") or ""))
    return bool(fields_a.symmetric_difference(fields_b))


def _build_invariant_bola_hypotheses(observations, findings, authenticated_roles):
    hypotheses = []
    if len(authenticated_roles) < 2:
        return hypotheses

    seen = set()
    role_names = [role.role_name for role in authenticated_roles if getattr(role, "role_name", None)]
    recent_observations = observations[-25:] if len(observations) > 25 else observations

    for obs in recent_observations:
        endpoint = getattr(obs, "endpoint", None)
        method = (getattr(obs, "method", None) or "GET").upper()
        owner_role = getattr(obs, "role_name", None)
        if (
            not endpoint
            or not owner_role
            or method != "GET"
            or getattr(obs, "status_code", None) != 200
            or is_auth_endpoint(endpoint)
            or not _is_object_style_endpoint(endpoint)
        ):
            continue

        object_id = _extract_object_id_from_endpoint(endpoint)
        if not object_id:
            parsed = _try_parse_json_body(getattr(obs, "body_preview", None))
            if isinstance(parsed, dict):
                for key in ("id", "vehicleId", "orderId", "videoId", "video_id"):
                    if parsed.get(key):
                        object_id = str(parsed.get(key))
                        break

        for other_role in role_names:
            if other_role == owner_role:
                continue
            if candidate_finding_exists(findings, "possible_bola", endpoint):
                continue
            if recent_observation_exists(observations, endpoint, method, other_role, limit=16):
                continue
            key = (endpoint, owner_role, other_role)
            if key in seen:
                continue
            seen.add(key)
            hypotheses.append(
                {
                    "candidate_key": f"bola_probe::invariant::{endpoint}::{owner_role}::{other_role}",
                    "agent_name": "rule_based_bola_agent",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": endpoint,
                    "http_method": method,
                    "description": (
                        f"Check object-isolation invariant on {endpoint}: "
                        f"{other_role} should not access object observed by {owner_role}"
                    ),
                    "payload": {
                        "owner_role": owner_role,
                        "other_role": other_role,
                        "object_type": "observed_object_endpoint",
                        "object_id": object_id,
                        "source": "invariant_object_isolation",
                        "source_observation_id": getattr(obs, "id", None),
                        "invariant_name": "cross_role_object_isolation",
                    },
                    "confidence": 0.94,
                    "estimated_cost": 1.0,
                    "false_positive_risk": 0.07,
                    "coverage_gain": 0.93,
                    "evidence_readiness": 0.96,
                }
            )
    return hypotheses


def recent_observation_exists(observations, endpoint: str, method: str, role_name: str | None, limit: int = 5) -> bool:
    recent = observations[-limit:] if len(observations) > limit else observations
    for obs in recent:
        if (
            (obs.endpoint or "") == (endpoint or "")
            and (obs.method or "").upper() == (method or "").upper()
            and (obs.role_name or None) == (role_name or None)
        ):
            return True
    return False


def recent_auth_probe_mode_exists(
    observations,
    endpoint: str,
    method: str,
    *,
    invalid_token: bool,
    limit: int = 8,
) -> bool:
    recent = observations[-limit:] if len(observations) > limit else observations
    for obs in recent:
        if (
            (obs.endpoint or "") != (endpoint or "")
            or (obs.method or "").upper() != (method or "").upper()
            or (obs.role_name or None) is not None
        ):
            continue

        headers = safe_load_json(getattr(obs, "request_headers", None)) or {}
        authorization = str(headers.get("Authorization", "") or "")
        has_invalid_token = "invalid-auth-boundary-token" in authorization

        if invalid_token and has_invalid_token:
            return True
        if not invalid_token and not authorization:
            return True

    return False


def count_recent_auth_probe_modes(observations, endpoint: str, method: str, limit: int = 8) -> dict:
    recent = observations[-limit:] if len(observations) > limit else observations
    counts = {
        "plain": 0,
        "invalid_token": 0,
    }
    for obs in recent:
        if (
            (obs.endpoint or "") != (endpoint or "")
            or (obs.method or "").upper() != (method or "").upper()
            or (obs.role_name or None) is not None
        ):
            continue

        headers = safe_load_json(getattr(obs, "request_headers", None)) or {}
        authorization = str(headers.get("Authorization", "") or "")
        if "invalid-auth-boundary-token" in authorization:
            counts["invalid_token"] += 1
        elif not authorization:
            counts["plain"] += 1

    return counts


def candidate_finding_exists(findings, finding_type: str, endpoint: str | None) -> bool:
    for finding in findings:
        if (
            finding.finding_type == finding_type
            and (finding.endpoint or "") == (endpoint or "")
            and getattr(finding, "verification_status", "candidate") == "candidate"
        ):
            return True
    return False


def active_finding_exists(findings, finding_type: str, endpoint: str | None) -> bool:
    for finding in findings:
        if (
            finding.finding_type == finding_type
            and (finding.endpoint or "") == (endpoint or "")
            and getattr(finding, "verification_status", "candidate") in {"candidate", "confirmed"}
        ):
            return True
    return False


def unique_hypotheses(items: list[dict]) -> list[dict]:
    unique = []
    seen = set()
    for item in items:
        key = item.get("candidate_key") or (
            item.get("hypothesis_type"),
            item.get("target_endpoint"),
            item.get("http_method"),
            json.dumps(item.get("payload", {}), sort_keys=True, ensure_ascii=False),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique


def _derive_base_url(observations, target_url: str | None = None) -> str | None:
    if target_url:
        return str(target_url).rstrip("/")
    for obs in observations:
        endpoint = getattr(obs, "endpoint", None)
        if not endpoint:
            continue
        parsed = urlparse(endpoint)
        if parsed.scheme and parsed.netloc:
            return f"{parsed.scheme}://{parsed.netloc}"
    return None


def _collect_auth_boundary_targets(observations, api_items=None, target_url: str | None = None) -> list[dict]:
    candidates = []
    seen = set()

    for obs in observations:
        endpoint = getattr(obs, "endpoint", None)
        method = (getattr(obs, "method", None) or "GET").upper()
        if (
            not endpoint
            or getattr(obs, "status_code", None) != 200
            or not getattr(obs, "role_name", None)
            or is_auth_endpoint(endpoint)
            or not is_high_value_api_endpoint(endpoint)
        ):
            continue
        key = (endpoint, method)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "endpoint": endpoint,
                "method": method,
                "request_params": safe_load_json(getattr(obs, "request_params", None)) or {},
                "request_body": safe_load_json(getattr(obs, "request_body", None)) or {},
                "source_role": getattr(obs, "role_name", None),
                "source_observation_id": getattr(obs, "id", None),
            }
        )

    for item in api_items or []:
        endpoint = to_absolute_endpoint(getattr(item, "path", None), target_url=target_url)
        method = (getattr(item, "method", None) or "GET").upper()
        if (
            not endpoint
            or method != "GET"
            or not is_high_value_api_endpoint(endpoint)
        ):
            continue
        key = (endpoint, method)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "endpoint": endpoint,
                "method": method,
                "request_params": {},
                "request_body": {},
                "source_role": None,
                "source_observation_id": None,
            }
        )

    base_url = _derive_base_url(observations, target_url=target_url)
    if base_url:
        fallback_targets = build_crapi_seed_urls(base_url) + [
            f"{base_url}/identity/api/v2/user/dashboard",
        ]
        for endpoint in fallback_targets:
            method = "GET"
            if not is_high_value_api_endpoint(endpoint):
                continue
            key = (endpoint, method)
            if key in seen:
                continue
            seen.add(key)
            candidates.append(
                {
                    "endpoint": endpoint,
                    "method": method,
                    "request_params": {},
                    "request_body": {},
                    "source_role": None,
                    "source_observation_id": None,
                }
            )

    return candidates


def _auth_target_priority(endpoint: str | None) -> int:
    value = (endpoint or "").lower()
    if "/identity/api/v2/user/dashboard" in value:
        return 5
    if "/community/api/v2/community/posts/recent" in value:
        return 4
    if "/identity/api/v2/vehicle/" in value:
        return 3
    if "/workshop/api/" in value:
        return 2
    if "/community/api/" in value:
        return 1
    return 0


def _safe_inventory_json(value):
    if isinstance(value, dict):
        return value
    return safe_load_json(value) or {}


def _api_item_sensitive_field_count(item) -> int:
    metadata = _safe_inventory_json(getattr(item, "raw_json", None))
    sensitive_fields = metadata.get("sensitive_response_fields", [])
    if isinstance(sensitive_fields, list):
        return len(sensitive_fields)
    return 0


def _api_item_has_path_params(item) -> bool:
    metadata = _safe_inventory_json(getattr(item, "raw_json", None))
    if metadata.get("has_path_params"):
        return True
    path_parameters = metadata.get("path_parameters", [])
    return bool(path_parameters)


def _collect_known_object_ids(observations) -> list[str]:
    found = []
    seen = set()

    for obs in observations:
        body_preview = str(getattr(obs, "body_preview", "") or "")
        endpoint = str(getattr(obs, "endpoint", "") or "")
        vehicle_ids = extract_vehicle_ids_from_text(body_preview)
        regex_hits = UUID_RE.findall(body_preview + "\n" + endpoint)

        for object_id in [*vehicle_ids, *regex_hits]:
            if object_id in seen:
                continue
            seen.add(object_id)
            found.append(object_id)

    return found


def _inventory_bola_candidates(api_items, known_object_ids, target_url: str | None = None) -> list[str]:
    candidates = []
    seen = set()

    for item in api_items or []:
        path = getattr(item, "path", None)
        method = (getattr(item, "method", None) or "GET").upper()
        if method != "GET" or not path:
            continue
        if not _api_item_has_path_params(item):
            continue

        path_lower = str(path).lower()
        if not any(marker in path_lower for marker in ("/vehicle/", "/report", "/location", "/details")):
            continue

        path_parameters = _safe_inventory_json(getattr(item, "raw_json", None)).get("path_parameters", [])
        if not path_parameters:
            continue

        template = str(path)
        for object_id in known_object_ids[:12]:
            candidate_path = template
            replaced = False
            for param_name in path_parameters:
                placeholder = "{" + str(param_name) + "}"
                if placeholder in candidate_path:
                    candidate_path = candidate_path.replace(placeholder, object_id)
                    replaced = True
            if not replaced:
                continue
            endpoint = to_absolute_endpoint(candidate_path, target_url=target_url)
            if endpoint and endpoint not in seen:
                seen.add(endpoint)
                candidates.append(endpoint)

    return candidates


def _rank_auth_boundary_targets(targets, observations) -> list[dict]:
    def sort_key(target: dict):
        endpoint = target["endpoint"]
        method = target["method"]
        mode_counts = count_recent_auth_probe_modes(observations, endpoint, method, limit=12)
        total_recent = mode_counts["plain"] + mode_counts["invalid_token"]
        has_source_observation = 1 if target.get("source_observation_id") is not None else 0
        return (
            total_recent,
            -has_source_observation,
            -_auth_target_priority(endpoint),
            endpoint or "",
        )

    return sorted(targets, key=sort_key)


def generate_auth_agent_hypotheses(roles, observations, findings=None, api_items=None, target_url: str | None = None):
    hypotheses = []
    findings = findings or []

    if not roles:
        hypotheses.append({
            "candidate_key": "bootstrap_roles::default_pair",
            "agent_name": "rule_based_auth_agent",
            "hypothesis_type": "bootstrap_roles",
            "target_endpoint": None,
            "http_method": None,
            "description": "Create default roles user_a and user_b for authenticated testing",
            "payload": {"role_names": ["user_a", "user_b"]},
            "confidence": 0.99,
            "estimated_cost": 0.2,
            "false_positive_risk": 0.01,
            "coverage_gain": 0.95,
            "evidence_readiness": 0.98,
        })

    for role in roles:
        if role.status == "created":
            hypotheses.append({
                "candidate_key": f"register_role::{role.role_name}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "register_role",
                "target_endpoint": None,
                "http_method": None,
                "description": f"Register role {role.role_name} to obtain valid credentials",
                "payload": {"role_name": role.role_name},
                "confidence": 0.97,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.03,
                "coverage_gain": 0.80,
                "evidence_readiness": 0.95,
            })

    for role in roles:
        if role.status == "registered" and not role.access_token:
            hypotheses.append({
                "candidate_key": f"login_role::{role.role_name}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "login_role",
                "target_endpoint": None,
                "http_method": None,
                "description": f"Login role {role.role_name} to obtain bearer token",
                "payload": {"role_name": role.role_name},
                "confidence": 0.98,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.03,
                "coverage_gain": 0.88,
                "evidence_readiness": 0.96,
            })

    signup_success = [
        x for x in observations
        if x.endpoint and "/identity/api/auth/signup" in x.endpoint and x.status_code == 200
    ]
    login_success = [
        x for x in observations
        if x.endpoint and "/identity/api/auth/login" in x.endpoint and x.status_code == 200
    ]

    if signup_success and not login_success:
        latest_signup = signup_success[-1]
        request_body = safe_load_json(latest_signup.request_body) or {}
        email = request_body.get("email", "test-user@example.com")
        password = request_body.get("password", "Test1234!")

        hypotheses.append({
            "candidate_key": f"login_from_signup::{email}",
            "agent_name": "rule_based_auth_agent",
            "hypothesis_type": "login",
            "target_endpoint": latest_signup.endpoint.replace("/signup", "/login"),
            "http_method": "POST",
            "description": "Successful signup observed; attempt login to obtain token for further testing",
            "payload": {
                "headers": {"Content-Type": "application/json"},
                "json_body": {"email": email, "password": password},
            },
            "confidence": 0.95,
            "estimated_cost": 1.0,
            "false_positive_risk": 0.05,
            "coverage_gain": 0.85,
            "evidence_readiness": 0.90,
        })

    auth_boundary_targets = _rank_auth_boundary_targets(
        _collect_auth_boundary_targets(
            observations,
            api_items=api_items,
            target_url=target_url,
        ),
        observations,
    )

    ranked_targets = auth_boundary_targets[:8]
    recent_mode_map = {
        (target["endpoint"], target["method"]): count_recent_auth_probe_modes(
            observations,
            target["endpoint"],
            target["method"],
            limit=12,
        )
        for target in ranked_targets
    }

    for target in ranked_targets:
        endpoint = target["endpoint"]
        method = target["method"]
        request_params = target["request_params"]
        request_body = target["request_body"]
        source_observation_id = target["source_observation_id"]
        has_source_observation = source_observation_id is not None
        endpoint_priority = _auth_target_priority(endpoint)
        mode_counts = recent_mode_map[(endpoint, method)]
        total_recent = mode_counts["plain"] + mode_counts["invalid_token"]
        plain_probe_recent = mode_counts["plain"] > 0
        invalid_probe_recent = mode_counts["invalid_token"] > 0

        if not plain_probe_recent:
            confidence = 0.88 + min(endpoint_priority * 0.01, 0.04)
            if not has_source_observation:
                confidence -= 0.03
            hypotheses.append({
                "candidate_key": f"anonymous_probe::{method}::{endpoint}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "anonymous_probe",
                "target_endpoint": endpoint,
                "http_method": method,
                "description": f"Probe high-value endpoint {method} {endpoint} without authentication to test access boundary",
                "payload": {
                    "headers": {"Content-Type": "application/json"},
                    "params": request_params,
                    "json_body": request_body,
                    "source_role": target["source_role"],
                },
                "confidence": max(confidence, 0.78),
                "estimated_cost": 1.0,
                "false_positive_risk": 0.10,
                "coverage_gain": 0.82 + min(endpoint_priority * 0.01, 0.04),
                "evidence_readiness": 0.86 if not has_source_observation else 0.90,
            })

        if not plain_probe_recent:
            confidence = 0.90 + min(endpoint_priority * 0.01, 0.03)
            if not has_source_observation:
                confidence -= 0.07
            hypotheses.append({
                "candidate_key": f"tokenless_replay_probe::{source_observation_id or endpoint}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "tokenless_replay_probe",
                "target_endpoint": endpoint,
                "http_method": method,
                "description": f"Replay previously successful authenticated request {method} {endpoint} without bearer token",
                "payload": {
                    "headers": {"Content-Type": "application/json"},
                    "params": request_params,
                    "json_body": request_body,
                    "source_observation_id": target["source_observation_id"],
                    "source_role": target["source_role"],
                },
                "confidence": max(confidence, 0.74),
                "estimated_cost": 1.0,
                "false_positive_risk": 0.08,
                "coverage_gain": 0.84 + min(endpoint_priority * 0.01, 0.03),
                "evidence_readiness": 0.80 if not has_source_observation else 0.92,
            })

        if not invalid_probe_recent:
            confidence = 0.89 + min(endpoint_priority * 0.01, 0.03)
            if not has_source_observation:
                confidence -= 0.04
            hypotheses.append({
                "candidate_key": f"auth_boundary_probe::{source_observation_id or endpoint}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "auth_boundary_probe",
                "target_endpoint": endpoint,
                "http_method": method,
                "description": f"Replay high-value endpoint {method} {endpoint} with an invalid bearer token to test auth boundary handling",
                "payload": {
                    "headers": {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer invalid-auth-boundary-token",
                    },
                    "params": request_params,
                    "json_body": request_body,
                    "source_observation_id": target["source_observation_id"],
                    "source_role": target["source_role"],
                },
                "confidence": max(confidence, 0.76),
                "estimated_cost": 1.0,
                "false_positive_risk": 0.09,
                "coverage_gain": 0.83 + min(endpoint_priority * 0.01, 0.03),
                "evidence_readiness": 0.84 if not has_source_observation else 0.91,
            })

        if plain_probe_recent and invalid_probe_recent:
            other_fresh_targets_exist = any(
                other_key != (endpoint, method)
                and (other_counts["plain"] + other_counts["invalid_token"]) == 0
                for other_key, other_counts in recent_mode_map.items()
            )
            if other_fresh_targets_exist:
                continue
            repeat_penalty = min(total_recent * 0.05, 0.20)
            hypotheses.append({
                "candidate_key": f"auth_boundary_probe::repeat::{endpoint}::{mode_counts['invalid_token']}",
                "agent_name": "rule_based_auth_agent",
                "hypothesis_type": "auth_boundary_probe",
                "target_endpoint": endpoint,
                "http_method": method,
                "description": (
                    f"Re-check high-value endpoint {method} {endpoint} with an invalid bearer token "
                    "after initial auth-boundary probes already ran"
                ),
                "payload": {
                    "headers": {
                        "Content-Type": "application/json",
                        "Authorization": "Bearer invalid-auth-boundary-token",
                    },
                    "params": request_params,
                    "json_body": request_body,
                    "source_observation_id": target["source_observation_id"],
                    "source_role": target["source_role"],
                    "repeat_allowed": True,
                },
                "confidence": max(0.40, 0.55 - repeat_penalty),
                "estimated_cost": 0.8,
                "false_positive_risk": min(0.30, 0.20 + repeat_penalty),
                "coverage_gain": max(0.12, 0.22 - repeat_penalty),
                "evidence_readiness": max(0.18, 0.30 - repeat_penalty),
            })

    for finding in findings:
        if getattr(finding, "verification_status", "candidate") != "candidate":
            continue
        if finding.finding_type != "auth_boundary_signal":
            continue

        evidence = safe_load_json(getattr(finding, "evidence_json", None)) or {}
        endpoint = finding.endpoint or evidence.get("endpoint")
        status_code = evidence.get("status_code")
        action_executed = evidence.get("action_executed", "auth_boundary_probe")
        if not endpoint or status_code not in {404, 405}:
            continue

        hypotheses.append({
            "candidate_key": f"verify_auth_boundary::{finding.id}",
            "agent_name": "rule_based_auth_agent",
            "hypothesis_type": "verify_auth_boundary",
            "target_endpoint": endpoint,
            "http_method": "GET",
            "description": f"Re-check auth boundary signal finding #{finding.id} on {endpoint}",
            "payload": {
                "finding_id": finding.id,
                "endpoint": endpoint,
                "expected_status_code": status_code,
                "verification_action": action_executed,
                "source_observation_id": evidence.get("source_observation_id"),
            },
            "confidence": 0.94,
            "estimated_cost": 0.6,
            "false_positive_risk": 0.08,
            "coverage_gain": 0.55,
            "evidence_readiness": 0.96,
        })

    return unique_hypotheses(hypotheses)


def generate_discovery_agent_hypotheses(api_items):
    if api_items:
        return []
    return [{
        "candidate_key": "discovery_followup",
        "agent_name": "rule_based_discovery_agent",
        "hypothesis_type": "discovery",
        "target_endpoint": None,
        "http_method": None,
        "description": "API endpoints not discovered yet; continue discovery via OpenAPI or AJAX spider",
        "payload": {
            "action": "discovery_followup",
            "recommended_tools": ["parse_openapi", "ajax_spider", "manual_api_probe"],
        },
        "confidence": 0.92,
        "estimated_cost": 1.0,
        "false_positive_risk": 0.10,
        "coverage_gain": 0.90,
        "evidence_readiness": 0.95,
    }]


def generate_probe_agent_hypotheses(api_items, observations, authenticated_roles, target_url: str | None = None):
    hypotheses = []
    for role in authenticated_roles[:2]:
        normalized_items = []
        for item in api_items:
            endpoint = to_absolute_endpoint(getattr(item, "path", None), target_url=target_url)
            if not endpoint:
                continue
            normalized_items.append((item, endpoint))

        normalized_items.sort(
            key=lambda pair: (
                -1 if is_high_value_api_endpoint(pair[1]) else 0,
                -_api_item_sensitive_field_count(pair[0]),
                -1 if _api_item_has_path_params(pair[0]) else 0,
                pair[1],
            )
        )
        high_value_items = [pair for pair in normalized_items if is_high_value_api_endpoint(pair[1])]
        candidate_items = high_value_items[:6] if high_value_items else api_items[:5]

        for item_data in candidate_items:
            if isinstance(item_data, tuple):
                item, endpoint = item_data
            else:
                item = item_data
                endpoint = to_absolute_endpoint(getattr(item, "path", None), target_url=target_url) or ""

            method = item.method or "GET"
            if recent_observation_exists(observations, endpoint, method, role.role_name, limit=8):
                continue

            confidence = 0.84
            coverage_gain = 0.78
            evidence_readiness = 0.88
            if is_high_value_api_endpoint(endpoint):
                confidence = 0.90
                coverage_gain = 0.90
                evidence_readiness = 0.93

            hypotheses.append({
                "candidate_key": f"authenticated_probe::{role.role_name}::{method}::{endpoint}",
                "agent_name": "rule_based_probe_agent",
                "hypothesis_type": "authenticated_probe",
                "target_endpoint": endpoint,
                "http_method": method,
                "description": f"Probe API endpoint {method} {endpoint} as role {role.role_name}",
                "payload": {
                    "role_name": role.role_name,
                    "use_role_token": True,
                    "headers": {"Content-Type": "application/json"},
                },
                "confidence": confidence,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.12,
                "coverage_gain": coverage_gain,
                "evidence_readiness": evidence_readiness,
            })
    return hypotheses


def generate_analysis_agent_hypotheses(observations):
    hypotheses = []
    for obs_a, obs_b in find_cross_role_pairs(observations)[:5]:
        if is_auth_endpoint(obs_a.endpoint):
            continue
        same_success = getattr(obs_a, "status_code", None) == 200 and getattr(obs_b, "status_code", None) == 200
        parsed_a = _try_parse_json_body(getattr(obs_a, "body_preview", None))
        parsed_b = _try_parse_json_body(getattr(obs_b, "body_preview", None))
        response_differs = parsed_a is not None and parsed_b is not None and parsed_a != parsed_b
        sensitive_asymmetry = _has_sensitive_field_asymmetry(obs_a, obs_b)
        invariant_triggered = (
            same_success
            and _is_collection_or_profile_endpoint(obs_a.endpoint)
            and (response_differs or sensitive_asymmetry)
        )
        confidence = 0.92 if is_high_value_api_endpoint(obs_a.endpoint) else 0.80
        coverage_gain = 0.88 if is_high_value_api_endpoint(obs_a.endpoint) else 0.55
        evidence_readiness = 0.94 if is_high_value_api_endpoint(obs_a.endpoint) else 0.68
        false_positive_risk = 0.08 if is_high_value_api_endpoint(obs_a.endpoint) else 0.22
        payload = {
            "observation_a_id": obs_a.id,
            "observation_b_id": obs_b.id,
            "role_a": obs_a.role_name,
            "role_b": obs_b.role_name,
        }
        if invariant_triggered:
            confidence = min(0.99, confidence + 0.05)
            coverage_gain = min(0.99, coverage_gain + 0.06)
            evidence_readiness = min(0.99, evidence_readiness + 0.04)
            false_positive_risk = max(0.04, false_positive_risk - 0.03)
            payload["invariant_name"] = "cross_role_response_parity"
            payload["sensitive_field_asymmetry"] = sensitive_asymmetry
            payload["response_differs"] = response_differs
        hypotheses.append({
            "candidate_key": f"compare_roles::{obs_a.method}::{obs_a.endpoint}",
            "agent_name": "rule_based_analysis_agent",
            "hypothesis_type": "compare_roles",
            "target_endpoint": obs_a.endpoint,
            "http_method": obs_a.method,
            "description": f"Compare cross-role responses for {obs_a.method} {obs_a.endpoint}",
            "payload": payload,
            "confidence": confidence,
            "estimated_cost": 0.5,
            "false_positive_risk": false_positive_risk,
            "coverage_gain": coverage_gain,
            "evidence_readiness": evidence_readiness,
        })
    return hypotheses


def generate_bopla_agent_hypotheses(observations, findings):
    hypotheses = []
    for obs in observations[-20:]:
        if is_auth_endpoint(obs.endpoint):
            continue
        if active_finding_exists(findings, "possible_bopla", obs.endpoint):
            continue
        bopla = build_bopla_hypothesis_from_observation(obs)
        if bopla:
            hypotheses.append(bopla)
    return hypotheses


def generate_bola_agent_hypotheses(observations, findings, authenticated_roles, api_items=None, target_url: str | None = None):
    hypotheses = []
    if len(authenticated_roles) < 2:
        return hypotheses

    role_a = authenticated_roles[0].role_name
    role_b = authenticated_roles[1].role_name

    for obs in find_recent_posts_observations(observations):
        vehicle_ids = extract_vehicle_ids_from_text(obs.body_preview or "")
        for vehicle_id in vehicle_ids[:3]:
            endpoint = f"http://host.docker.internal:8888/identity/api/v2/vehicle/{vehicle_id}/location"
            if candidate_finding_exists(findings, "possible_bola", endpoint):
                continue
            if recent_observation_exists(observations, endpoint, "GET", role_a, limit=12):
                continue
            hypotheses.append({
                "candidate_key": f"bola_probe::vehicle::{vehicle_id}::{role_a}::{role_b}",
                "agent_name": "rule_based_bola_agent",
                "hypothesis_type": "bola_probe",
                "target_endpoint": endpoint,
                "http_method": "GET",
                "description": f"Probe shared vehicle object {vehicle_id} across roles {role_a} and {role_b}",
                "payload": {
                    "owner_role": role_a,
                    "other_role": role_b,
                    "object_type": "vehicle",
                    "object_id": vehicle_id,
                },
                "confidence": 0.96,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.08,
                "coverage_gain": 0.95,
                "evidence_readiness": 0.97,
            })

    known_object_ids = _collect_known_object_ids(observations)
    for endpoint in _inventory_bola_candidates(api_items, known_object_ids, target_url=target_url):
        if candidate_finding_exists(findings, "possible_bola", endpoint):
            continue
        if recent_observation_exists(observations, endpoint, "GET", role_a, limit=12):
            continue
        hypotheses.append({
            "candidate_key": f"bola_probe::inventory::{endpoint}::{role_a}::{role_b}",
            "agent_name": "rule_based_bola_agent",
            "hypothesis_type": "bola_probe",
            "target_endpoint": endpoint,
            "http_method": "GET",
            "description": f"Probe object endpoint discovered from OpenAPI/inventory across roles {role_a} and {role_b}",
            "payload": {
                "owner_role": role_a,
                "other_role": role_b,
                "object_type": "inventory_object",
                "object_id": endpoint.rstrip('/').split('/')[-2] if '/' in endpoint else endpoint,
                "source": "inventory_openapi",
            },
            "confidence": 0.91,
            "estimated_cost": 1.0,
            "false_positive_risk": 0.10,
            "coverage_gain": 0.90,
            "evidence_readiness": 0.92,
        })
    hypotheses.extend(
        _build_invariant_bola_hypotheses(
            observations,
            findings,
            authenticated_roles,
        )
    )
    return hypotheses


def generate_verifier_agent_hypotheses(findings):
    hypotheses = []
    for finding in findings:
        if finding.verification_status != "candidate":
            continue

        if finding.finding_type == "possible_bola":
            evidence = safe_load_json(finding.evidence_json) or {}
            endpoint = finding.endpoint
            owner_role = evidence.get("owner_role")
            other_role = evidence.get("other_role")

            if endpoint and owner_role and other_role:
                hypotheses.append({
                    "candidate_key": f"verify_bola::{finding.id}",
                    "agent_name": "rule_based_verifier_agent",
                    "hypothesis_type": "verify_bola",
                    "target_endpoint": endpoint,
                    "http_method": "GET",
                    "description": f"Verify BOLA candidate finding #{finding.id}",
                    "payload": {
                        "finding_id": finding.id,
                        "owner_role": owner_role,
                        "other_role": other_role,
                        "endpoint": endpoint,
                    },
                    "confidence": 0.99,
                    "estimated_cost": 0.2,
                    "false_positive_risk": 0.03,
                    "coverage_gain": 0.95,
                    "evidence_readiness": 0.99,
                })

        if finding.finding_type == "possible_bopla":
            evidence = safe_load_json(finding.evidence_json) or {}
            endpoint = finding.endpoint
            observation_id = evidence.get("observation_id")
            exposed_fields = evidence.get("exposed_fields", [])

            if endpoint and observation_id:
                hypotheses.append({
                    "candidate_key": f"verify_bopla::{finding.id}",
                    "agent_name": "rule_based_verifier_agent",
                    "hypothesis_type": "verify_bopla",
                    "target_endpoint": endpoint,
                    "http_method": "GET",
                    "description": f"Verify BOPLA candidate finding #{finding.id}",
                    "payload": {
                        "finding_id": finding.id,
                        "observation_id": observation_id,
                        "expected_fields": exposed_fields,
                        "endpoint": endpoint,
                    },
                    "confidence": 0.99,
                    "estimated_cost": 0.2,
                    "false_positive_risk": 0.03,
                    "coverage_gain": 0.95,
                    "evidence_readiness": 0.99,
                })
    return hypotheses


def generate_fallback_agent_hypotheses():
    return [{
        "candidate_key": "fallback_discovery",
        "agent_name": "rule_based_fallback_agent",
        "hypothesis_type": "discovery",
        "target_endpoint": None,
        "http_method": None,
        "description": "No useful inventory or observations; continue discovery",
        "payload": {
            "action": "discovery_followup",
            "recommended_tools": ["spider_again", "openapi", "manual_seed"],
        },
        "confidence": 0.80,
        "estimated_cost": 1.0,
        "false_positive_risk": 0.20,
        "coverage_gain": 0.75,
        "evidence_readiness": 0.85,
    }]
