from __future__ import annotations

import json
from urllib.parse import urlparse

from ..services.bopla_service import build_bopla_hypothesis_from_observation
from ..services.discovery_service import build_crapi_seed_urls
from ..services.extraction_service import extract_vehicle_ids_from_text


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
        endpoint = getattr(item, "path", None)
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


def generate_probe_agent_hypotheses(api_items, observations, authenticated_roles):
    hypotheses = []
    for role in authenticated_roles[:2]:
        high_value_items = [item for item in api_items if is_high_value_api_endpoint(item.path)]
        candidate_items = high_value_items[:6] if high_value_items else api_items[:5]

        for item in candidate_items:
            method = item.method or "GET"
            endpoint = item.path or ""
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
        hypotheses.append({
            "candidate_key": f"compare_roles::{obs_a.method}::{obs_a.endpoint}",
            "agent_name": "rule_based_analysis_agent",
            "hypothesis_type": "compare_roles",
            "target_endpoint": obs_a.endpoint,
            "http_method": obs_a.method,
            "description": f"Compare cross-role responses for {obs_a.method} {obs_a.endpoint}",
            "payload": {
                "observation_a_id": obs_a.id,
                "observation_b_id": obs_b.id,
                "role_a": obs_a.role_name,
                "role_b": obs_b.role_name,
            },
            "confidence": 0.92 if is_high_value_api_endpoint(obs_a.endpoint) else 0.80,
            "estimated_cost": 0.5,
            "false_positive_risk": 0.08 if is_high_value_api_endpoint(obs_a.endpoint) else 0.22,
            "coverage_gain": 0.88 if is_high_value_api_endpoint(obs_a.endpoint) else 0.55,
            "evidence_readiness": 0.94 if is_high_value_api_endpoint(obs_a.endpoint) else 0.68,
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


def generate_bola_agent_hypotheses(observations, findings, authenticated_roles):
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
