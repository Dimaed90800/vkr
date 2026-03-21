import json

from ..models import SurfaceInventory, Observation, RoleCredential
from ..services.extraction_service import extract_vehicle_ids_from_text


def _safe_load_json(value):
    if not value:
        return None
    try:
        return json.loads(value)
    except Exception:
        return None


def _find_cross_role_pairs(observations):
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


def _find_recent_posts_observations(observations):
    return [
        obs for obs in observations
        if obs.endpoint and "/community/api/v2/community/posts/recent" in obs.endpoint and obs.status_code == 200
    ]

def _extract_top_level_json_keys_from_observation(observation):
    if not observation.body_preview:
        return []

    try:
        data = json.loads(observation.body_preview)
    except Exception:
        return []

    if isinstance(data, dict):
        return list(data.keys())

    return []


def generate_bopla_hypothesis(observation):
    keys = _extract_top_level_json_keys_from_observation(observation)
    if not keys:
        return None

    sensitive_keys = ["role", "admin", "balance", "email", "userid", "userId", "credit"]

    found = [
        k for k in keys
        if any(s.lower() in k.lower() for s in sensitive_keys)
    ]

    if not found:
        return None

    return {
        "candidate_key": f"bopla_probe::{observation.method}::{observation.endpoint}",
        "agent_name": "rule_based_bopla_agent",
        "hypothesis_type": "bopla_probe",
        "target_endpoint": observation.endpoint,
        "http_method": observation.method,
        "description": f"Check excessive data exposure on {observation.endpoint}: {found}",
        "payload": {
            "observation_id": observation.id,
            "suspected_fields": found
        },
        "confidence": 0.88,
        "estimated_cost": 0.5,
        "false_positive_risk": 0.18,
        "coverage_gain": 0.72,
        "evidence_readiness": 0.91
    }
def generate_hypotheses_for_session(db, session_id: int) -> list[dict]:
    hypotheses = []

    inventory_items = db.query(SurfaceInventory).filter(
        SurfaceInventory.session_id == session_id
    ).all()

    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).all()

    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).all()

    api_items = [x for x in inventory_items if x.asset_type == "api"]
    authenticated_roles = [r for r in roles if r.access_token]
    cross_role_pairs = _find_cross_role_pairs(observations)

    signup_success = [
        x for x in observations
        if x.endpoint and "/identity/api/auth/signup" in x.endpoint and x.status_code == 200
    ]
    login_success = [
        x for x in observations
        if x.endpoint and "/identity/api/auth/login" in x.endpoint and x.status_code == 200
    ]

    if not api_items:
        hypotheses.append({
            "candidate_key": "discovery_followup",
            "agent_name": "rule_based_discovery_agent",
            "hypothesis_type": "discovery",
            "target_endpoint": None,
            "http_method": None,
            "description": "API endpoints not discovered yet; continue discovery via OpenAPI or AJAX spider",
            "payload": {
                "action": "discovery_followup",
                "recommended_tools": ["parse_openapi", "ajax_spider", "manual_api_probe"]
            },
            "confidence": 0.92,
            "estimated_cost": 1.0,
            "false_positive_risk": 0.10,
            "coverage_gain": 0.90,
            "evidence_readiness": 0.95
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
                "evidence_readiness": 0.95
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
                "evidence_readiness": 0.96
            })

    for role in authenticated_roles[:2]:
        for item in api_items[:5]:
            method = item.method or "GET"
            endpoint = item.path or ""
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
                    "headers": {"Content-Type": "application/json"}
                },
                "confidence": 0.84,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.12,
                "coverage_gain": 0.78,
                "evidence_readiness": 0.88
            })

    for obs_a, obs_b in cross_role_pairs[:5]:
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
                "role_b": obs_b.role_name
            },
            "confidence": 0.90,
            "estimated_cost": 0.5,
            "false_positive_risk": 0.15,
            "coverage_gain": 0.82,
            "evidence_readiness": 0.94
        })

    for obs in observations[-20:]:
        bopla = generate_bopla_hypothesis(obs)
        if bopla:
            hypotheses.append(bopla)

    if len(authenticated_roles) >= 2:
        role_a = authenticated_roles[0].role_name
        role_b = authenticated_roles[1].role_name

        for obs in _find_recent_posts_observations(observations):
            vehicle_ids = extract_vehicle_ids_from_text(obs.body_preview or "")
            for vehicle_id in vehicle_ids[:3]:
                endpoint = f"http://host.docker.internal:8888/identity/api/v2/vehicle/{vehicle_id}/location"
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
                        "object_id": vehicle_id
                    },
                    "confidence": 0.96,
                    "estimated_cost": 1.0,
                    "false_positive_risk": 0.08,
                    "coverage_gain": 0.95,
                    "evidence_readiness": 0.97
                })

    if signup_success and not login_success:
        latest_signup = signup_success[-1]
        request_body = _safe_load_json(latest_signup.request_body) or {}

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
                "json_body": {
                    "email": email,
                    "password": password
                }
            },
            "confidence": 0.95,
            "estimated_cost": 1.0,
            "false_positive_risk": 0.05,
            "coverage_gain": 0.85,
            "evidence_readiness": 0.90
        })

    if not hypotheses:
        hypotheses.append({
            "candidate_key": "fallback_discovery",
            "agent_name": "rule_based_fallback_agent",
            "hypothesis_type": "discovery",
            "target_endpoint": None,
            "http_method": None,
            "description": "No useful inventory or observations; continue discovery",
            "payload": {
                "action": "discovery_followup",
                "recommended_tools": ["spider_again", "openapi", "manual_seed"]
            },
            "confidence": 0.80,
            "estimated_cost": 1.0,
            "false_positive_risk": 0.20,
            "coverage_gain": 0.75,
            "evidence_readiness": 0.85
        })

    return hypotheses

# def generate_bopla_hypothesis(observation):
#     if not observation.response_json:
#         return None
#
#     sensitive_keys = ["role", "admin", "balance", "email", "userId"]
#
#     found = [
#         k for k in observation.response_json.keys()
#         if any(s in k.lower() for s in sensitive_keys)
#     ]
#
#     if not found:
#         return None
#
#     return {
#         "type": "bopla_probe",
#         "target_endpoint": observation.endpoint,
#         "http_method": observation.method,
#         "description": f"Check excessive data exposure: {found}"
#     }