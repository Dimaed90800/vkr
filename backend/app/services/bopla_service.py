import json


SENSITIVE_FIELD_MARKERS = (
    "role",
    "admin",
    "balance",
    "email",
    "credit",
    "token",
    "secret",
    "phone",
    "password",
    "ssn",
    "userid",
    "user_id",
    "userId",
)

AUTH_ENDPOINT_MARKERS = (
    "/auth/login",
    "/auth/signup",
    "/auth/refresh",
    "/auth/token",
)

EXPECTED_EXPOSURE_BY_ENDPOINT_MARKERS = {
    "/identity/api/v2/user/dashboard": {
        "email",
        "available_credit",
        "role",
    },
    "/identity/api/v2/vehicle/": {
        "email",
        "fullname",
    },
}

SAFE_AUTH_FIELDS = {
    "token",
    "access_token",
    "refresh_token",
    "type",
    "token_type",
    "message",
    "mfarequired",
    "mfaRequired",
}


def filter_expected_bopla_fields(endpoint: str, fields: list[str]) -> tuple[list[str], list[str], list[str]]:
    filtered_fields = list(fields or [])

    filtered_out_as_auth_expected = []
    if _is_auth_endpoint(endpoint):
        retained = []
        for field in filtered_fields:
            leaf = _field_leaf(field)
            if leaf in SAFE_AUTH_FIELDS:
                filtered_out_as_auth_expected.append(field)
            else:
                retained.append(field)
        filtered_fields = retained

    filtered_out_as_endpoint_expected = []
    expected_fields = _expected_fields_for_endpoint(endpoint or "")
    if expected_fields:
        retained = []
        for field in filtered_fields:
            leaf = _field_leaf(field)
            if leaf in expected_fields:
                filtered_out_as_endpoint_expected.append(field)
            else:
                retained.append(field)
        filtered_fields = retained

    return filtered_fields, filtered_out_as_auth_expected, filtered_out_as_endpoint_expected


def _try_parse_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _collect_field_paths(value, prefix=""):
    paths = []

    if isinstance(value, dict):
        for key, nested in value.items():
            current = f"{prefix}.{key}" if prefix else key
            paths.append(current)
            paths.extend(_collect_field_paths(nested, current))
    elif isinstance(value, list):
        for item in value[:5]:
            paths.extend(_collect_field_paths(item, prefix))

    return paths


def _is_sensitive_field(field_path: str) -> bool:
    field_lower = field_path.lower()
    return any(marker.lower() in field_lower for marker in SENSITIVE_FIELD_MARKERS)


def _is_auth_endpoint(endpoint: str) -> bool:
    if not endpoint:
        return False
    endpoint_lower = endpoint.lower()
    return any(marker in endpoint_lower for marker in AUTH_ENDPOINT_MARKERS)


def _field_leaf(path: str) -> str:
    return path.split(".")[-1] if path else path


def _expected_fields_for_endpoint(endpoint: str) -> set[str]:
    endpoint_lower = (endpoint or "").lower()
    expected = set()
    for marker, fields in EXPECTED_EXPOSURE_BY_ENDPOINT_MARKERS.items():
        if marker in endpoint_lower:
            if marker == "/identity/api/v2/vehicle/" and "/location" not in endpoint_lower:
                continue
            expected.update(str(field) for field in fields)
    return expected


def extract_sensitive_field_paths(body_text: str) -> list[str]:
    parsed = _try_parse_json(body_text)
    if parsed is None:
        return []

    all_paths = _collect_field_paths(parsed)
    sensitive = []
    for path in all_paths:
        if _is_sensitive_field(path) and path not in sensitive:
            sensitive.append(path)
    return sensitive


def build_bopla_hypothesis_from_observation(observation):
    sensitive_paths = extract_sensitive_field_paths(observation.body_preview or "")
    if not sensitive_paths:
        return None

    sensitive_paths, _, _ = filter_expected_bopla_fields(observation.endpoint or "", sensitive_paths)

    if not sensitive_paths:
        return None

    return {
        "candidate_key": f"bopla_probe::{observation.id}",
        "agent_name": "rule_based_bopla_agent",
        "hypothesis_type": "bopla_probe",
        "target_endpoint": observation.endpoint,
        "http_method": observation.method,
        "description": (
            f"Check excessive data exposure on {observation.endpoint}: "
            f"{', '.join(sensitive_paths[:5])}"
        ),
        "payload": {
            "observation_id": observation.id,
            "suspected_fields": sensitive_paths,
        },
        "confidence": 0.95,
        "estimated_cost": 0.3,
        "false_positive_risk": 0.10,
        "coverage_gain": 0.86,
        "evidence_readiness": 0.97
    }


def analyze_bopla_observation(observation, suspected_fields=None) -> dict:
    suspected_fields = suspected_fields or []
    parsed = _try_parse_json(observation.body_preview or "")
    detected_fields = extract_sensitive_field_paths(observation.body_preview or "")

    exposed_fields = []
    for field in detected_fields:
        if field in suspected_fields or _is_sensitive_field(field):
            if field not in exposed_fields:
                exposed_fields.append(field)

    exposed_fields, filtered_out_as_auth_expected, filtered_out_as_endpoint_expected = (
        filter_expected_bopla_fields(observation.endpoint or "", exposed_fields)
    )

    signals = []
    if parsed is not None:
        signals.append("json_response_detected")
    if exposed_fields:
        signals.append("sensitive_fields_exposed")
    if len(exposed_fields) >= 3:
        signals.append("multiple_sensitive_fields_exposed")
    if filtered_out_as_auth_expected:
        signals.append("auth_expected_fields_filtered")
    if filtered_out_as_endpoint_expected:
        signals.append("endpoint_expected_fields_filtered")

    inference = "possible_bopla" if exposed_fields else "no_issue"

    return {
        "observation_id": observation.id,
        "endpoint": observation.endpoint,
        "method": observation.method,
        "status_code": observation.status_code,
        "suspected_fields": suspected_fields,
        "detected_sensitive_fields": detected_fields,
        "exposed_fields": exposed_fields,
        "filtered_out_as_auth_expected": filtered_out_as_auth_expected,
        "filtered_out_as_endpoint_expected": filtered_out_as_endpoint_expected,
        "signals": signals,
        "inference": inference,
    }
