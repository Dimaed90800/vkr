import json
from typing import Any, Optional, Tuple

import requests


COMMON_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
]

SENSITIVE_RESPONSE_FIELD_MARKERS = (
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


def fetch_openapi_document(openapi_url: str) -> dict:
    resp = requests.get(openapi_url, timeout=30)
    resp.raise_for_status()
    return resp.json()


def find_openapi_document(base_url: str) -> Tuple[Optional[str], Optional[dict]]:
    base = base_url.rstrip("/")

    for path in COMMON_OPENAPI_PATHS:
        candidate = f"{base}{path}"
        try:
            resp = requests.get(candidate, timeout=10)
            if resp.status_code != 200:
                continue

            content_type = (resp.headers.get("Content-Type") or "").lower()
            text = resp.text.strip()

            if "json" in content_type or text.startswith("{"):
                parsed = resp.json()
            else:
                try:
                    parsed = json.loads(text)
                except Exception:
                    continue

            if isinstance(parsed, dict) and parsed.get("paths"):
                return candidate, parsed
        except Exception:
            continue

    return None, None


def _resolve_schema_ref(spec: dict, ref: str) -> dict:
    if not ref.startswith("#/"):
        return {}

    current: Any = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(current, dict):
            return {}
        current = current.get(part)

    return current if isinstance(current, dict) else {}


def _merge_schema_variants(spec: dict, schema: dict) -> dict:
    if not isinstance(schema, dict):
        return {}

    if "$ref" in schema:
        resolved = _resolve_schema_ref(spec, str(schema.get("$ref")))
        return _merge_schema_variants(spec, resolved)

    for key in ("allOf", "oneOf", "anyOf"):
        variants = schema.get(key)
        if not isinstance(variants, list):
            continue
        merged: dict = {}
        for variant in variants:
            nested = _merge_schema_variants(spec, variant)
            if nested:
                merged.setdefault("properties", {}).update(nested.get("properties", {}))
        if merged:
            if "type" not in merged:
                merged["type"] = schema.get("type", "object")
            return merged

    return schema


def _collect_schema_field_paths(spec: dict, schema: dict, prefix: str = "") -> list[str]:
    schema = _merge_schema_variants(spec, schema)
    if not schema:
        return []

    results = []
    schema_type = schema.get("type")

    if schema_type == "array":
        items = schema.get("items", {})
        return _collect_schema_field_paths(spec, items, prefix=prefix)

    properties = schema.get("properties", {})
    if isinstance(properties, dict):
        for key, nested in properties.items():
            current = f"{prefix}.{key}" if prefix else str(key)
            results.append(current)
            results.extend(_collect_schema_field_paths(spec, nested, prefix=current))

    return results


def _extract_response_schema_fields(spec: dict, operation: dict) -> list[str]:
    responses = operation.get("responses", {})
    preferred_codes = ("200", "201", "202", "203", "2XX", "default")

    for status_code in preferred_codes:
        response = responses.get(status_code)
        if not isinstance(response, dict):
            continue
        content = response.get("content", {})
        if not isinstance(content, dict):
            continue

        for media_type, media_value in content.items():
            if "json" not in str(media_type).lower():
                continue
            if not isinstance(media_value, dict):
                continue
            schema = media_value.get("schema", {})
            field_paths = _collect_schema_field_paths(spec, schema)
            if field_paths:
                return field_paths

    return []


def _extract_path_parameter_names(path: str, parameters: list[dict]) -> list[str]:
    names = []
    for chunk in str(path or "").split("/"):
        if chunk.startswith("{") and chunk.endswith("}"):
            names.append(chunk.strip("{}"))

    for item in parameters or []:
        if not isinstance(item, dict):
            continue
        if str(item.get("in") or "").lower() != "path":
            continue
        name = str(item.get("name") or "").strip()
        if name and name not in names:
            names.append(name)

    return names


def _filter_sensitive_response_fields(field_paths: list[str]) -> list[str]:
    filtered = []
    for path in field_paths or []:
        lowered = str(path).lower()
        if any(marker.lower() in lowered for marker in SENSITIVE_RESPONSE_FIELD_MARKERS):
            filtered.append(path)
    return filtered


def parse_openapi_spec(spec: dict) -> list[dict]:
    results = []

    paths = spec.get("paths", {})
    components = spec.get("components", {})
    security_schemes = components.get("securitySchemes", {})

    auth_hint = None
    if security_schemes:
        auth_hint = ",".join(security_schemes.keys())

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue

        for method, operation in methods.items():
            if method.lower() not in {"get", "post", "put", "delete", "patch", "options", "head"}:
                continue

            parameters = operation.get("parameters", [])
            request_body = operation.get("requestBody", {})
            response_field_paths = _extract_response_schema_fields(spec, operation)
            sensitive_response_fields = _filter_sensitive_response_fields(response_field_paths)
            path_parameters = _extract_path_parameter_names(path, parameters)

            content_type = None
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                if content:
                    content_type = ",".join(content.keys())

            results.append({
                "path": path,
                "method": method.upper(),
                "parameters": parameters,
                "path_parameters": path_parameters,
                "has_path_params": bool(path_parameters),
                "content_type": content_type,
                "auth_hint": auth_hint,
                "response_field_paths": response_field_paths,
                "sensitive_response_fields": sensitive_response_fields,
                "raw": operation
            })

    return results
