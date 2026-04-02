import json
from typing import Optional, Tuple

import requests


COMMON_OPENAPI_PATHS = [
    "/openapi.json",
    "/swagger.json",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
]


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

            content_type = None
            if isinstance(request_body, dict):
                content = request_body.get("content", {})
                if content:
                    content_type = ",".join(content.keys())

            results.append({
                "path": path,
                "method": method.upper(),
                "parameters": parameters,
                "content_type": content_type,
                "auth_hint": auth_hint,
                "raw": operation
            })

    return results
