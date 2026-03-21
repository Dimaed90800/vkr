import requests


def fetch_openapi_document(openapi_url: str) -> dict:
    resp = requests.get(openapi_url, timeout=30)
    resp.raise_for_status()
    return resp.json()


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