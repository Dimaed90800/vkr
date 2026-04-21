from __future__ import annotations

import json
from typing import Any

import requests
import yaml

try:
    from backend.models.recon import OpenAPIReconRequest, OpenAPIReconResponse
except ModuleNotFoundError:  # pragma: no cover
    from models.recon import OpenAPIReconRequest, OpenAPIReconResponse


class OpenAPIService:
    def parse(self, request: OpenAPIReconRequest) -> OpenAPIReconResponse:
        spec = self._load_spec(request)
        endpoints = self._extract_endpoints(spec)
        info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
        return OpenAPIReconResponse(
            target_url=request.target_url,
            openapi_url=str(request.openapi_url or ""),
            title=str(info.get("title") or ""),
            version=str(info.get("version") or ""),
            endpoints=endpoints,
            raw_metadata={
                "spec_type": "openapi",
                "openapi_version": str(spec.get("openapi") or spec.get("swagger") or ""),
                "endpoint_count": len(endpoints),
            },
        )

    def _load_spec(self, request: OpenAPIReconRequest) -> dict[str, Any]:
        raw = str(request.openapi_spec_text or "").strip()
        if not raw:
            url = str(request.openapi_url or "").strip()
            if not url:
                raise ValueError("Either openapi_url or openapi_spec_text must be provided.")
            response = requests.get(url, timeout=20)
            response.raise_for_status()
            raw = response.text
        parsed: Any
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            parsed = yaml.safe_load(raw)
        if not isinstance(parsed, dict):
            raise ValueError("OpenAPI document must deserialize to an object.")
        if not isinstance(parsed.get("paths"), dict):
            raise ValueError("OpenAPI document does not contain a valid paths object.")
        return parsed

    def _extract_endpoints(self, spec: dict[str, Any]) -> list[dict[str, Any]]:
        endpoints: list[dict[str, Any]] = []
        methods = {"get", "post", "put", "patch", "delete", "options", "head"}
        for path, path_item in (spec.get("paths") or {}).items():
            if not isinstance(path_item, dict):
                continue
            path_level_parameters = path_item.get("parameters") if isinstance(path_item.get("parameters"), list) else []
            for method, operation in path_item.items():
                if method.lower() not in methods or not isinstance(operation, dict):
                    continue
                parameters = list(path_level_parameters) + list(operation.get("parameters") or [])
                path_params = self._parameter_names(parameters, "path")
                query_params = self._parameter_names(parameters, "query")
                body_fields = self._body_fields(operation.get("requestBody"))
                security = operation.get("security")
                endpoints.append(
                    {
                        "path": str(path),
                        "method": method.upper(),
                        "operation_id": str(operation.get("operationId") or ""),
                        "summary": str(operation.get("summary") or operation.get("description") or ""),
                        "path_params": path_params,
                        "query_params": query_params,
                        "body_fields": body_fields,
                        "tags": [str(item) for item in list(operation.get("tags") or []) if str(item or "").strip()],
                        "security_schemes": self._security_schemes(security),
                        "auth_required": bool(security),
                    }
                )
        return endpoints

    def _parameter_names(self, parameters: list[Any], location: str) -> list[str]:
        names: list[str] = []
        for item in parameters:
            if not isinstance(item, dict):
                continue
            if str(item.get("in") or "").lower() != location:
                continue
            name = str(item.get("name") or "").strip()
            if name and name not in names:
                names.append(name)
        return names

    def _body_fields(self, request_body: Any) -> list[str]:
        if not isinstance(request_body, dict):
            return []
        content = request_body.get("content")
        if not isinstance(content, dict):
            return []
        for media in content.values():
            if not isinstance(media, dict):
                continue
            schema = media.get("schema")
            fields = self._schema_fields(schema)
            if fields:
                return fields
        return []

    def _schema_fields(self, schema: Any) -> list[str]:
        if not isinstance(schema, dict):
            return []
        properties = schema.get("properties")
        if isinstance(properties, dict):
            return [str(key) for key in properties.keys()]
        items = schema.get("items")
        if isinstance(items, dict):
            return self._schema_fields(items)
        return []

    def _security_schemes(self, security: Any) -> list[str]:
        schemes: list[str] = []
        if not isinstance(security, list):
            return schemes
        for item in security:
            if not isinstance(item, dict):
                continue
            for key in item.keys():
                name = str(key or "").strip()
                if name and name not in schemes:
                    schemes.append(name)
        return schemes
