import json
from collections.abc import Mapping
from typing import Any

import yaml

try:
    from backend.models.recon import EndpointSurface, OpenAPIReconRequest, OpenAPIReconResponse
except ModuleNotFoundError:  # pragma: no cover
    from models.recon import EndpointSurface, OpenAPIReconRequest, OpenAPIReconResponse


class OpenAPIService:
    def parse(self, request: OpenAPIReconRequest) -> OpenAPIReconResponse:
        if request.openapi_spec_text:
            parsed = self._parse_spec_text(request.openapi_spec_text)
            endpoints = self._extract_endpoints(parsed)
            auth_schemes = self._extract_auth_schemes(parsed)
            schemas = sorted(list((parsed.get("components") or {}).get("schemas", {}).keys()))
            return OpenAPIReconResponse(
                target_url=request.target_url,
                surface_summary=f"Parsed {len(endpoints)} endpoints from provided OpenAPI spec.",
                endpoints=endpoints,
                auth_schemes=auth_schemes,
                schemas=schemas,
                raw_metadata={"source": "openapi_spec_text"},
            )

        if request.openapi_url:
            return OpenAPIReconResponse(
                target_url=request.target_url,
                surface_summary="OpenAPI URL was provided. Returning mocked parsed surface for MVP.",
                endpoints=[
                    EndpointSurface(
                        path="/identity/api/v2/vehicle/{id}/location",
                        methods=["GET"],
                        auth_required=True,
                        path_params=["id"],
                        query_params=[],
                        body_fields=[],
                        auth_hints=["bearer"],
                    ),
                    EndpointSurface(
                        path="/community/api/v2/community/posts/recent",
                        methods=["GET"],
                        auth_required=True,
                        path_params=[],
                        query_params=[],
                        body_fields=[],
                        auth_hints=["bearer"],
                    ),
                ],
                auth_schemes=["bearerAuth"],
                schemas=["VehicleLocation", "Post"],
                raw_metadata={"source": "openapi_url_stub", "openapi_url": str(request.openapi_url)},
            )

        return OpenAPIReconResponse(
            target_url=request.target_url,
            surface_summary="No OpenAPI input provided. Returning empty surface.",
            endpoints=[],
            auth_schemes=[],
            schemas=[],
            raw_metadata={"source": "empty_openapi_input"},
        )

    def _parse_spec_text(self, text: str) -> dict[str, Any]:
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = yaml.safe_load(text)
        if not isinstance(parsed, Mapping):
            raise ValueError("OpenAPI document must parse to an object")
        return dict(parsed)

    def _extract_endpoints(self, parsed: dict[str, Any]) -> list[EndpointSurface]:
        paths = parsed.get("paths") or {}
        if not isinstance(paths, Mapping):
            raise ValueError("OpenAPI paths must be an object")

        endpoints: list[EndpointSurface] = []
        for path, operations in paths.items():
            if not isinstance(operations, Mapping):
                continue
            methods: list[str] = []
            path_params = self._extract_path_params(path)
            query_params: list[str] = []
            body_fields: list[str] = []
            auth_hints: list[str] = []
            auth_required = False

            for method, operation in operations.items():
                if str(method).lower() not in {"get", "post", "put", "patch", "delete", "head", "options"}:
                    continue
                methods.append(str(method).upper())
                if not isinstance(operation, Mapping):
                    continue
                for parameter in operation.get("parameters") or []:
                    if not isinstance(parameter, Mapping):
                        continue
                    name = str(parameter.get("name") or "")
                    location = str(parameter.get("in") or "")
                    if location == "query" and name and name not in query_params:
                        query_params.append(name)
                request_body = operation.get("requestBody") or {}
                if isinstance(request_body, Mapping):
                    body_fields.extend(self._extract_body_fields(request_body))
                if operation.get("security"):
                    auth_required = True
                    auth_hints.extend(self._extract_auth_names(operation.get("security")))

            endpoints.append(
                EndpointSurface(
                    path=str(path),
                    methods=methods,
                    auth_required=auth_required,
                    path_params=sorted(set(path_params)),
                    query_params=sorted(set(query_params)),
                    body_fields=sorted(set(body_fields)),
                    auth_hints=sorted(set(auth_hints)),
                )
            )
        return endpoints

    def _extract_path_params(self, path: str) -> list[str]:
        params: list[str] = []
        current = ""
        in_param = False
        for ch in path:
            if ch == "{":
                in_param = True
                current = ""
            elif ch == "}":
                if current:
                    params.append(current)
                in_param = False
            elif in_param:
                current += ch
        return params

    def _extract_body_fields(self, request_body: Mapping[str, Any]) -> list[str]:
        content = request_body.get("content") or {}
        if not isinstance(content, Mapping):
            return []
        for media_type in ["application/json", "multipart/form-data", "application/x-www-form-urlencoded"]:
            schema = (content.get(media_type) or {}).get("schema") if isinstance(content.get(media_type), Mapping) else None
            if isinstance(schema, Mapping):
                properties = schema.get("properties") or {}
                if isinstance(properties, Mapping):
                    return [str(name) for name in properties.keys()]
        return []

    def _extract_auth_names(self, security: Any) -> list[str]:
        names: list[str] = []
        if isinstance(security, list):
            for item in security:
                if isinstance(item, Mapping):
                    names.extend(str(name) for name in item.keys())
        return names

    def _extract_auth_schemes(self, parsed: dict[str, Any]) -> list[str]:
        security_schemes = ((parsed.get("components") or {}).get("securitySchemes") or {})
        if not isinstance(security_schemes, Mapping):
            return []
        return sorted(str(name) for name in security_schemes.keys())
