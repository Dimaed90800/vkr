import json
from collections.abc import Mapping
from typing import Any

import yaml

try:
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
    from backend.models.recon import EndpointSurface, OpenAPIReconRequest, OpenAPIReconResponse
    from backend.services.candidate_classifier import (
        CandidateClassifier,
        OBJECT_ID_KEYWORDS,
        ROLE_FIELD_KEYWORDS,
        SENSITIVE_KEYWORDS,
    )
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
    from models.recon import EndpointSurface, OpenAPIReconRequest, OpenAPIReconResponse
    from services.candidate_classifier import (
        CandidateClassifier,
        OBJECT_ID_KEYWORDS,
        ROLE_FIELD_KEYWORDS,
        SENSITIVE_KEYWORDS,
    )


class OpenAPINormalizer:
    def __init__(self) -> None:
        self.classifier = CandidateClassifier()

    def normalize(
        self,
        request: OpenAPIReconRequest,
        parsed_surface: OpenAPIReconResponse,
    ) -> NormalizedApiSurface:
        if request.openapi_spec_text:
            document = self._parse_spec_text(request.openapi_spec_text)
            return self._normalize_from_document(document)
        return self._normalize_from_flat_surface(parsed_surface.endpoints)

    def _normalize_from_document(self, document: dict[str, Any]) -> NormalizedApiSurface:
        paths = document.get("paths") or {}
        global_security = document.get("security") or []
        if not isinstance(paths, Mapping):
            return NormalizedApiSurface(endpoints=[])

        endpoints: list[NormalizedEndpoint] = []
        for path, operations in paths.items():
            if not isinstance(operations, Mapping):
                continue
            for method, operation in operations.items():
                method_upper = str(method or "").upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                    continue
                if not isinstance(operation, Mapping):
                    operation = {}

                path_params = self._extract_path_params(str(path))
                query_params = self._extract_query_params(operation)
                body_fields = self._extract_body_fields(operation.get("requestBody") or {})
                object_param_name = self._detect_object_param_name(path_params, query_params, body_fields)
                object_id_candidates = self._extract_object_id_candidates(
                    operation=operation,
                    path_params=path_params,
                    query_params=query_params,
                    body_fields=body_fields,
                    object_param_name=object_param_name,
                )
                security_schemes = self._extract_security_schemes(operation, global_security)
                endpoint = NormalizedEndpoint(
                    path=str(path),
                    method=method_upper,
                    operation_id=str(operation.get("operationId") or ""),
                    summary=str(operation.get("summary") or operation.get("description") or ""),
                    path_params=path_params,
                    query_params=query_params,
                    body_fields=body_fields,
                    auth_required=bool(security_schemes),
                    security_schemes=security_schemes,
                    tags=[str(tag) for tag in (operation.get("tags") or []) if str(tag).strip()],
                    object_param_name=object_param_name,
                    object_id_candidates=object_id_candidates,
                    resource_signals=self._resource_signals(
                        path=str(path),
                        summary=str(operation.get("summary") or operation.get("description") or ""),
                        tags=[str(tag) for tag in (operation.get("tags") or []) if str(tag).strip()],
                        path_params=path_params,
                        query_params=query_params,
                        body_fields=body_fields,
                    ),
                )
                endpoints.append(self.classifier.classify(endpoint))
        return NormalizedApiSurface(endpoints=endpoints)

    def _normalize_from_flat_surface(self, flat_endpoints: list[EndpointSurface]) -> NormalizedApiSurface:
        endpoints: list[NormalizedEndpoint] = []
        for item in flat_endpoints:
            methods = item.methods or ["GET"]
            for method in methods:
                endpoint = NormalizedEndpoint(
                    path=item.path,
                    method=str(method).upper(),
                    operation_id="",
                    summary="",
                    path_params=list(item.path_params or []),
                    query_params=list(item.query_params or []),
                    body_fields=list(item.body_fields or []),
                    auth_required=bool(item.auth_required),
                    security_schemes=list(item.auth_hints or []),
                    tags=[],
                    object_param_name=self._detect_object_param_name(
                        list(item.path_params or []),
                        list(item.query_params or []),
                        list(item.body_fields or []),
                    ),
                    object_id_candidates=[],
                    resource_signals=self._resource_signals(
                        path=item.path,
                        summary="",
                        tags=[],
                        path_params=list(item.path_params or []),
                        query_params=list(item.query_params or []),
                        body_fields=list(item.body_fields or []),
                    ),
                )
                endpoints.append(self.classifier.classify(endpoint))
        return NormalizedApiSurface(endpoints=endpoints)

    def _resource_signals(
        self,
        *,
        path: str,
        summary: str,
        tags: list[str],
        path_params: list[str],
        query_params: list[str],
        body_fields: list[str],
    ) -> ResourceSignals:
        normalized_fields = [self._normalize_name(item) for item in [*path_params, *query_params, *body_fields]]
        haystack = " ".join([path, summary, *tags, *path_params, *query_params, *body_fields]).lower()

        has_object_id = any(name in OBJECT_ID_KEYWORDS for name in normalized_fields) or "{" in path
        has_role_fields = any(name in ROLE_FIELD_KEYWORDS for name in normalized_fields)
        has_sensitive_keywords = any(keyword in haystack for keyword in SENSITIVE_KEYWORDS)

        return ResourceSignals(
            has_object_id=has_object_id,
            has_role_fields=has_role_fields,
            has_sensitive_keywords=has_sensitive_keywords,
        )

    def _parse_spec_text(self, text: str) -> dict[str, Any]:
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            payload = yaml.safe_load(text)
        if not isinstance(payload, Mapping):
            return {}
        return dict(payload)

    def _extract_path_params(self, path: str) -> list[str]:
        params: list[str] = []
        current = ""
        in_param = False
        for char in path:
            if char == "{":
                current = ""
                in_param = True
            elif char == "}":
                if current:
                    params.append(current)
                in_param = False
            elif in_param:
                current += char
        return sorted(set(params))

    def _extract_query_params(self, operation: Mapping[str, Any]) -> list[str]:
        found: list[str] = []
        for parameter in operation.get("parameters") or []:
            if not isinstance(parameter, Mapping):
                continue
            if str(parameter.get("in") or "") == "query":
                name = str(parameter.get("name") or "")
                if name:
                    found.append(name)
        return sorted(set(found))

    def _extract_body_fields(self, request_body: Mapping[str, Any]) -> list[str]:
        content = request_body.get("content") or {}
        if not isinstance(content, Mapping):
            return []
        for media_type in ["application/json", "multipart/form-data", "application/x-www-form-urlencoded"]:
            media = content.get(media_type) or {}
            if not isinstance(media, Mapping):
                continue
            schema = media.get("schema") or {}
            if not isinstance(schema, Mapping):
                continue
            properties = schema.get("properties") or {}
            if isinstance(properties, Mapping):
                return sorted(str(key) for key in properties.keys())
        return []

    def _extract_security_schemes(
        self,
        operation: Mapping[str, Any],
        global_security: list[Any],
    ) -> list[str]:
        security = operation.get("security")
        if security is None:
            security = global_security
        names: list[str] = []
        if isinstance(security, list):
            for item in security:
                if isinstance(item, Mapping):
                    names.extend(str(name) for name in item.keys())
        return sorted(set(names))

    def _normalize_name(self, value: str) -> str:
        return str(value or "").strip().lower().replace("-", "").replace("_", "")

    def _detect_object_param_name(
        self,
        path_params: list[str],
        query_params: list[str],
        body_fields: list[str],
    ) -> str:
        for name in [*path_params, *query_params, *body_fields]:
            if self._normalize_name(name) in OBJECT_ID_KEYWORDS:
                return str(name)
        return path_params[0] if path_params else ""

    def _extract_object_id_candidates(
        self,
        *,
        operation: Mapping[str, Any],
        path_params: list[str],
        query_params: list[str],
        body_fields: list[str],
        object_param_name: str,
    ) -> list[str]:
        if not object_param_name:
            return []

        candidates: list[str] = []
        valid_names = {self._normalize_name(object_param_name)}
        valid_names.update(self._normalize_name(name) for name in [*path_params, *query_params, *body_fields])

        for parameter in operation.get("parameters") or []:
            if not isinstance(parameter, Mapping):
                continue
            name = str(parameter.get("name") or "")
            if self._normalize_name(name) not in valid_names:
                continue
            candidates.extend(self._collect_examples(parameter))
            schema = parameter.get("schema") or {}
            if isinstance(schema, Mapping):
                candidates.extend(self._collect_examples(schema))

        request_body = operation.get("requestBody") or {}
        content = request_body.get("content") or {}
        if isinstance(content, Mapping):
            for media in content.values():
                if not isinstance(media, Mapping):
                    continue
                schema = media.get("schema") or {}
                if not isinstance(schema, Mapping):
                    continue
                properties = schema.get("properties") or {}
                if not isinstance(properties, Mapping):
                    continue
                for name, property_schema in properties.items():
                    if self._normalize_name(str(name)) not in valid_names:
                        continue
                    if isinstance(property_schema, Mapping):
                        candidates.extend(self._collect_examples(property_schema))

        normalized: list[str] = []
        seen: set[str] = set()
        for item in candidates:
            value = str(item).strip()
            if value and value not in seen:
                seen.add(value)
                normalized.append(value)
        return normalized

    def _collect_examples(self, source: Mapping[str, Any]) -> list[str]:
        found: list[str] = []
        for key in ("example", "default"):
            value = source.get(key)
            if value not in (None, ""):
                found.append(str(value))
        enum_values = source.get("enum")
        if isinstance(enum_values, list):
            found.extend(str(item) for item in enum_values if item not in (None, ""))
        examples = source.get("examples")
        if isinstance(examples, Mapping):
            for example_value in examples.values():
                if isinstance(example_value, Mapping):
                    value = example_value.get("value")
                    if value not in (None, ""):
                        found.append(str(value))
                elif example_value not in (None, ""):
                    found.append(str(example_value))
        return found
