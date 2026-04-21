from __future__ import annotations

from typing import Any

try:
    from backend.models.api_surface import AuthSignals, CandidateScores, NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import AuthSignals, CandidateScores, NormalizedApiSurface, NormalizedEndpoint, ResourceSignals


class OpenAPINormalizer:
    def normalize(self, request, surface) -> NormalizedApiSurface:
        endpoints = [self._normalize_endpoint(item) for item in list(getattr(surface, "endpoints", []) or [])]
        return NormalizedApiSurface(endpoints=endpoints)

    def _normalize_endpoint(self, item: Any) -> NormalizedEndpoint:
        raw = item if isinstance(item, dict) else {}
        path = str(raw.get("path") or "")
        method = str(raw.get("method") or "GET").upper()
        path_params = [str(v) for v in list(raw.get("path_params") or [])]
        query_params = [str(v) for v in list(raw.get("query_params") or [])]
        body_fields = [str(v) for v in list(raw.get("body_fields") or [])]
        object_param_name = self._object_param_name(path_params, query_params, body_fields)
        auth_required = bool(raw.get("auth_required")) or bool(raw.get("security_schemes"))
        return NormalizedEndpoint(
            path=path,
            method=method,
            operation_id=str(raw.get("operation_id") or ""),
            summary=str(raw.get("summary") or ""),
            path_params=path_params,
            query_params=query_params,
            body_fields=body_fields,
            auth_required=auth_required,
            security_schemes=[str(v) for v in list(raw.get("security_schemes") or [])],
            tags=[str(v) for v in list(raw.get("tags") or [])],
            object_param_name=object_param_name,
            object_id_candidates=[],
            resource_signals=ResourceSignals(
                has_object_id=bool(object_param_name),
                has_role_fields=any(self._is_role_hint(name) for name in body_fields + query_params),
                has_sensitive_keywords=any(self._is_sensitive_hint(name) for name in body_fields + query_params),
            ),
            auth_signals=AuthSignals(
                has_auth_header=auth_required,
                has_cookie_auth=False,
                header_names=["authorization"] if auth_required else [],
                cookie_names=[],
            ),
            sources=["openapi"],
            source_confidence=0.92,
            candidate_scores=CandidateScores(
                authorization=0.75 if auth_required or object_param_name else 0.35,
                injection=0.66 if (query_params or body_fields) else 0.22,
                business_logic=0.7 if self._has_workflow_hint(path) else 0.3,
            ),
            candidate_classes=self._candidate_classes(auth_required, object_param_name, query_params, body_fields, path),
        )

    def _object_param_name(self, *groups: list[str]) -> str:
        for group in groups:
            for name in group:
                normalized = str(name or "").strip()
                if normalized and self._is_object_id_hint(normalized):
                    return normalized
        return ""

    def _is_object_id_hint(self, name: str) -> bool:
        lowered = name.lower()
        return lowered in {"id", "video_id", "order_id", "userid", "user_id", "vehicleid", "vehicle_id", "postid", "post_id", "report_id"} or lowered.endswith("id")

    def _is_role_hint(self, name: str) -> bool:
        lowered = name.lower()
        return any(token in lowered for token in ("role", "admin", "permission", "scope"))

    def _is_sensitive_hint(self, name: str) -> bool:
        lowered = name.lower()
        return any(token in lowered for token in ("password", "token", "secret", "email", "phone"))

    def _has_workflow_hint(self, path: str) -> bool:
        lowered = path.lower()
        return any(token in lowered for token in ("order", "checkout", "return", "coupon", "workflow", "transition", "status"))

    def _candidate_classes(self, auth_required: bool, object_param_name: str, query_params: list[str], body_fields: list[str], path: str) -> list[str]:
        classes: list[str] = []
        if auth_required or object_param_name:
            classes.append("authorization")
        if query_params or body_fields:
            classes.append("injection")
        if self._has_workflow_hint(path) or str(path).upper().startswith("/V"):
            classes.append("business_logic")
        return classes or ["business_logic"]
