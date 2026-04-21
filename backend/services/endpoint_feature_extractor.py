from __future__ import annotations


class EndpointFeatureExtractor:
    PRIVILEGED_HINTS = ("admin", "internal", "management", "merchant", "mechanic", "moderation")
    SELF_HINTS = ("/me", "/self", "/profile")
    WORKFLOW_HINTS = ("order", "checkout", "return", "coupon", "workflow", "transition", "status", "redeem")
    DOC_HINTS = ("openapi", "swagger", "docs", "inventory")

    def extract(self, endpoint) -> dict[str, bool]:
        path = str(getattr(endpoint, "path", "") or "").lower()
        method = str(getattr(endpoint, "method", "GET") or "GET").upper()
        path_params = [str(v).lower() for v in list(getattr(endpoint, "path_params", []) or [])]
        query_params = [str(v).lower() for v in list(getattr(endpoint, "query_params", []) or [])]
        body_fields = [str(v).lower() for v in list(getattr(endpoint, "body_fields", []) or [])]
        return {
            "has_path_object_id": any(self._looks_like_object_id(item) for item in path_params) or "{" in path and "id" in path,
            "has_query_object_id": any(self._looks_like_object_id(item) for item in query_params),
            "has_body_object_id": any(self._looks_like_object_id(item) for item in body_fields),
            "has_query_params": bool(query_params),
            "has_body_fields": bool(body_fields),
            "has_sensitive_body_fields": any(self._is_sensitive_field(item) for item in body_fields),
            "has_auth_semantics": any(token in path for token in ("login", "signin", "signup", "register", "password", "token", "auth")),
            "has_url_field": any("url" in item or "uri" in item for item in body_fields + query_params),
            "has_workflow_verbs": any(token in path for token in self.WORKFLOW_HINTS),
            "has_search_semantics": any(token in path for token in ("search", "filter", "query", "lookup")) or "q" in query_params,
            "is_collection_like": self._is_collection_like(path, path_params),
            "is_exposure_prone_get": method == "GET" and (bool(getattr(endpoint, "auth_required", False)) or self._is_collection_like(path, path_params)),
            "is_privileged": any(token in path for token in self.PRIVILEGED_HINTS),
            "is_self_scoped": any(token in path for token in self.SELF_HINTS),
            "is_versioned": any(segment.startswith("/v") and segment[2:3].isdigit() for segment in [path[:3], path[:4]]),
            "is_doc_or_inventory_like": any(token in path for token in self.DOC_HINTS),
        }

    def _looks_like_object_id(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return lowered in {"id", "video_id", "vehicleid", "vehicle_id", "order_id", "postid", "post_id", "report_id", "userid", "user_id"} or lowered.endswith("id")

    def _is_sensitive_field(self, value: str) -> bool:
        lowered = str(value or "").lower()
        return any(token in lowered for token in ("password", "token", "secret", "role", "admin", "email", "phone"))

    def _is_collection_like(self, path: str, path_params: list[str]) -> bool:
        if path_params:
            return False
        if path.endswith("/all") or path.endswith("/list"):
            return True
        parts = [part for part in path.split("/") if part]
        return len(parts) >= 2
