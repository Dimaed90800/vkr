try:
    from backend.models.api_surface import NormalizedApiSurface
    from backend.models.testing import ExecutionContext
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface
    from models.testing import ExecutionContext


class CapabilityInferenceService:
    AUTH_ENTRYPOINT_PREFIXES = ("/api", "/identity", "/auth", "/user", "/account")

    def infer(
        self,
        *,
        execution_context: ExecutionContext | None,
        normalized_surface: NormalizedApiSurface | None,
    ) -> dict[str, bool]:
        endpoints = list(normalized_surface.endpoints if normalized_surface else [])
        roles = list(execution_context.roles if execution_context else [])

        role_profiles = [item for item in roles if isinstance(item, dict)]
        auth_profiles = [item for item in role_profiles if self._has_auth_material(item)]
        provisioned_identities = [item for item in auth_profiles if self._looks_provisioned(item)]
        lowered_paths = [str(endpoint.path or "").lower() for endpoint in endpoints]
        source_names = {
            str(source or "").strip().lower()
            for endpoint in endpoints
            for source in (endpoint.sources or [])
            if str(source or "").strip()
        }

        has_openapi_input = bool(
            execution_context
            and (
                str(execution_context.openapi_url or "").strip()
                or str(execution_context.openapi_spec_text or "").strip()
            )
        )
        discovered_auth_endpoints = list(execution_context.discovered_auth_endpoints if execution_context else [])
        has_login_endpoint = any(any(token in path for token in ("login", "signin", "sign-in", "token", "auth")) for path in lowered_paths) or any(
            str(item.get("type") or "").strip().lower() == "login" for item in discovered_auth_endpoints if isinstance(item, dict)
        )
        has_register_endpoint = any(any(token in path for token in ("register", "signup", "sign-up")) for path in lowered_paths) or any(
            str(item.get("type") or "").strip().lower() == "register" for item in discovered_auth_endpoints if isinstance(item, dict)
        )
        has_auth_entrypoint_candidates = bool(
            endpoints
            and any(
                any(str(path).startswith(prefix) for prefix in self.AUTH_ENTRYPOINT_PREFIXES)
                for path in lowered_paths
            )
        )

        has_execution_traffic = bool(execution_context and list(execution_context.traffic_requests or []))

        return {
            "has_openapi": has_openapi_input or "openapi" in source_names,
            "has_discovery_surface": any(source in source_names for source in {"discovery", "passive_discovery", "passive", "js_analysis"}) or any("/api" in path for path in lowered_paths),
            "has_traffic_surface": any(source in source_names for source in {"traffic", "browser_traffic"}) or has_execution_traffic,
            "has_browser_capture": "browser_traffic" in source_names or "browser_capture" in source_names or "playwright" in source_names,
            "has_auth_profiles": bool(auth_profiles),
            "has_multi_role_auth": len(auth_profiles) >= 2,
            "has_provisioned_identities": bool(provisioned_identities),
            "has_register_endpoint": has_register_endpoint,
            "has_login_endpoint": has_login_endpoint,
            "has_auth_entrypoint_candidates": has_auth_entrypoint_candidates,
            "has_api_surface": bool(endpoints),
            "has_input_shape": any(
                endpoint.query_params or endpoint.body_fields or endpoint.path_params
                or any(source in {"traffic", "browser_traffic"} for source in (endpoint.sources or []))
                for endpoint in endpoints
            ),
            "has_workflow_hints": (
                len(endpoints) >= 2
                or any(endpoint.observed_examples for endpoint in endpoints)
                or any(source in {"browser_traffic", "js_analysis"} for source in source_names)
            ),
            "has_object_candidates": any(endpoint.object_id_candidates for endpoint in endpoints),
            "has_prepared_object": any(
                endpoint.object_id_candidates and any(source in {"prepared", "traffic", "discovery", "openapi"} for source in (endpoint.sources or []))
                for endpoint in endpoints
            ),
        }

    def _has_auth_material(self, role: dict) -> bool:
        return bool(
            role.get("token")
            or role.get("auth_headers")
            or role.get("headers")
            or role.get("cookies")
        )

    def _looks_provisioned(self, role: dict) -> bool:
        name = str(role.get("name") or role.get("role") or "").strip().lower()
        return bool(name.startswith("user_auto_") or role.get("provisioned") is True)
