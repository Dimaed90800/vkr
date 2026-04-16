try:
    from backend.models.api_surface import AuthSignals, NormalizedApiSurface, NormalizedEndpoint, ObservedExample, ResourceSignals
    from backend.services.candidate_classifier import CandidateClassifier
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import AuthSignals, NormalizedApiSurface, NormalizedEndpoint, ObservedExample, ResourceSignals
    from services.candidate_classifier import CandidateClassifier


class SurfaceMergeService:
    def __init__(self) -> None:
        self.classifier = CandidateClassifier()

    def merge(
        self,
        openapi_surface: NormalizedApiSurface | None,
        discovery_surface: NormalizedApiSurface | None,
        traffic_surface: NormalizedApiSurface | None = None,
    ) -> NormalizedApiSurface:
        merged: dict[tuple[str, str], NormalizedEndpoint] = {}

        for endpoint in (openapi_surface.endpoints if openapi_surface else []):
            key = (str(endpoint.method or "").upper(), str(endpoint.path or ""))
            item = endpoint.model_copy(deep=True)
            item.sources = self._merge_strings(item.sources, ["openapi"])
            item.source_confidence = max(float(item.source_confidence or 0), 0.9)
            merged[key] = item

        for surface, source_name, confidence in (
            (discovery_surface, "discovery", 0.75),
            (traffic_surface, "traffic", 0.95),
        ):
            for endpoint in (surface.endpoints if surface else []):
                key = (str(endpoint.method or "").upper(), str(endpoint.path or ""))
                item = endpoint.model_copy(deep=True)
                item.sources = self._merge_strings(item.sources, [source_name])
                item.source_confidence = max(float(item.source_confidence or 0), confidence)
                if key not in merged:
                    merged[key] = self.classifier.classify(item)
                    continue
                merged[key] = self._merge_endpoint(merged[key], item)

        endpoints = sorted(merged.values(), key=lambda item: (item.path, item.method))
        return NormalizedApiSurface(endpoints=endpoints)

    def _merge_endpoint(
        self,
        openapi_endpoint: NormalizedEndpoint,
        discovery_endpoint: NormalizedEndpoint,
    ) -> NormalizedEndpoint:
        merged = openapi_endpoint.model_copy(deep=True)
        merged.query_params = sorted(set(merged.query_params).union(discovery_endpoint.query_params))
        merged.path_params = merged.path_params or discovery_endpoint.path_params
        merged.body_fields = sorted(set(merged.body_fields).union(discovery_endpoint.body_fields))
        merged.object_param_name = merged.object_param_name or discovery_endpoint.object_param_name
        merged.object_id_candidates = self._merge_strings(
            merged.object_id_candidates,
            discovery_endpoint.object_id_candidates,
        )
        merged.auth_required = merged.auth_required or discovery_endpoint.auth_required
        merged.security_schemes = self._merge_strings(
            merged.security_schemes,
            discovery_endpoint.security_schemes,
        )
        merged.resource_signals = ResourceSignals(
            has_object_id=merged.resource_signals.has_object_id or discovery_endpoint.resource_signals.has_object_id,
            has_role_fields=merged.resource_signals.has_role_fields or discovery_endpoint.resource_signals.has_role_fields,
            has_sensitive_keywords=merged.resource_signals.has_sensitive_keywords or discovery_endpoint.resource_signals.has_sensitive_keywords,
        )
        merged.auth_signals = AuthSignals(
            has_auth_header=merged.auth_signals.has_auth_header or discovery_endpoint.auth_signals.has_auth_header,
            has_cookie_auth=merged.auth_signals.has_cookie_auth or discovery_endpoint.auth_signals.has_cookie_auth,
            header_names=self._merge_strings(merged.auth_signals.header_names, discovery_endpoint.auth_signals.header_names),
            cookie_names=self._merge_strings(merged.auth_signals.cookie_names, discovery_endpoint.auth_signals.cookie_names),
        )
        merged.observed_examples = self._merge_examples(
            merged.observed_examples,
            discovery_endpoint.observed_examples,
        )
        merged.sources = self._merge_strings(merged.sources, discovery_endpoint.sources)
        merged.source_confidence = max(float(merged.source_confidence or 0), float(discovery_endpoint.source_confidence or 0))
        return self.classifier.classify(merged)

    def _merge_strings(self, left: list[str], right: list[str]) -> list[str]:
        seen: set[str] = set()
        values: list[str] = []
        for item in [*(left or []), *(right or [])]:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            values.append(value)
        return values

    def _merge_examples(self, left: list[ObservedExample], right: list[ObservedExample]) -> list[ObservedExample]:
        seen: set[tuple[str, str, str]] = set()
        values: list[ObservedExample] = []
        for item in [*(left or []), *(right or [])]:
            key = (str(item.source or ""), str(item.method or ""), str(item.url or ""))
            if key in seen:
                continue
            seen.add(key)
            values.append(item)
        return values[:5]
