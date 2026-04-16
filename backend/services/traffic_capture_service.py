from __future__ import annotations

from urllib.parse import parse_qsl, urlparse

try:
    from backend.models.api_surface import AuthSignals, NormalizedApiSurface, NormalizedEndpoint, ObservedExample
    from backend.models.traffic_discovery import ObservedHttpRequest, TrafficDiscoveryRequest, TrafficDiscoveryResponse
    from backend.services.candidate_classifier import CandidateClassifier
    from backend.services.discovery_service import DiscoveryService
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import AuthSignals, NormalizedApiSurface, NormalizedEndpoint, ObservedExample
    from models.traffic_discovery import ObservedHttpRequest, TrafficDiscoveryRequest, TrafficDiscoveryResponse
    from services.candidate_classifier import CandidateClassifier
    from services.discovery_service import DiscoveryService


class TrafficCaptureService:
    def __init__(self) -> None:
        self.classifier = CandidateClassifier()
        self.discovery_helper = DiscoveryService()

    def capture(self, request: TrafficDiscoveryRequest) -> TrafficDiscoveryResponse:
        by_key: dict[tuple[str, str], NormalizedEndpoint] = {}

        accepted_requests = 0
        for observed in request.requests or []:
            endpoint = self._normalize_request(observed)
            if endpoint is None:
                continue
            accepted_requests += 1
            key = (endpoint.method.upper(), endpoint.path)
            if key not in by_key:
                by_key[key] = endpoint
                continue
            by_key[key] = self._merge_endpoint(by_key[key], endpoint)

        endpoints = sorted(by_key.values(), key=lambda item: (item.path, item.method))
        return TrafficDiscoveryResponse(
            traffic_summary=(
                f"Imported {len(request.requests or [])} observed requests and normalized "
                f"{len(endpoints)} unique endpoints."
            ),
            normalized_surface=NormalizedApiSurface(endpoints=endpoints),
            raw_metadata={
                "observed_request_total": len(request.requests or []),
                "accepted_request_total": accepted_requests,
                "normalized_endpoint_total": len(endpoints),
                "source": "traffic",
            },
        )

    def _normalize_request(self, observed: ObservedHttpRequest) -> NormalizedEndpoint | None:
        parsed = urlparse(str(observed.url))
        if parsed.scheme not in {"http", "https"}:
            return None
        if self.discovery_helper._is_noise_url(parsed.path):
            return None

        normalized_path, path_params, object_ids = self.discovery_helper._normalize_path(parsed.path)
        url_query_params = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name]
        explicit_query_params = [str(key) for key in (observed.query_params or {}).keys() if str(key).strip()]
        body_fields = self._extract_body_fields(observed.json_body)
        auth_signals = self._build_auth_signals(observed.headers or {}, observed.cookies or {})

        endpoint = NormalizedEndpoint(
            path=normalized_path,
            method=str(observed.method or "GET").upper(),
            path_params=path_params,
            query_params=sorted(set(url_query_params).union(explicit_query_params)),
            body_fields=body_fields,
            auth_required=auth_signals.has_auth_header or auth_signals.has_cookie_auth,
            security_schemes=["observedAuth"] if (auth_signals.has_auth_header or auth_signals.has_cookie_auth) else [],
            tags=[],
            object_param_name=path_params[0] if path_params else "",
            object_id_candidates=[str(value) for value in object_ids],
            resource_signals=self.discovery_helper._resource_signals(normalized_path, path_params, sorted(set(url_query_params).union(explicit_query_params))),
            auth_signals=auth_signals,
            observed_examples=[
                ObservedExample(
                    source="traffic",
                    method=str(observed.method or "GET").upper(),
                    url=str(observed.url),
                )
            ],
            sources=["traffic"],
            source_confidence=0.95,
        )
        return self.classifier.classify(endpoint)

    def _merge_endpoint(self, primary: NormalizedEndpoint, secondary: NormalizedEndpoint) -> NormalizedEndpoint:
        merged = primary.model_copy(deep=True)
        merged.query_params = sorted(set(merged.query_params).union(secondary.query_params))
        merged.body_fields = sorted(set(merged.body_fields).union(secondary.body_fields))
        merged.object_id_candidates = self._merge_strings(merged.object_id_candidates, secondary.object_id_candidates)
        merged.auth_required = merged.auth_required or secondary.auth_required
        merged.security_schemes = self._merge_strings(merged.security_schemes, secondary.security_schemes)
        merged.auth_signals = AuthSignals(
            has_auth_header=merged.auth_signals.has_auth_header or secondary.auth_signals.has_auth_header,
            has_cookie_auth=merged.auth_signals.has_cookie_auth or secondary.auth_signals.has_cookie_auth,
            header_names=self._merge_strings(merged.auth_signals.header_names, secondary.auth_signals.header_names),
            cookie_names=self._merge_strings(merged.auth_signals.cookie_names, secondary.auth_signals.cookie_names),
        )
        merged.observed_examples = self._merge_examples(merged.observed_examples, secondary.observed_examples)
        merged.sources = self._merge_strings(merged.sources, secondary.sources)
        merged.source_confidence = max(float(merged.source_confidence or 0), float(secondary.source_confidence or 0))
        return self.classifier.classify(merged)

    def _extract_body_fields(self, payload) -> list[str]:
        if isinstance(payload, dict):
            return sorted(str(key) for key in payload.keys() if str(key).strip())
        return []

    def _build_auth_signals(self, headers: dict[str, str], cookies: dict[str, str]) -> AuthSignals:
        normalized_headers = {str(k).strip(): str(v) for k, v in (headers or {}).items() if str(k).strip()}
        normalized_cookies = {str(k).strip(): str(v) for k, v in (cookies or {}).items() if str(k).strip()}
        lowered_header_names = {key.lower() for key in normalized_headers.keys()}
        lowered_cookie_names = {key.lower() for key in normalized_cookies.keys()}
        auth_header_names = [
            key for key in normalized_headers.keys()
            if key.lower() in {"authorization", "x-auth-token", "x-access-token", "cookie"}
        ]
        auth_cookie_names = [
            key for key in normalized_cookies.keys()
            if key.lower() in {"session", "sessionid", "jwt", "token", "access_token", "refresh_token"}
        ]
        return AuthSignals(
            has_auth_header=bool(auth_header_names) or any(name in lowered_header_names for name in {"authorization", "x-auth-token", "x-access-token"}),
            has_cookie_auth=bool(auth_cookie_names) or any(name in lowered_cookie_names for name in {"session", "sessionid", "jwt", "token", "access_token"}),
            header_names=sorted(auth_header_names),
            cookie_names=sorted(auth_cookie_names),
        )

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
