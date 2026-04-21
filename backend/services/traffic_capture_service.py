from __future__ import annotations

from urllib.parse import urljoin
from urllib.parse import parse_qsl, urlparse

import httpx

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
    DEFAULT_ANONYMOUS_PATHS = [
        "/",
        "/api",
        "/v1",
        "/v2",
        "/v3",
        "/auth",
        "/login",
        "/signin",
        "/signup",
        "/register",
        "/identity",
        "/community",
        "/workshop",
        "/profile",
        "/users",
        "/orders",
    ]
    API_LIKE_PREFIXES = (
        "/api",
        "/v1",
        "/v2",
        "/auth",
        "/login",
        "/register",
        "/identity",
        "/community",
        "/workshop",
        "/user",
        "/account",
        "/profile",
        "/orders",
    )

    def __init__(self) -> None:
        self.classifier = CandidateClassifier()
        self.discovery_helper = DiscoveryService()

    def capture(self, request: TrafficDiscoveryRequest) -> TrafficDiscoveryResponse:
        observed_requests = list(request.requests or [])
        generated_requests: list[ObservedHttpRequest] = []
        generation_mode = "provided"
        probe_metadata = {
            "candidate_path_total": 0,
            "attempted_path_total": 0,
            "accepted_paths": [],
            "rejected_paths_with_reasons": [],
        }
        if not observed_requests and request.target_url:
            generated_requests, probe_metadata = self._generate_anonymous_requests(request)
            observed_requests = generated_requests
            generation_mode = "autonomous_anonymous"

        accepted_requests = sum(
            1
            for observed in observed_requests
            if self._normalize_request(observed, source_name="traffic", source_confidence=0.95) is not None
        )
        normalized_surface = self.normalize_requests(observed_requests, source_name="traffic", source_confidence=0.95)
        endpoints = list(normalized_surface.endpoints or [])
        return TrafficDiscoveryResponse(
            traffic_summary=(
                f"Imported {len(observed_requests)} observed requests and normalized "
                f"{len(endpoints)} unique endpoints."
            ),
            normalized_surface=normalized_surface,
            raw_metadata={
                "observed_request_total": len(observed_requests),
                "provided_request_total": len(request.requests or []),
                "generated_request_total": len(generated_requests),
                "candidate_path_total": int(probe_metadata.get("candidate_path_total", 0) or 0),
                "attempted_path_total": int(probe_metadata.get("attempted_path_total", 0) or 0),
                "accepted_request_total": accepted_requests,
                "rejected_request_total": len(probe_metadata.get("rejected_paths_with_reasons", []) or []),
                "normalized_endpoint_total": len(endpoints),
                "source": "traffic",
                "generation_mode": generation_mode,
                "accepted_paths": list(probe_metadata.get("accepted_paths") or []),
                "rejected_paths_with_reasons": list(probe_metadata.get("rejected_paths_with_reasons") or []),
                "likely_spa": bool(
                    generation_mode == "autonomous_anonymous"
                    and not endpoints
                    and any(
                        isinstance(item, dict) and str(item.get("reason") or "") == "non_api_non_json_response"
                        for item in (probe_metadata.get("rejected_paths_with_reasons") or [])
                    )
                ),
            },
        )

    def normalize_requests(
        self,
        observed_requests: list[ObservedHttpRequest],
        *,
        source_name: str = "traffic",
        source_confidence: float = 0.95,
    ) -> NormalizedApiSurface:
        by_key: dict[tuple[str, str], NormalizedEndpoint] = {}
        for observed in observed_requests or []:
            endpoint = self._normalize_request(
                observed,
                source_name=source_name,
                source_confidence=source_confidence,
            )
            if endpoint is None:
                continue
            key = (endpoint.method.upper(), endpoint.path)
            if key not in by_key:
                by_key[key] = endpoint
                continue
            by_key[key] = self._merge_endpoint(by_key[key], endpoint)
        return NormalizedApiSurface(endpoints=sorted(by_key.values(), key=lambda item: (item.path, item.method)))

    def generate_authenticated_requests(
        self,
        *,
        target_url: str,
        allowed_hosts: list[str],
        roles: list[dict],
        candidate_paths: list[str],
        max_duration_sec: int = 15,
    ) -> list[ObservedHttpRequest]:
        profile = self._first_auth_profile(roles)
        if not profile:
            return []
        urls = self._bounded_candidate_urls(
            target_url=target_url,
            explicit_paths=candidate_paths,
            allowed_hosts=allowed_hosts,
            limit=8,
        )
        timeout = min(max(int(max_duration_sec or 15), 5), 20)
        headers = self._auth_headers(profile)
        cookies = self._auth_cookies(profile)
        observed: list[ObservedHttpRequest] = []
        with httpx.Client(timeout=timeout, headers=headers or None, cookies=cookies or None, follow_redirects=True) as client:
            for url in urls:
                try:
                    response = client.get(url)
                except Exception:
                    continue
                if response.status_code in {200, 201, 202, 204, 401, 403}:
                    observed.append(
                        ObservedHttpRequest(
                            method="GET",
                            url=str(response.request.url),
                            headers=headers,
                            cookies=cookies,
                            query_params={},
                            json_body=None,
                        )
                    )
        return observed

    def _generate_anonymous_requests(self, request: TrafficDiscoveryRequest) -> tuple[list[ObservedHttpRequest], dict[str, object]]:
        urls = self._bounded_candidate_urls(
            target_url=str(request.target_url or ""),
            explicit_paths=list(getattr(request, "candidate_paths", []) or []),
            allowed_hosts=list(getattr(request, "allowed_hosts", []) or []),
            limit=max(1, min(int(request.max_requests or 20), 10)),
        )
        timeout = min(max(int(request.max_duration_sec or 30), 5), 20)
        observed: list[ObservedHttpRequest] = []
        accepted_paths: list[str] = []
        rejected_paths_with_reasons: list[dict[str, str | int | None]] = []
        attempted = 0
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for url in urls:
                attempted += 1
                try:
                    response = client.get(url)
                except Exception as exc:
                    rejected_paths_with_reasons.append({"path": urlparse(url).path or "/", "reason": str(exc)})
                    continue
                accepted, reason = self._accept_anonymous_response(url, response)
                if accepted:
                    accepted_paths.append(urlparse(str(response.request.url)).path or "/")
                    observed.append(
                        ObservedHttpRequest(
                            method="GET",
                            url=str(response.request.url),
                            headers={},
                            cookies={},
                            query_params={},
                            json_body=None,
                        )
                    )
                else:
                    rejected_paths_with_reasons.append(
                        {
                            "path": urlparse(url).path or "/",
                            "status_code": response.status_code,
                            "reason": reason,
                        }
                    )
        return observed, {
            "candidate_path_total": len(self.DEFAULT_ANONYMOUS_PATHS),
            "attempted_path_total": attempted,
            "accepted_paths": accepted_paths,
            "rejected_paths_with_reasons": rejected_paths_with_reasons,
        }

    def _bounded_candidate_urls(
        self,
        *,
        target_url: str,
        explicit_paths: list[str],
        allowed_hosts: list[str],
        limit: int,
    ) -> list[str]:
        allowed = {str(item or "").strip().lower() for item in (allowed_hosts or []) if str(item or "").strip()}
        candidate_paths = list(explicit_paths or []) + list(self.DEFAULT_ANONYMOUS_PATHS)
        seen: set[str] = set()
        urls: list[str] = []
        base = str(target_url or "").rstrip("/") + "/"
        for path in candidate_paths:
            normalized_path = str(path or "").strip()
            if not normalized_path:
                continue
            url = normalized_path if normalized_path.startswith(("http://", "https://")) else urljoin(base, normalized_path.lstrip("/"))
            host = urlparse(url).netloc.lower()
            if allowed and host not in allowed:
                continue
            if url in seen:
                continue
            seen.add(url)
            urls.append(url)
            if len(urls) >= limit:
                break
        return urls

    def _accept_anonymous_response(self, url: str, response: httpx.Response) -> tuple[bool, str]:
        status_code = int(response.status_code or 0)
        path = urlparse(str(response.request.url)).path or "/"
        content_type = str(response.headers.get("content-type") or "").lower()
        is_api_like = self._is_api_like_path(path)
        is_json_like = any(token in content_type for token in ("application/json", "problem+json"))

        if status_code not in {200, 401, 403, 405}:
            return False, f"status_{status_code}_not_accepted"
        if is_api_like:
            return True, "api_like_path"
        if is_json_like:
            return True, "json_like_response"
        return False, "non_api_non_json_response"

    def _is_api_like_path(self, path: str) -> bool:
        lowered = str(path or "").lower()
        return any(lowered == prefix or lowered.startswith(prefix + "/") for prefix in self.API_LIKE_PREFIXES)

    def _first_auth_profile(self, roles: list[dict]) -> dict | None:
        for role in roles or []:
            if not isinstance(role, dict):
                continue
            if role.get("token") or role.get("auth_headers") or role.get("cookies"):
                return role
        return None

    def _auth_headers(self, profile: dict) -> dict[str, str]:
        headers = {
            str(k): str(v)
            for k, v in (profile.get("auth_headers") or {}).items()
            if str(k).strip()
        } if isinstance(profile.get("auth_headers"), dict) else {}
        token = profile.get("token")
        if token and "authorization" not in {key.lower() for key in headers.keys()}:
            token_type = str(profile.get("token_type") or "Bearer").strip() or "Bearer"
            headers["Authorization"] = f"{token_type} {token}"
        return headers

    def _auth_cookies(self, profile: dict) -> dict[str, str]:
        if not isinstance(profile.get("cookies"), dict):
            return {}
        return {str(k): str(v) for k, v in profile.get("cookies", {}).items() if str(k).strip()}

    def _normalize_request(
        self,
        observed: ObservedHttpRequest,
        *,
        source_name: str = "traffic",
        source_confidence: float = 0.95,
    ) -> NormalizedEndpoint | None:
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
                    source=source_name,
                    method=str(observed.method or "GET").upper(),
                    url=str(observed.url),
                )
            ],
            sources=[source_name],
            source_confidence=source_confidence,
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
