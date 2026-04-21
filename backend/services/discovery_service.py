from __future__ import annotations

import re
from collections.abc import Iterable
import logging
from urllib.parse import parse_qsl, urljoin, urlparse

import httpx

try:
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ObservedExample, ResourceSignals
    from backend.models.discovery import DiscoveryRequest, DiscoveryResponse
    from backend.services.candidate_classifier import (
        CandidateClassifier,
        OBJECT_ID_KEYWORDS,
        SENSITIVE_KEYWORDS,
    )
    from backend.services.zap_client import ZapClient
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ObservedExample, ResourceSignals
    from models.discovery import DiscoveryRequest, DiscoveryResponse
    from services.candidate_classifier import (
        CandidateClassifier,
        OBJECT_ID_KEYWORDS,
        SENSITIVE_KEYWORDS,
    )
    from services.zap_client import ZapClient


logger = logging.getLogger(__name__)


class DiscoveryService:
    DEFAULT_DISCOVERY_SEEDS = [
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
        "/admin",
        "/user",
        "/users",
        "/account",
        "/profile",
        "/orders",
        "/cart",
        "/checkout",
        "/payment",
    ]

    def __init__(self) -> None:
        self.classifier = CandidateClassifier()
        self.http_timeout_sec = 8.0

    def zap_health_check(self, request: DiscoveryRequest):
        logger.info(
            "Running discovery ZAP diagnostics zap_base_url=%s target_url=%s",
            request.zap_base_url,
            request.target_url,
        )
        diagnostics = ZapClient(request.zap_base_url).health_check(
            target_url=str(request.target_url),
            max_duration_sec=min(max(int(request.max_duration_sec or 15), 10), 15),
        )
        diagnostics["target_reachable_from_backend"] = self._target_reachable_from_backend(
            target_url=str(request.target_url),
            allowed_hosts=request.allowed_hosts,
        )
        logger.info(
            "Discovery ZAP diagnostics result zap_reachable=%s target_reachable_from_backend=%s target_reachable_from_zap=%s spider_status=%s error=%s",
            diagnostics.get("zap_reachable"),
            diagnostics.get("target_reachable_from_backend"),
            diagnostics.get("target_reachable_from_zap"),
            diagnostics.get("spider_status"),
            diagnostics.get("error"),
        )
        if not diagnostics["target_reachable_from_backend"] and not diagnostics.get("error"):
            diagnostics["stage"] = "reach_target_from_backend"
            diagnostics["error"] = "backend_could_not_reach_target"
        return diagnostics

    def discover(self, request: DiscoveryRequest) -> DiscoveryResponse:
        if not request.enable_discovery:
            return DiscoveryResponse(
                target_url=request.target_url,
                discovery_summary="Discovery disabled. Returned 0 raw URLs and 0 normalized endpoints.",
                raw_urls=[],
                normalized_surface=NormalizedApiSurface(endpoints=[]),
                raw_metadata={
                    "source": request.discovery_mode,
                    "enabled": False,
                    "spider_used": False,
                    "ajax_spider_used": False,
                },
            )
        effective_seeds = self._effective_discovery_seeds(request.discovery_seeds)
        seed_urls = self._build_seed_urls(
            target_url=str(request.target_url),
            discovery_seeds=effective_seeds,
        )
        authenticated_headers, authenticated_cookies, auth_role_name = self._build_authenticated_seed_context(
            request.roles,
            request.use_authenticated_discovery,
        )
        metadata = {
            "source": request.discovery_mode,
            "zap_base_url": str(request.zap_base_url),
            "connection_attempted": True,
            "connection_ok": False,
            "spider_used": bool(request.use_spider),
            "ajax_spider_used": bool(request.use_ajax_spider),
            "seed_url_total": len(seed_urls),
        }
        zap_diagnostics = self.zap_health_check(request)
        metadata["zap_diagnostics"] = dict(zap_diagnostics)
        if not zap_diagnostics.get("zap_reachable"):
            metadata["diagnosis"] = "zap_unreachable"
            metadata["stage"] = str(zap_diagnostics.get("stage") or "connect_zap")
            metadata["error"] = str(zap_diagnostics.get("error") or "")
            return DiscoveryResponse(
                target_url=request.target_url,
                discovery_summary="Discovery aborted because ZAP is unreachable.",
                raw_urls=[],
                normalized_surface=NormalizedApiSurface(endpoints=[]),
                raw_metadata=metadata,
            )
        if not zap_diagnostics.get("target_reachable_from_zap"):
            metadata["diagnosis"] = "target_unreachable_from_zap"
            metadata["stage"] = str(zap_diagnostics.get("stage") or "reach_target_from_zap")
            metadata["error"] = str(zap_diagnostics.get("error") or "")
            return DiscoveryResponse(
                target_url=request.target_url,
                discovery_summary="Discovery aborted because ZAP cannot reach the target.",
                raw_urls=[],
                normalized_surface=NormalizedApiSurface(endpoints=[]),
                raw_metadata=metadata,
            )
        try:
            raw_urls, zap_metadata = ZapClient(request.zap_base_url).discover_urls(
                str(request.target_url),
                seed_urls=seed_urls,
                use_spider=request.use_spider,
                use_ajax_spider=request.use_ajax_spider,
                max_children=request.max_children,
                max_duration_sec=request.max_duration_sec,
            )
            metadata.update(zap_metadata)
        except Exception as exc:
            raw_urls = []
            metadata["error"] = str(exc)

        seeded_urls, seed_metadata = self._run_seed_requests(
            seed_urls=seed_urls,
            headers=authenticated_headers,
            cookies=authenticated_cookies,
            max_duration_sec=request.max_duration_sec,
        )
        metadata.update(seed_metadata)
        if auth_role_name:
            metadata["authenticated_seed_role"] = auth_role_name

        filtered_urls = self._filter_urls(
            raw_urls=[*raw_urls, *seeded_urls],
            target_url=str(request.target_url),
            allowed_hosts=request.allowed_hosts,
            discovery_seeds=effective_seeds,
        )
        normalized_surface = self._normalize_urls(filtered_urls, discovery_seeds=effective_seeds)
        metadata["seed_mode"] = "user_provided" if request.discovery_seeds else "auto_generated"
        metadata["effective_discovery_seeds"] = effective_seeds
        metadata["effective_seed_total"] = len(effective_seeds)
        metadata["zap_diagnostics"] = {
            **dict(zap_diagnostics),
            "urls_discovered": int(zap_diagnostics.get("urls_discovered", 0) or 0),
            "api_like_url_count": int(zap_diagnostics.get("api_like_urls", 0) or 0),
            "spider_status": str(zap_diagnostics.get("spider_status") or ""),
        }
        if zap_diagnostics.get("urls_discovered", 0) and not zap_diagnostics.get("api_like_urls", 0):
            metadata["diagnosis"] = "spa_or_js_heavy_app"
        summary = (
            f"ZAP discovered {len(raw_urls)} raw URLs and normalized "
            f"{len(normalized_surface.endpoints)} unique endpoints."
        )
        return DiscoveryResponse(
            target_url=request.target_url,
            discovery_summary=summary,
            raw_urls=filtered_urls,
            normalized_surface=normalized_surface,
            raw_metadata=metadata,
        )

    def _target_reachable_from_backend(self, *, target_url: str, allowed_hosts: list[str]) -> bool:
        parsed = urlparse(target_url)
        host = str(parsed.netloc or "").strip().lower()
        allowed = {str(item or "").strip().lower() for item in (allowed_hosts or []) if str(item or "").strip()}
        if allowed and host not in allowed:
            return False
        try:
            response = httpx.get(target_url, timeout=self.http_timeout_sec, follow_redirects=True)
            return response.status_code is not None
        except Exception:
            return False

    def _effective_discovery_seeds(self, discovery_seeds: list[str]) -> list[str]:
        seeds = [str(item or "").strip() for item in (discovery_seeds or []) if str(item or "").strip()]
        if seeds:
            return seeds
        return list(self.DEFAULT_DISCOVERY_SEEDS)

    def _filter_urls(
        self,
        *,
        raw_urls: Iterable[str],
        target_url: str,
        allowed_hosts: list[str],
        discovery_seeds: list[str],
    ) -> list[str]:
        allowed = {str(item).strip().lower() for item in allowed_hosts if str(item).strip()}
        target_parsed = urlparse(target_url)
        default_host = target_parsed.netloc.lower()
        if default_host:
            allowed.add(default_host)

        filtered: list[str] = []
        seen: set[str] = set()
        for item in raw_urls:
            value = str(item or "").strip()
            if not value:
                continue
            parsed = urlparse(value)
            if parsed.scheme not in {"http", "https"}:
                continue
            host = parsed.netloc.lower()
            if allowed and host not in allowed:
                continue
            if self._is_noise_url(parsed.path):
                continue
            if value in seen:
                continue
            seen.add(value)
            filtered.append(value)
        api_like = [item for item in filtered if self._is_api_like_url(item, discovery_seeds)]
        return api_like or filtered

    def _normalize_urls(self, raw_urls: list[str], *, discovery_seeds: list[str]) -> NormalizedApiSurface:
        by_key: dict[tuple[str, str], NormalizedEndpoint] = {}
        object_candidates: dict[tuple[str, str], list[str]] = {}

        for raw_url in raw_urls:
            parsed = urlparse(raw_url)
            normalized_path, path_params, object_ids = self._normalize_path(parsed.path)
            query_params = sorted({name for name, _ in parse_qsl(parsed.query, keep_blank_values=True) if name})
            key = ("GET", normalized_path)

            endpoint = by_key.get(key)
            if endpoint is None:
                endpoint = NormalizedEndpoint(
                    path=normalized_path,
                    method="GET",
                    path_params=path_params,
                    query_params=query_params,
                    body_fields=[],
                    auth_required=False,
                    security_schemes=[],
                    tags=[],
                    object_param_name=path_params[0] if path_params else "",
                    object_id_candidates=[],
                    resource_signals=self._resource_signals(normalized_path, path_params, query_params),
                    observed_examples=[ObservedExample(source="discovery", method="GET", url=raw_url)],
                    sources=["discovery"],
                    source_confidence=0.75,
                )
                by_key[key] = endpoint
                object_candidates[key] = []
            else:
                endpoint.query_params = sorted(set(endpoint.query_params).union(query_params))

            for value in object_ids:
                if value not in object_candidates[key]:
                    object_candidates[key].append(value)

        endpoints: list[NormalizedEndpoint] = []
        for key, endpoint in by_key.items():
            endpoint.object_id_candidates = list(object_candidates.get(key) or [])
            endpoint.object_param_name = endpoint.object_param_name or (endpoint.path_params[0] if endpoint.path_params else "")
            classified = self.classifier.classify(endpoint)
            if self._is_useful_endpoint(classified, discovery_seeds):
                endpoints.append(classified)

        endpoints.sort(key=lambda item: (item.path, item.method))
        return NormalizedApiSurface(endpoints=endpoints)

    def _normalize_path(self, path: str) -> tuple[str, list[str], list[str]]:
        segments = [segment for segment in str(path or "").split("/") if segment]
        normalized_segments: list[str] = []
        path_params: list[str] = []
        object_ids: list[str] = []

        for segment in segments:
            if self._is_object_like_segment(segment):
                normalized_segments.append("{id}")
                if "id" not in path_params:
                    path_params.append("id")
                object_ids.append(segment)
            else:
                normalized_segments.append(segment)

        normalized_path = "/" + "/".join(normalized_segments) if normalized_segments else "/"
        return normalized_path, path_params, object_ids

    def _resource_signals(
        self,
        path: str,
        path_params: list[str],
        query_params: list[str],
    ) -> ResourceSignals:
        lowered_path = str(path or "").lower()
        normalized_names = {
            str(item).strip().lower().replace("-", "").replace("_", "")
            for item in [*path_params, *query_params]
        }
        has_object_id = bool(path_params) or "{id}" in lowered_path
        has_sensitive_keywords = any(keyword in lowered_path for keyword in SENSITIVE_KEYWORDS)
        has_role_fields = any(
            token in normalized_names
            for token in {"role", "roles", "owner", "ownerid", "owner_id", "userid", "user_id"}
        )
        return ResourceSignals(
            has_object_id=has_object_id,
            has_role_fields=has_role_fields,
            has_sensitive_keywords=has_sensitive_keywords,
        )

    def _build_seed_urls(self, *, target_url: str, discovery_seeds: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for seed in discovery_seeds or []:
            value = str(seed or "").strip()
            if not value:
                continue
            if value.startswith(("http://", "https://")):
                absolute = value
            else:
                absolute = urljoin(str(target_url).rstrip("/") + "/", value.lstrip("/"))
            if absolute not in seen:
                seen.add(absolute)
                normalized.append(absolute)
        return normalized

    def _build_authenticated_seed_context(
        self,
        roles: list[dict],
        enabled: bool,
    ) -> tuple[dict[str, str], dict[str, str], str | None]:
        if not enabled:
            return {}, {}, None
        for role in roles or []:
            if not isinstance(role, dict):
                continue
            headers: dict[str, str] = {}
            cookies: dict[str, str] = {}

            auth_headers = role.get("auth_headers")
            if isinstance(auth_headers, dict):
                headers.update({str(k): str(v) for k, v in auth_headers.items() if str(k).strip()})

            raw_headers = role.get("headers")
            if isinstance(raw_headers, dict):
                headers.update({str(k): str(v) for k, v in raw_headers.items() if str(k).strip()})

            token = role.get("token")
            if token and "authorization" not in {key.lower() for key in headers}:
                token_type = str(role.get("token_type") or "Bearer").strip() or "Bearer"
                headers["Authorization"] = f"{token_type} {token}"

            token_header_name = role.get("token_header_name")
            if token and token_header_name:
                headers[str(token_header_name)] = str(token)

            raw_cookies = role.get("cookies")
            if isinstance(raw_cookies, dict):
                cookies.update({str(k): str(v) for k, v in raw_cookies.items() if str(k).strip()})

            if headers or cookies:
                return headers, cookies, str(role.get("name") or role.get("role") or "").strip() or None
        return {}, {}, None

    def _run_seed_requests(
        self,
        *,
        seed_urls: list[str],
        headers: dict[str, str],
        cookies: dict[str, str],
        max_duration_sec: int,
    ) -> tuple[list[str], dict[str, object]]:
        if not seed_urls:
            return [], {
                "seed_request_total": 0,
                "seed_success_total": 0,
                "authenticated_seed_used": bool(headers or cookies),
            }

        timeout = min(max(int(max_duration_sec or 30), 5), 30)
        discovered: list[str] = []
        successes = 0
        with httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers=headers or None,
            cookies=cookies or None,
        ) as client:
            for seed_url in seed_urls:
                try:
                    response = client.get(seed_url)
                except Exception:
                    continue
                if response.status_code in {200, 201, 202, 204, 301, 302, 303, 307, 308, 401, 403}:
                    successes += 1
                    discovered.append(str(response.request.url))
                    discovered.append(str(response.url))
                    discovered.extend(self._extract_links(str(response.url), response))

        return self._dedupe_urls(discovered), {
            "seed_request_total": len(seed_urls),
            "seed_success_total": successes,
            "authenticated_seed_used": bool(headers or cookies),
        }

    def _extract_links(self, base_url: str, response: httpx.Response) -> list[str]:
        body = response.text or ""
        if not body:
            return []

        content_type = str(response.headers.get("content-type") or "").lower()
        results: list[str] = []
        absolute_matches = re.findall(r"https?://[^\s\"'<>]+", body)
        relative_matches = re.findall(r"(?:(?:href|src|action)\s*=\s*[\"']|[\"'])(/[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]+)", body)

        for item in absolute_matches:
            results.append(item)
        for item in relative_matches:
            results.append(urljoin(base_url, item))

        if "json" in content_type:
            json_path_matches = re.findall(r"/[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]*api[A-Za-z0-9._~:/?#\\[\\]@!$&'()*+,;=%-]*", body, flags=re.IGNORECASE)
            for item in json_path_matches:
                results.append(urljoin(base_url, item))
        return self._dedupe_urls(results)

    def _is_useful_endpoint(self, endpoint: NormalizedEndpoint, discovery_seeds: list[str]) -> bool:
        lower_path = str(endpoint.path or "").lower()
        if self._is_noise_url(lower_path):
            return False
        if self._matches_seed_prefix(lower_path, discovery_seeds):
            return True
        if "/api/" in lower_path or lower_path.startswith("/api/") or lower_path.endswith("/api"):
            return True
        if endpoint.path_params or endpoint.query_params or endpoint.object_id_candidates:
            return True
        if endpoint.resource_signals.has_sensitive_keywords or endpoint.resource_signals.has_object_id:
            return True
        if any(score > 0.2 for score in endpoint.candidate_scores.model_dump().values()):
            return True
        return False

    def _is_api_like_url(self, raw_url: str, discovery_seeds: list[str]) -> bool:
        parsed = urlparse(raw_url)
        lower_path = str(parsed.path or "").lower()
        if self._matches_seed_prefix(lower_path, discovery_seeds):
            return True
        if "/api/" in lower_path or lower_path.startswith("/api/") or lower_path.endswith("/api"):
            return True
        if self._is_object_like_path(lower_path):
            return True
        if any(keyword in lower_path for keyword in (*OBJECT_ID_KEYWORDS, *SENSITIVE_KEYWORDS, "community", "identity", "vehicle", "workshop", "profile", "order", "post")):
            return True
        return bool(parsed.query)

    def _matches_seed_prefix(self, lower_path: str, discovery_seeds: list[str]) -> bool:
        normalized_seeds = []
        for item in discovery_seeds or []:
            parsed = urlparse(str(item or "").strip())
            seed_path = str(parsed.path if parsed.scheme or parsed.netloc else item or "").strip()
            if not seed_path:
                continue
            normalized = "/" + "/".join(part for part in seed_path.split("/") if part)
            normalized_seeds.append(normalized.lower() if normalized != "/" else normalized)
        return any(lower_path == seed or lower_path.startswith(seed + "/") for seed in normalized_seeds if seed and seed != "/")

    def _is_noise_url(self, path: str) -> bool:
        lower_path = str(path or "").lower()
        if lower_path in {"/", "/robots.txt", "/sitemap.xml", "/favicon.ico"}:
            return True
        return any(
            lower_path.endswith(suffix)
            for suffix in (
                ".css",
                ".js",
                ".map",
                ".png",
                ".jpg",
                ".jpeg",
                ".gif",
                ".svg",
                ".ico",
                ".woff",
                ".woff2",
            )
        )

    def _is_object_like_path(self, path: str) -> bool:
        return any(self._is_object_like_segment(segment) for segment in str(path or "").split("/") if segment)

    def _dedupe_urls(self, values: list[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in values:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _is_object_like_segment(self, segment: str) -> bool:
        value = str(segment or "").strip()
        if not value:
            return False
        lower_value = value.lower()
        if lower_value in {"me", "new", "recent", "latest", "search", "health"}:
            return False
        if value.isdigit():
            return True
        if self._looks_like_uuid(value):
            return True
        if self._looks_like_hex(value):
            return True
        if len(value) >= 12 and any(char.isdigit() for char in value) and any(char.isalpha() for char in value):
            return True
        return False

    def _looks_like_uuid(self, value: str) -> bool:
        parts = value.split("-")
        if len(parts) != 5:
            return False
        expected_lengths = [8, 4, 4, 4, 12]
        for part, expected in zip(parts, expected_lengths, strict=False):
            if len(part) != expected or not all(char in "0123456789abcdefABCDEF" for char in part):
                return False
        return True

    def _looks_like_hex(self, value: str) -> bool:
        if len(value) < 12:
            return False
        return all(char in "0123456789abcdefABCDEF" for char in value)
