"""Backend-only JS endpoint surface expansion.

Fetches one in-scope JavaScript asset, extracts API-like paths without
executing JS, and emits safe discovered_endpoint observations. It never stores
raw JS content, headers, cookies, bodies, or tokens in ToolResult artifacts.
"""
from __future__ import annotations

import hashlib
import re
import time
from urllib.parse import urlparse, urlunparse

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.api_graph_path_matcher import (
        is_static_or_service_asset,
        match_route_fragment,
        normalize_api_path,
        normalize_route_fragment_for_match,
    )
    from backend.services.artifact_store import ArtifactStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.api_graph_path_matcher import (
        is_static_or_service_asset,
        match_route_fragment,
        normalize_api_path,
        normalize_route_fragment_for_match,
    )
    from services.artifact_store import ArtifactStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage


_PATH_RE = re.compile(
    r'(?P<quote>["\'])'
    r'(?P<value>('
    r'https?://[^"\']+'
    r'|/(?:api|identity/api|community/api|workshop/api|v1|v2)/[^"\']*'
    r'))'
    r'(?P=quote)',
    re.IGNORECASE,
)
_ALLOWED_PREFIXES = (
    "/api/",
    "/identity/api/",
    "/community/api/",
    "/workshop/api/",
    "/v1/",
    "/v2/",
)

_ROUTE_FRAGMENT_RE = re.compile(
    r'["`]([a-zA-Z0-9_{}<>\./-]+(?:/[a-zA-Z0-9_{}<>\./-]+)+)["`]',
)

_NOISE_SEGMENTS = frozenset({
    "static", "assets", "images", "css", "scss", "svg", "png", "jpg", "jpeg", "ico", "map",
    "theme", "themes", "reducer", "components", "node_modules", "webpack", "chunk", "docs",
})

_TLD_SKIP = re.compile(r"\.(com|org)(/|$)", re.IGNORECASE)


class JsEndpointExtractorAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        js_url = str(inputs.get("js_url") or "").strip()
        if not js_url:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="missing_js_url",
                message="js_url is required for js_endpoint_extractor.",
            )

        validation_mode = str(
            inputs.get("validation_mode") or "static_js_endpoint_extraction"
        ).strip() or "static_js_endpoint_extraction"
        max_js_bytes = max(1, int(inputs.get("max_js_bytes") or 3000000))
        max_endpoints = max(1, int(inputs.get("max_endpoints") or 50))
        max_route_fragments = max(1, min(int(inputs.get("max_route_fragments") or 100), 100))
        timeout_sec = min(command.budget.timeout_sec, campaign.limits.max_duration_sec, 15)
        source_observation_id = str(inputs.get("source_observation_id") or "").strip()
        safe_js_url = _strip_query_and_fragment(js_url)
        source_js_ref = hashlib.sha256(safe_js_url.encode("utf-8")).hexdigest()[:16]

        result = self._http.request(
            campaign,
            method="GET",
            url=js_url,
            timeout_sec=timeout_sec,
            max_response_bytes=max_js_bytes,
            follow_redirects=False,
        )
        if result.error is not None:
            if result.error.code == "response_too_large":
                marker_details = _marker_details(
                    safe_js_url=safe_js_url,
                    source_js_ref=source_js_ref,
                    source_observation_id=source_observation_id,
                    result="js_too_large_skipped",
                    absolute_paths_count=0,
                    route_fragments_count=0,
                    route_fragments_matched_count=0,
                    endpoints_extracted_count=0,
                    endpoints_emitted_count=0,
                    filtered_count=0,
                    multi_match_skipped=0,
                    fragment_no_graph_match=0,
                    reason_codes=["response_too_large"],
                )
                artifact = self._artifacts.save_artifact(
                    campaign_id=command.campaign_id,
                    tool_run_id=tool_run_id,
                    artifact_type="js_endpoint_extraction_summary",
                    content=marker_details,
                )
                duration_ms = int(time.monotonic() * 1000) - start_ms
                return ToolResult(
                    tool_run_id=tool_run_id,
                    campaign_id=command.campaign_id,
                    task_id=command.task_id,
                    command_id=command.command_id,
                    tool_name=command.tool_name,
                    status="finished",
                    summary=ToolResultSummary(
                        request_count=1,
                        success_count=0,
                        client_error_count=0,
                        server_error_count=0,
                        duration_ms=duration_ms,
                    ),
                    requests=[ToolResultRequest(
                        request_id="",
                        role="",
                        method="GET",
                        url=safe_js_url,
                        path_template=normalize_api_path(urlparse(safe_js_url).path or "/"),
                    )],
                    responses=[ToolResultResponse(
                        request_id="",
                        status_code=int(result.status_code or 0),
                    )],
                    observations=[ToolResultObservationLite(
                        observation_type="js_endpoint_extraction_result",
                        confidence=0.0,
                        details=marker_details,
                    )],
                    artifacts=[artifact],
                )
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=result.error.code,
                message=result.error.message,
            )

        response_text = result.response_body if isinstance(result.response_body, str) else ""
        safe_js_url = _strip_query_and_fragment(result.url)
        source_js_ref = hashlib.sha256(safe_js_url.encode("utf-8")).hexdigest()[:16]

        absolute_paths = _extract_api_paths(
            response_text,
            target_url=str(campaign.target_url or ""),
            max_endpoints=max_endpoints,
        )
        fragments, filtered_count = _extract_route_fragments(
            response_text,
            target_url=str(campaign.target_url or ""),
            max_route_fragments=max_route_fragments,
        )

        discovered: list[ToolResultObservationLite] = []
        seen_paths: set[str] = set()
        multi_match_skipped = 0
        fragment_no_graph_match = 0
        route_fragments_matched_count = 0
        extracted_from_fragments = 0

        for path in absolute_paths:
            if path in seen_paths:
                continue
            seen_paths.add(path)
            discovered.append(ToolResultObservationLite(
                observation_type="discovered_endpoint",
                confidence=0.6,
                details={
                    "source": "js_endpoint_extractor",
                    "path": path,
                    "url": _resolve_safe_url(str(campaign.target_url or ""), path),
                    "method": "GET",
                    "operation_id": "",
                    "source_js_ref": source_js_ref,
                    "source_observation_id": source_observation_id,
                    "extraction_mode": validation_mode,
                },
            ))

        for frag in fragments:
            matches = match_route_fragment(command.campaign_id, frag, "GET", 3)
            if len(matches) == 1:
                route_fragments_matched_count += 1
                extracted_from_fragments += 1
                m = matches[0]
                path = str(m.get("path_template") or "")
                if not path or path in seen_paths:
                    continue
                seen_paths.add(path)
                discovered.append(ToolResultObservationLite(
                    observation_type="discovered_endpoint",
                    confidence=0.65,
                    details={
                        "source": "js_endpoint_extractor",
                        "path": path,
                        "url": _resolve_safe_url(str(campaign.target_url or ""), path),
                        "method": str(m.get("method") or "GET"),
                        "operation_id": str(m.get("operation_id") or ""),
                        "source_js_ref": source_js_ref,
                        "source_observation_id": source_observation_id,
                        "extraction_mode": validation_mode,
                        "route_fragment": normalize_route_fragment_for_match(frag) or frag,
                        "openapi_match_hint": True,
                    },
                ))
            elif len(matches) > 1:
                multi_match_skipped += 1
            else:
                fragment_no_graph_match += 1

        endpoints_emitted_count = sum(
            1 for o in discovered if str(o.observation_type) == "discovered_endpoint"
        )
        endpoints_extracted_count = len(absolute_paths) + extracted_from_fragments

        reason_codes: list[str] = []
        if multi_match_skipped:
            reason_codes.append("fragment_multi_match_skipped")
        if fragment_no_graph_match:
            reason_codes.append("fragment_no_graph_match")
        if filtered_count:
            reason_codes.append("filtered_route_fragments")

        if endpoints_emitted_count > 0:
            result_code = "endpoints_extracted"
        elif len(fragments) > 0:
            result_code = "route_fragments_found"
        else:
            result_code = "no_api_paths_found"
            if not reason_codes:
                reason_codes.append("no_api_paths_found")

        marker_details = _marker_details(
            safe_js_url=safe_js_url,
            source_js_ref=source_js_ref,
            source_observation_id=source_observation_id,
            result=result_code,
            absolute_paths_count=len(absolute_paths),
            route_fragments_count=len(fragments),
            route_fragments_matched_count=route_fragments_matched_count,
            endpoints_extracted_count=endpoints_extracted_count,
            endpoints_emitted_count=endpoints_emitted_count,
            filtered_count=filtered_count,
            multi_match_skipped=multi_match_skipped,
            fragment_no_graph_match=fragment_no_graph_match,
            reason_codes=reason_codes,
        )

        observations: list[ToolResultObservationLite] = [
            ToolResultObservationLite(
                observation_type="js_endpoint_extraction_result",
                confidence=0.0,
                details=marker_details,
            ),
            *discovered,
        ]

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="js_endpoint_extraction_summary",
            content=marker_details,
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        success = 1 if 200 <= result.status_code <= 399 else 0
        client_error = 1 if 400 <= result.status_code <= 499 else 0
        server_error = 1 if result.status_code >= 500 else 0
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=1,
                success_count=success,
                client_error_count=client_error,
                server_error_count=server_error,
                duration_ms=duration_ms,
            ),
            requests=[ToolResultRequest(
                request_id="",
                role="",
                method="GET",
                url=safe_js_url,
                path_template=normalize_api_path(urlparse(safe_js_url).path or "/"),
            )],
            responses=[ToolResultResponse(
                request_id="",
                status_code=result.status_code,
            )],
            observations=observations,
            artifacts=[artifact],
        )

    @staticmethod
    def _failed_result(
        *,
        command: WorkerCommand,
        tool_run_id: str,
        duration_ms: int,
        error_type: str,
        message: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            errors=[ToolResultError(
                error_type=error_type,
                message=message,
                recoverable=False,
            )],
        )


def _marker_details(
    *,
    safe_js_url: str,
    source_js_ref: str,
    source_observation_id: str,
    result: str,
    absolute_paths_count: int,
    route_fragments_count: int,
    route_fragments_matched_count: int,
    endpoints_extracted_count: int,
    endpoints_emitted_count: int,
    filtered_count: int,
    multi_match_skipped: int,
    fragment_no_graph_match: int,
    reason_codes: list[str],
) -> dict[str, object]:
    return {
        "source": "js_endpoint_extractor",
        "js_url_sanitized": safe_js_url,
        "source_js_ref": source_js_ref,
        "source_observation_id": source_observation_id,
        "result": result,
        "absolute_paths_count": absolute_paths_count,
        "route_fragments_count": route_fragments_count,
        "route_fragments_matched_count": route_fragments_matched_count,
        "endpoints_extracted_count": endpoints_extracted_count,
        "endpoints_emitted_count": endpoints_emitted_count,
        "filtered_count": filtered_count,
        "multi_match_skipped": multi_match_skipped,
        "fragment_no_graph_match": fragment_no_graph_match,
        "reason_codes": list(reason_codes),
    }


def _extract_api_paths(response_text: str, *, target_url: str, max_endpoints: int) -> list[str]:
    seen: set[str] = set()
    extracted: list[str] = []
    for match in _PATH_RE.finditer(response_text or ""):
        raw_value = str(match.group("value") or "").strip()
        normalized = _normalize_extracted_value(raw_value, target_url=target_url)
        if not normalized:
            continue
        if normalized in seen:
            continue
        seen.add(normalized)
        extracted.append(normalized)
        if len(extracted) >= max_endpoints:
            break
    return extracted


def _extract_route_fragments(
    response_text: str,
    *,
    target_url: str,
    max_route_fragments: int,
) -> tuple[list[str], int]:
    """Return (unique fragments, filtered_count)."""
    seen: set[str] = set()
    out: list[str] = []
    filtered = 0
    target_host = (urlparse(str(target_url or "")).hostname or "").lower()
    for match in _ROUTE_FRAGMENT_RE.finditer(response_text or ""):
        raw = str(match.group(1) or "").strip()
        raw = raw.split("?", 1)[0].split("#", 1)[0]
        if "://" in raw:
            parsed = urlparse(raw)
            host = (parsed.hostname or "").lower()
            if host and host != target_host:
                filtered += 1
                continue
            raw = parsed.path or raw
        if raw.startswith("//"):
            filtered += 1
            continue
        if _TLD_SKIP.search(raw):
            filtered += 1
            continue
        if not _fragment_allowed_chars(raw):
            filtered += 1
            continue
        parts = [p for p in raw.strip("/").split("/") if p]
        if len(parts) < 2:
            filtered += 1
            continue
        if any(seg.lower() in _NOISE_SEGMENTS for seg in parts):
            filtered += 1
            continue
        key = raw.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(raw)
        if len(out) >= max_route_fragments:
            break
    return out, filtered


def _fragment_allowed_chars(value: str) -> bool:
    return bool(re.fullmatch(r"[a-zA-Z0-9_{}<>\./-]+", value))


def _normalize_extracted_value(raw_value: str, *, target_url: str) -> str:
    parsed_target = urlparse(str(target_url or ""))
    parsed = urlparse(str(raw_value or ""))
    if parsed.scheme:
        target_host = (parsed_target.hostname or "").lower()
        candidate_host = (parsed.hostname or "").lower()
        target_host_port = f"{target_host}:{parsed_target.port}" if parsed_target.port is not None else target_host
        candidate_host_port = f"{candidate_host}:{parsed.port}" if parsed.port is not None else candidate_host
        if candidate_host not in {target_host, target_host_port} and candidate_host_port not in {
            target_host,
            target_host_port,
        }:
            return ""
        path_value = parsed.path or "/"
    else:
        path_value = raw_value
    normalized = normalize_api_path(path_value)
    lowered = normalized.lower()
    if not any(lowered.startswith(prefix) for prefix in _ALLOWED_PREFIXES):
        return ""
    if is_static_or_service_asset(normalized):
        return ""
    return normalized


def _resolve_safe_url(target_url: str, path: str) -> str:
    parsed = urlparse(str(target_url or ""))
    if not parsed.scheme or not parsed.netloc:
        return path
    return sanitize_url_for_storage(
        urlunparse((parsed.scheme, parsed.netloc, normalize_api_path(path), "", "", ""))
    )


def _strip_query_and_fragment(url: str) -> str:
    safe = sanitize_url_for_storage(url)
    parsed = urlparse(safe)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))
