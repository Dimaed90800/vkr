"""Phase API8-2 - bounded cookie flag validator adapter.

Performs one safe GET replay and evaluates sanitized Set-Cookie metadata only.
It never stores raw Set-Cookie values, clear cookie names, full headers, bodies,
or tokens.
"""
from __future__ import annotations

import time
from typing import Any
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
    from services.artifact_store import ArtifactStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage


_STRONG_ISSUES = frozenset({
    "missing_httponly",
    "missing_secure",
    "samesite_none_without_secure",
})


class CookieFlagValidatorAdapter:
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
        method = str(inputs.get("method") or "GET").upper()
        if method != "GET":
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="cookie_method_not_allowed",
                message="cookie_flag_validator supports only GET.",
            )

        request_url = str(inputs.get("request_url") or inputs.get("target_url") or "").strip()
        if not request_url:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="missing_request_url",
                message="request_url (or target_url) is required for cookie_flag_validator.",
            )

        validation_mode = str(inputs.get("validation_mode") or "baseline_cookie_flag_check").strip()
        max_response_bytes = int(inputs.get("max_response_bytes") or 262144)
        timeout_sec = min(command.budget.timeout_sec, campaign.limits.max_duration_sec, 15)

        result = self._http.request(
            campaign,
            method=method,
            url=request_url,
            timeout_sec=timeout_sec,
            max_response_bytes=max_response_bytes,
            follow_redirects=False,
        )
        if result.error is not None:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=result.error.code,
                message=result.error.message,
            )

        safe_request_url = _url_without_query(result.url)
        observations: list[ToolResultObservationLite] = []
        issue_code_counts: dict[str, int] = {}
        affected_cookies_count = 0
        seen_keys: set[tuple[str, tuple[str, ...]]] = set()
        for cookie_summary in result.cookie_summaries or []:
            issue_codes = _strong_issue_codes(cookie_summary)
            for code in issue_codes:
                issue_code_counts[code] = int(issue_code_counts.get(code, 0)) + 1
            if not issue_codes:
                continue
            affected_cookies_count += 1
            cookie_hash = str(cookie_summary.get("cookie_name_hash") or "")
            dedup_key = (cookie_hash, tuple(sorted(issue_codes)))
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            observations.append(ToolResultObservationLite(
                observation_type="validated_cookie_flag_issue",
                confidence=0.8,
                details={
                    "tool_name": "cookie_flag_validator",
                    "operation_id": str(inputs.get("operation_id") or command.operation_id or ""),
                    "path_template": str(inputs.get("path_template") or ""),
                    "request_url": safe_request_url,
                    "validation_mode": validation_mode or "baseline_cookie_flag_check",
                    "status_code": result.status_code,
                    "cookie_name_hash": cookie_hash,
                    "issue_codes": list(issue_codes),
                    "has_httponly": cookie_summary.get("has_httponly") is True,
                    "has_secure": cookie_summary.get("has_secure") is True,
                    "samesite_state": str(cookie_summary.get("samesite_state") or "missing"),
                    "is_https": cookie_summary.get("is_https") is True,
                    "security_relevance": "medium",
                    "recommended_next_action": "prove_cookie_flag_misconfiguration",
                },
            ))

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="cookie_flag_probe_summary",
            content={
                "cookies_seen_count": len(result.cookie_summaries or []),
                "affected_cookies_count": affected_cookies_count,
                "issue_code_counts": issue_code_counts,
                "validation_mode": validation_mode or "baseline_cookie_flag_check",
                "request_url": safe_request_url,
            },
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
                success_count=1 if 200 <= result.status_code <= 399 else 0,
                client_error_count=1 if 400 <= result.status_code <= 499 else 0,
                server_error_count=1 if result.status_code >= 500 else 0,
                duration_ms=duration_ms,
            ),
            requests=[ToolResultRequest(
                request_id="",
                role=str(inputs.get("auth_profile") or ""),
                method=result.method,
                url=safe_request_url,
                path_template=str(inputs.get("path_template") or ""),
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


def _strong_issue_codes(cookie_summary: dict[str, Any]) -> list[str]:
    issue_codes: list[str] = []
    has_httponly = cookie_summary.get("has_httponly") is True
    has_secure = cookie_summary.get("has_secure") is True
    samesite_state = str(cookie_summary.get("samesite_state") or "missing").lower()
    is_https = cookie_summary.get("is_https") is True

    if not has_httponly:
        issue_codes.append("missing_httponly")
    if is_https and not has_secure:
        issue_codes.append("missing_secure")
    if samesite_state == "none" and not has_secure:
        issue_codes.append("samesite_none_without_secure")

    deduped: list[str] = []
    for code in issue_codes:
        if code in _STRONG_ISSUES and code not in deduped:
            deduped.append(code)
    return deduped


def _url_without_query(url: str) -> str:
    safe = sanitize_url_for_storage(url)
    parsed = urlparse(safe)
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path, "", "", ""))
