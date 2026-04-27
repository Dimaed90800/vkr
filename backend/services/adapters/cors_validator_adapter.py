"""Phase 19A-1 - bounded CORS validator adapter.

Validates CORS policy with a fixed cross-origin probe and emits only sanitized
metadata. It never stores raw bodies, full headers, auth/cookie values, or
creates Evidence/Judge/Finding artifacts directly.
"""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlparse

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
    from backend.services.http.safe_http_client import SafeHttpClient
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
    from services.http.safe_http_client import SafeHttpClient


_DEFAULT_ORIGIN = "https://evil.example.invalid"
_DEFAULT_ORIGIN_LABEL = "evil_example_invalid"
_ALLOWED_METHODS = {"GET", "OPTIONS"}
_STRONG_ISSUES = {
    "cors_wildcard_with_credentials",
    "cors_origin_reflection_with_credentials",
}


class CorsValidatorAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        method = str(inputs.get("method") or "GET").upper()
        if method not in _ALLOWED_METHODS:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="cors_method_not_allowed",
                message="cors_validator supports only GET or OPTIONS.",
            )

        request_url = str(inputs.get("request_url") or inputs.get("target_url") or "").strip()
        if not request_url:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="missing_request_url",
                message="request_url (or target_url) is required for cors_validator.",
            )

        origin_probe = str(inputs.get("origin_probe") or _DEFAULT_ORIGIN).strip() or _DEFAULT_ORIGIN
        validation_mode = str(inputs.get("validation_mode") or "single_replay_cors_check").strip()
        max_response_bytes = int(inputs.get("max_response_bytes") or 262144)
        timeout_sec = min(command.budget.timeout_sec, campaign.limits.max_duration_sec, 15)

        request_count = 0
        result = self._http.request(
            campaign,
            method=method,
            url=request_url,
            headers={"Origin": origin_probe},
            body=None,
            timeout_sec=timeout_sec,
            max_response_bytes=max_response_bytes,
            follow_redirects=False,
        )
        request_count += 1

        if result.error is not None:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=result.error.code,
                message=result.error.message,
            )

        policy = _extract_cors_policy(
            headers=result.response_headers_redacted or {},
            origin_probe=origin_probe,
        )
        strong = any(code in _STRONG_ISSUES for code in policy["issue_codes"])
        obs: list[ToolResultObservationLite] = []
        if strong:
            obs.append(ToolResultObservationLite(
                observation_type="validated_cors_issue",
                confidence=0.80,
                details={
                    "tool_name": "cors_validator",
                    "operation_id": str(inputs.get("operation_id") or command.operation_id or ""),
                    "path_template": str(inputs.get("path_template") or ""),
                    "request_url": _url_without_query(result.url),
                    "origin_probe_label": _DEFAULT_ORIGIN_LABEL,
                    "acao_state": policy["acao_state"],
                    "acac_present": policy["acac_present"],
                    "vary_origin_present": policy["vary_origin_present"],
                    "origin_reflection_detected": policy["origin_reflection_detected"],
                    "issue_codes": list(policy["issue_codes"]),
                    "validation_mode": validation_mode or "single_replay_cors_check",
                    "request_count": request_count,
                    "status_code": result.status_code,
                    "security_relevance": "medium",
                    "recommended_next_action": "prove_cors_misconfiguration",
                },
            ))

        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=request_count,
                success_count=1 if 200 <= result.status_code <= 399 else 0,
                client_error_count=1 if 400 <= result.status_code <= 499 else 0,
                server_error_count=1 if result.status_code >= 500 else 0,
                duration_ms=duration_ms,
            ),
            requests=[ToolResultRequest(
                request_id="",
                role=str(inputs.get("auth_profile") or ""),
                method=result.method,
                url=result.url,
                path_template=str(inputs.get("path_template") or ""),
            )],
            responses=[ToolResultResponse(
                request_id="",
                status_code=result.status_code,
            )],
            observations=obs,
            artifacts=[],
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


def _extract_cors_policy(headers: dict[str, Any], origin_probe: str) -> dict[str, Any]:
    acao = _get_header(headers, "Access-Control-Allow-Origin")
    acac = _get_header(headers, "Access-Control-Allow-Credentials")
    vary = _get_header(headers, "Vary")
    acao_clean = str(acao or "").strip()
    acac_present = str(acac or "").strip().lower() == "true"
    vary_origin_present = "origin" in str(vary or "").lower()
    origin_reflection_detected = acao_clean == str(origin_probe or "").strip()

    if not acao_clean:
        acao_state = "missing"
    elif acao_clean == "*":
        acao_state = "wildcard"
    elif origin_reflection_detected:
        acao_state = "reflective"
    elif acao_clean.startswith("http://") or acao_clean.startswith("https://"):
        acao_state = "specific"
    else:
        acao_state = "other"

    issue_codes: list[str] = []
    if acao_state == "wildcard" and acac_present:
        issue_codes.append("cors_wildcard_with_credentials")
    if origin_reflection_detected and acac_present:
        issue_codes.append("cors_origin_reflection_with_credentials")
    if origin_reflection_detected and not acac_present:
        issue_codes.append("cors_overly_permissive_origin")
    if origin_reflection_detected and not vary_origin_present:
        issue_codes.append("cors_missing_vary_origin_when_reflecting")

    return {
        "acao_state": acao_state,
        "acac_present": bool(acac_present),
        "vary_origin_present": bool(vary_origin_present),
        "origin_reflection_detected": bool(origin_reflection_detected),
        "issue_codes": issue_codes[:10],
    }


def _get_header(headers: dict[str, Any], name: str) -> str:
    target = str(name or "").lower()
    for key, value in (headers or {}).items():
        if str(key or "").lower() == target:
            return str(value or "")
    return ""


def _url_without_query(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
