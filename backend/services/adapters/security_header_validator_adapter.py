"""Phase 13B - security header validation adapter.

Validates a single ZAP passive security-header alert with one controlled
HTTP replay. It never creates EvidencePack, JudgeDecision, or Finding.
"""
from __future__ import annotations

import re
import time
from typing import Any

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
    from backend.services.request_corpus_service import redact_sensitive_data
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
    from services.request_corpus_service import redact_sensitive_data


_SUPPORTED_ALERTS: dict[str, set[str]] = {
    "x-frame-options": {
        "X-Frame-Options Header Not Set",
    },
    "x-content-type-options": {
        "X-Content-Type-Options Header Missing",
    },
    "content-security-policy": {
        "Content Security Policy (CSP) Header Not Set",
    },
    "strict-transport-security": {
        "Strict-Transport-Security Header Not Set",
    },
}

_XFO_SAFE_VALUES = {"deny", "sameorigin"}


class SecurityHeaderValidatorAdapter:
    def __init__(
        self,
        http_client: SafeHttpClient | None = None,
    ) -> None:
        self._http = http_client or SafeHttpClient()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs or {}
        method = str(inputs.get("method") or "GET").upper()
        request_url = str(inputs.get("request_url") or inputs.get("target_url") or "").strip()
        header_name = str(inputs.get("header_name") or "").strip()
        alert_name = str(inputs.get("alert_name") or "").strip()
        normalized_header = _normalize_header_name(header_name)
        validation_error = _validate_mapping(normalized_header, alert_name)
        if validation_error is not None:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=validation_error[0],
                message=validation_error[1],
            )

        result = self._http.request(
            campaign,
            method=method,
            url=request_url,
            timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
            max_response_bytes=int(inputs.get("max_response_bytes") or 262144),
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

        actual_value = self._header_value(result.response_headers_redacted, header_name)
        issue = _evaluate_issue(
            normalized_header=normalized_header,
            request_url=result.url,
            actual_value=actual_value,
        )
        observation = None
        if issue.issue_confirmed:
            observation = ToolResultObservationLite(
                observation_type="validated_security_header_issue",
                confidence=0.85,
                details={
                    "header_name": header_name,
                    "alert_name": alert_name,
                    "expected_state": "present_or_safe_value",
                    "actual_state": issue.actual_state,
                    "actual_value_redacted": issue.actual_value_redacted,
                    "request_id": "",
                    "operation_id": str(inputs.get("operation_id") or command.operation_id or ""),
                    "path_template": str(inputs.get("path_template") or ""),
                    "source_observation_id": str(inputs.get("source_observation_id") or ""),
                    "source_alert_name": alert_name,
                    "validation_mode": "single_replay_header_check",
                    "url": result.url,
                },
            )

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="security_header_validation_summary",
            content={
                "header_name": header_name,
                "alert_name": alert_name,
                "sanitized_url": result.url,
                "issue_confirmed": issue.issue_confirmed,
                "actual_state": issue.actual_state,
                "normalized_value": issue.actual_value_redacted if not issue.issue_confirmed else "",
                "status_code": result.status_code,
                "diagnostic_reason": issue.diagnostic_reason,
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
                url=result.url,
                path_template=str(inputs.get("path_template") or ""),
            )],
            responses=[ToolResultResponse(
                request_id="",
                status_code=result.status_code,
            )],
            observations=[observation] if observation is not None else [],
            artifacts=[artifact],
        )

    @staticmethod
    def _header_value(headers: dict[str, Any], header_name: str) -> str:
        target = header_name.lower()
        for key, value in (headers or {}).items():
            if str(key).lower() == target:
                return str(value or "")
        return ""

    def _failed_result(
        self,
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


class _IssueResult:
    def __init__(
        self,
        *,
        issue_confirmed: bool,
        actual_state: str,
        actual_value_redacted: str,
        diagnostic_reason: str = "",
    ) -> None:
        self.issue_confirmed = issue_confirmed
        self.actual_state = actual_state
        self.actual_value_redacted = actual_value_redacted
        self.diagnostic_reason = diagnostic_reason


def _normalize_header_name(header_name: str) -> str:
    return str(header_name or "").strip().lower()


def _validate_mapping(normalized_header: str, alert_name: str) -> tuple[str, str] | None:
    if normalized_header not in _SUPPORTED_ALERTS:
        return (
            "unsupported_security_header",
            f"Header '{normalized_header or ''}' is not supported by security_header_validator.",
        )
    if not str(alert_name or "").strip():
        return (
            "unsupported_alert_mapping",
            f"Alert '{alert_name}' is not supported for header '{normalized_header}'.",
        )
    if alert_name not in _SUPPORTED_ALERTS[normalized_header]:
        return (
            "unsupported_alert_mapping",
            f"Alert '{alert_name}' is not supported for header '{normalized_header}'.",
        )
    return None


def _evaluate_issue(
    *,
    normalized_header: str,
    request_url: str,
    actual_value: str,
) -> _IssueResult:
    cleaned_value = _clean_header_value(actual_value)
    lowered = cleaned_value.lower()

    if normalized_header == "x-frame-options":
        if not cleaned_value:
            return _IssueResult(issue_confirmed=True, actual_state="missing", actual_value_redacted="")
        if lowered not in _XFO_SAFE_VALUES:
            return _IssueResult(
                issue_confirmed=True,
                actual_state="unsafe_value",
                actual_value_redacted=cleaned_value,
            )
        return _IssueResult(issue_confirmed=False, actual_state="safe", actual_value_redacted=cleaned_value)

    if normalized_header == "x-content-type-options":
        if not cleaned_value:
            return _IssueResult(issue_confirmed=True, actual_state="missing", actual_value_redacted="")
        if lowered != "nosniff":
            return _IssueResult(
                issue_confirmed=True,
                actual_state="unsafe_value",
                actual_value_redacted=cleaned_value,
            )
        return _IssueResult(issue_confirmed=False, actual_state="safe", actual_value_redacted=cleaned_value)

    if normalized_header == "content-security-policy":
        if not cleaned_value:
            state = "missing" if actual_value == "" else "empty"
            return _IssueResult(issue_confirmed=True, actual_state=state, actual_value_redacted="")
        return _IssueResult(issue_confirmed=False, actual_state="safe", actual_value_redacted="")

    if normalized_header == "strict-transport-security":
        safe_url = sanitize_url_for_storage(request_url)
        if not safe_url.lower().startswith("https://"):
            return _IssueResult(
                issue_confirmed=False,
                actual_state="not_applicable",
                actual_value_redacted="",
                diagnostic_reason="hsts_not_applicable_to_http",
            )
        if not cleaned_value:
            state = "missing" if actual_value == "" else "empty"
            return _IssueResult(issue_confirmed=True, actual_state=state, actual_value_redacted="")
        return _IssueResult(issue_confirmed=False, actual_state="safe", actual_value_redacted=_truncate(cleaned_value))

    return _IssueResult(issue_confirmed=False, actual_state="unsupported", actual_value_redacted="")


def _clean_header_value(value: str) -> str:
    safe = _truncate(str(value or "").strip())
    _, redacted = redact_sensitive_data(None, {"value": safe})
    return str((redacted or {}).get("value") or "")


def _truncate(value: str, limit: int = 120) -> str:
    trimmed = re.sub(r"\s+", " ", value).strip()
    return trimmed[:limit]
