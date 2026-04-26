"""Phase 9A — single-request HTTP replay adapter."""
from __future__ import annotations

import time
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.auth_materializer import AuthMaterializer
    from backend.services.http.safe_http_client import SafeHttpClient, SafeHttpResult
    from backend.services.request_corpus_service import RequestCorpusService
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.auth_materializer import AuthMaterializer
    from services.http.safe_http_client import SafeHttpClient, SafeHttpResult
    from services.request_corpus_service import RequestCorpusService


class HttpReplayAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._auth = AuthMaterializer()
        self._corpus = RequestCorpusService()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs or {}
        role = str(inputs.get("auth_profile") or inputs.get("role") or "")

        auth, auth_error = self._auth.materialize(
            campaign,
            role,
            extra_headers=_dict(inputs.get("headers")),
            extra_cookies=_dict(inputs.get("cookies")),
        )
        if auth_error is not None:
            return self._failed_result(
                command,
                tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=auth_error.code,
                message=auth_error.message,
            )

        result = self._http.request(
            campaign,
            method=str(inputs.get("method") or "GET"),
            url=str(inputs.get("url") or ""),
            query=_dict(inputs.get("query")),
            headers=auth.headers if auth else _dict(inputs.get("headers")),
            cookies=auth.cookies if auth else _dict(inputs.get("cookies")),
            body=inputs.get("body"),
            timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
            max_response_bytes=int(inputs.get("max_response_bytes") or 1024 * 1024),
            follow_redirects=bool(inputs.get("follow_redirects") or False),
        )
        if result.error is not None:
            return self._failed_result(
                command,
                tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=result.error.code,
                message=result.error.message,
                details=result.error.details,
                safe_result=result,
            )

        request_id = self._store_exchange(
            command=command,
            tool_run_id=tool_run_id,
            inputs=inputs,
            role=role,
            safe_result=result,
        )
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="http_replay_exchange",
            content=_artifact_summary(result, request_id),
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
                request_id=request_id,
                role=role,
                method=result.method,
                url=result.url,
                path_template=str(inputs.get("path_template") or ""),
            )],
            responses=[ToolResultResponse(
                request_id=request_id,
                status_code=result.status_code,
            )],
            artifacts=[artifact],
        )

    def _store_exchange(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        inputs: dict[str, Any],
        role: str,
        safe_result: SafeHttpResult,
    ) -> str:
        item = self._corpus.add_exchange(
            campaign_id=command.campaign_id,
            method=safe_result.method,
            url=safe_result.url,
            headers=safe_result.request_headers_redacted,
            body=safe_result.request_body_redacted,
            status_code=safe_result.status_code,
            response_body=safe_result.response_body,
            response_content_type=safe_result.response_content_type,
            auth_profile=role,
            source="tool:http_replay_executor",
            source_tool_run_id=tool_run_id,
            operation_id=command.operation_id or str(inputs.get("operation_id") or ""),
            path_template=str(inputs.get("path_template") or ""),
        )
        return item.request_id

    def _failed_result(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        *,
        duration_ms: int,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
        safe_result: SafeHttpResult | None = None,
    ) -> ToolResult:
        artifacts = []
        if safe_result is not None:
            artifacts.append(self._artifacts.save_artifact(
                campaign_id=command.campaign_id,
                tool_run_id=tool_run_id,
                artifact_type="http_replay_error",
                content=_artifact_summary(safe_result, ""),
            ))
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            artifacts=artifacts,
            errors=[ToolResultError(
                error_type=error_type,
                message=message,
                recoverable=True,
            )],
        )


def _dict(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _artifact_summary(result: SafeHttpResult, request_id: str) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "method": result.method,
        "url": result.url,
        "status_code": result.status_code,
        "request_headers_redacted": result.request_headers_redacted,
        "request_cookies_redacted": result.request_cookies_redacted,
        "request_body_redacted": result.request_body_redacted,
        "response_content_type": result.response_content_type,
        "response_body_redacted": result.response_body,
        "error": result.error.__dict__ if result.error else None,
    }
