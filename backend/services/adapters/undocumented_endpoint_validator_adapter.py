"""Safe one-shot validator for runtime-discovered undocumented endpoints."""
from __future__ import annotations

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
    from backend.services.artifact_store import ArtifactStore
    from backend.services.http.safe_http_client import SafeHttpClient
    from backend.services.api_graph_path_matcher import normalize_api_path
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
    from services.http.safe_http_client import SafeHttpClient
    from services.api_graph_path_matcher import normalize_api_path


class UndocumentedEndpointValidatorAdapter:
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
        method = str(inputs.get("method") or "GET").strip().upper() or "GET"
        if method not in {"GET", "HEAD"}:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="undocumented_method_not_allowed",
                message="undocumented_endpoint_validator supports only GET or HEAD.",
            )

        request_url = str(inputs.get("request_url") or "").strip()
        if not request_url:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="missing_request_url",
                message="request_url is required for undocumented_endpoint_validator.",
            )

        validation_mode = str(
            inputs.get("validation_mode") or "one_shot_undocumented_endpoint_check"
        ).strip()
        path = normalize_api_path(str(inputs.get("path") or request_url))
        timeout_sec = min(command.budget.timeout_sec, campaign.limits.max_duration_sec, 15)
        max_response_bytes = int(inputs.get("max_response_bytes") or 262144)

        result = self._http.request(
            campaign,
            method=method,
            url=request_url,
            timeout_sec=timeout_sec,
            max_response_bytes=max_response_bytes,
            follow_redirects=False,
        )
        status_code = _get_status_code(result)
        if result.error is not None:
            if result.error.code == "response_too_large":
                if status_code is not None and status_code != 404:
                    return self._finished_with_status_metadata(
                        command=command,
                        tool_run_id=tool_run_id,
                        start_ms=start_ms,
                        method=method,
                        path=path,
                        safe_url=_strip_query_and_fragment(result.url),
                        status_code=status_code,
                        source_observation_id=str(inputs.get("source_observation_id") or ""),
                        validation_mode=validation_mode,
                        response_truncated=True,
                        reason_codes=["response_too_large_metadata_only"],
                        outcome="accessible",
                    )
                if status_code is not None and status_code == 404:
                    return self._finished_with_status_metadata(
                        command=command,
                        tool_run_id=tool_run_id,
                        start_ms=start_ms,
                        method=method,
                        path=path,
                        safe_url=_strip_query_and_fragment(result.url),
                        status_code=status_code,
                        source_observation_id=str(inputs.get("source_observation_id") or ""),
                        validation_mode=validation_mode,
                        response_truncated=True,
                        reason_codes=["response_too_large_404"],
                        outcome="not_found",
                    )
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=result.error.code,
                message=result.error.message,
            )

        safe_url = _strip_query_and_fragment(result.url)
        normalized_status = int(status_code or 0)
        outcome = "accessible" if normalized_status and normalized_status != 404 else "not_found"
        reason_codes = [] if outcome == "accessible" else ["not_found"]
        observations: list[ToolResultObservationLite] = []
        if normalized_status and normalized_status != 404:
            observations.append(ToolResultObservationLite(
                observation_type="undocumented_endpoint_signal",
                confidence=0.8,
                details={
                    "method": method,
                    "path": path,
                    "url_sanitized": safe_url,
                    "status_code": normalized_status,
                    "source": "zap_discovery_passive",
                    "source_observation_id": str(inputs.get("source_observation_id") or ""),
                    "openapi_match": False,
                    "matched_operation_id": "",
                    "is_static_asset": False,
                    "validation_mode": validation_mode,
                    "security_relevance": "medium",
                    "recommended_next_action": "validate_undocumented_endpoint_inventory",
                },
            ))

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="undocumented_endpoint_validation_summary",
            content={
                "method": method,
                "path": path,
                "status_code": normalized_status,
                "result": outcome,
                "reason_codes": reason_codes,
            },
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        success = 1 if 200 <= normalized_status <= 399 else 0
        client_error = 1 if 400 <= normalized_status <= 499 else 0
        server_error = 1 if normalized_status >= 500 else 0
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
                method=method,
                url=safe_url,
                path_template=path,
            )],
            responses=[ToolResultResponse(
                request_id="",
                status_code=normalized_status,
            )],
            observations=observations,
            artifacts=[artifact],
        )

    def _finished_with_status_metadata(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        method: str,
        path: str,
        safe_url: str,
        status_code: int,
        source_observation_id: str,
        validation_mode: str,
        response_truncated: bool,
        reason_codes: list[str],
        outcome: str,
    ) -> ToolResult:
        observations: list[ToolResultObservationLite] = []
        if status_code and status_code != 404:
            observations.append(ToolResultObservationLite(
                observation_type="undocumented_endpoint_signal",
                confidence=0.8,
                details={
                    "method": method,
                    "path": path,
                    "url_sanitized": safe_url,
                    "status_code": status_code,
                    "source": "zap_discovery_passive",
                    "source_observation_id": source_observation_id,
                    "openapi_match": False,
                    "matched_operation_id": "",
                    "is_static_asset": False,
                    "validation_mode": validation_mode,
                    "security_relevance": "medium",
                    "recommended_next_action": "validate_undocumented_endpoint_inventory",
                    "response_truncated": response_truncated,
                    "reason_codes": reason_codes,
                },
            ))
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="undocumented_endpoint_validation_summary",
            content={
                "method": method,
                "path": path,
                "status_code": status_code,
                "result": outcome,
                "reason_codes": reason_codes,
            },
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        success = 1 if 200 <= status_code <= 399 else 0
        client_error = 1 if 400 <= status_code <= 499 else 0
        server_error = 1 if status_code >= 500 else 0
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
                method=method,
                url=safe_url,
                path_template=path,
            )],
            responses=[ToolResultResponse(
                request_id="",
                status_code=status_code,
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


def _strip_query_and_fragment(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", "", ""))


def _coerce_int(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _get_status_code(result: object) -> int | None:
    code = _coerce_int(getattr(result, "status_code", None))
    if code is not None:
        return code
    error = getattr(result, "error", None)
    if error is None:
        return None
    code = _coerce_int(getattr(error, "status_code", None))
    if code is not None:
        return code
    details = getattr(error, "details", None)
    if isinstance(details, dict):
        code = _coerce_int(details.get("status_code"))
        if code is not None:
            return code
    metadata = getattr(error, "metadata", None)
    if isinstance(metadata, dict):
        code = _coerce_int(metadata.get("status_code"))
        if code is not None:
            return code
    if isinstance(error, dict):
        code = _coerce_int(error.get("status_code"))
        if code is not None:
            return code
        details_dict = error.get("details")
        if isinstance(details_dict, dict):
            code = _coerce_int(details_dict.get("status_code"))
            if code is not None:
                return code
        metadata_dict = error.get("metadata")
        if isinstance(metadata_dict, dict):
            code = _coerce_int(metadata_dict.get("status_code"))
            if code is not None:
                return code
    return None
