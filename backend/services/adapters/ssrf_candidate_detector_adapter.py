"""Diagnostic-only SSRF candidate detector.

Analyzes safe OpenAPI-derived field summaries and emits ssrf_candidate_signal
observations without performing any HTTP requests or SSRF callbacks.
"""
from __future__ import annotations

import time
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore


class SsrfCandidateDetectorAdapter:
    def __init__(self) -> None:
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        _ = campaign
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        operation_id = str(command.operation_id or inputs.get("operation_id") or "").strip()
        method = str(inputs.get("method") or "GET").strip().upper() or "GET"
        path = str(inputs.get("path_template") or inputs.get("path") or "").strip()
        validation_mode = str(
            inputs.get("validation_mode") or "ssrf_candidate_detection"
        ).strip() or "ssrf_candidate_detection"
        candidate_fields_raw = inputs.get("candidate_fields")
        candidate_fields = (
            [item for item in candidate_fields_raw if isinstance(item, dict)]
            if isinstance(candidate_fields_raw, list)
            else []
        )
        if not operation_id or not path:
            return self._failed_result(
                command=command,
                tool_run_id=tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type="missing_operation_context",
                message="operation_id and path_template are required for ssrf_candidate_detector.",
            )

        observations: list[ToolResultObservationLite] = []
        seen_pairs: set[tuple[str, str]] = set()
        for row in candidate_fields[:20]:
            field_name = str(row.get("field_name") or "").strip()
            field_path = str(row.get("field_path") or "").strip()
            if not field_name or not field_path:
                continue
            pair = (field_name, field_path)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            observations.append(
                ToolResultObservationLite(
                    observation_type="ssrf_candidate_signal",
                    confidence=0.8 if str(row.get("confidence") or "").strip().lower() == "high" else 0.6,
                    details={
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "schema_type": str(row.get("schema_type") or "string").strip() or "string",
                        "schema_format": str(row.get("schema_format") or "").strip(),
                        "confidence": str(row.get("confidence") or "medium").strip() or "medium",
                        "reason_codes": _safe_list(row.get("reason_codes")),
                        "validation_mode": validation_mode,
                        "security_relevance": "medium",
                        "recommended_next_action": "validate_ssrf_candidate_safely",
                    },
                ),
            )

        artifact_content = {
            "tool_name": "ssrf_candidate_detector",
            "operation_id": operation_id,
            "method": method,
            "path": path,
            "validation_mode": validation_mode,
            "candidate_fields_count": len(candidate_fields),
            "emitted_signals_count": len(observations),
            "reason_codes": _aggregate_reason_codes(candidate_fields),
            "result": "ssrf_candidates_found" if observations else "no_ssrf_candidate_fields",
        }
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="ssrf_candidate_detection_summary",
            content=artifact_content,
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
                request_count=0,
                success_count=1,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
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
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )


def _safe_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    out: list[str] = []
    for item in value:
        text = str(item).strip()
        if text:
            out.append(text[:120])
    return out[:10]


def _aggregate_reason_codes(candidate_fields: list[dict[str, Any]]) -> list[str]:
    seen: list[str] = []
    for item in candidate_fields:
        for code in _safe_list(item.get("reason_codes")):
            if code not in seen:
                seen.append(code)
    return seen[:10]
