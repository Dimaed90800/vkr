"""Phase 5 — NoopAdapter.

Fully synthetic adapter that does NOT perform real network I/O.
Used only for `noop_tool` and `custom_request_executor` in the
Phase 5 skeleton path.

This adapter must NOT be used as a fallback for every tool.
Unknown/unsupported tools must receive a controlled error, not
a fake success from this adapter.
"""
from __future__ import annotations

import time

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore


class NoopAdapter:
    def __init__(self) -> None:
        self._artifact_store = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)

        synthetic_request = ToolResultRequest(
            request_id=f"req_synthetic_{tool_run_id[:12]}",
            role=command.inputs.get("owner_role", "synthetic"),
            method=command.inputs.get("method", "GET"),
            url=command.inputs.get("url", campaign.target_url),
            path_template=command.inputs.get("path_template", ""),
        )
        synthetic_response = ToolResultResponse(
            request_id=synthetic_request.request_id,
            status_code=200,
        )

        exchange = {
            "request": synthetic_request.model_dump(mode="json"),
            "response": synthetic_response.model_dump(mode="json"),
            "synthetic": True,
        }
        artifact_ref = self._artifact_store.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="http_exchange",
            content=exchange,
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
                success_count=1,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
            requests=[synthetic_request],
            responses=[synthetic_response],
            observations=[],
            artifacts=[artifact_ref],
            errors=[],
        )
