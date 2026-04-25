"""Phase 5 — ToolRun and ToolResult v1 data contracts.

ToolRun tracks the lifecycle of a single tool execution.
ToolResult is the normalized output produced when a ToolRun finishes.

These models do NOT create Observations (Phase 5.6), EvidencePacks,
Judge inputs, or confirmed findings.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ToolRunStatus(str, Enum):
    accepted = "accepted"
    queued = "queued"
    running = "running"
    finished = "finished"
    failed = "failed"
    timeout = "timeout"
    cancelled = "cancelled"
    skipped = "skipped"


class ToolExecutionMode(str, Enum):
    sync = "sync"
    async_ = "async"


class ToolArtifactRef(BaseModel):
    artifact_id: str = ""
    artifact_type: str = ""
    path: str = ""
    size_bytes: int = 0


class ToolRunProgress(BaseModel):
    requests_sent: int = 0
    max_requests: int = 0
    elapsed_sec: float = 0.0


class ToolRun(BaseModel):
    schema_version: str = "tool-run/v1"
    tool_run_id: str
    campaign_id: str
    command_id: str = ""
    task_id: str = ""
    tool_name: str
    execution_mode: ToolExecutionMode = ToolExecutionMode.sync
    status: ToolRunStatus = ToolRunStatus.accepted
    started_at: str = ""
    finished_at: str = ""
    progress: ToolRunProgress = Field(default_factory=ToolRunProgress)
    result_ready: bool = False
    artifact_refs: list[ToolArtifactRef] = Field(default_factory=list)
    error: str | None = None


class ToolResultSummary(BaseModel):
    request_count: int = 0
    success_count: int = 0
    client_error_count: int = 0
    server_error_count: int = 0
    duration_ms: int = 0


class ToolResultRequest(BaseModel):
    request_id: str = ""
    role: str = ""
    method: str = "GET"
    url: str = ""
    path_template: str = ""


class ToolResultResponse(BaseModel):
    request_id: str = ""
    status_code: int = 0


class ToolResultObservationLite(BaseModel):
    """Lightweight tool signal — NOT the Phase 5.6 Observation model."""
    observation_type: str = ""
    confidence: float = 0.0
    details: dict[str, Any] = Field(default_factory=dict)


class ToolResultError(BaseModel):
    error_type: str = ""
    message: str = ""
    recoverable: bool = False


class ToolResult(BaseModel):
    schema_version: str = "tool-result/v1"
    tool_run_id: str
    campaign_id: str
    task_id: str = ""
    command_id: str = ""
    tool_name: str
    status: str = "finished"
    summary: ToolResultSummary = Field(default_factory=ToolResultSummary)
    requests: list[ToolResultRequest] = Field(default_factory=list)
    responses: list[ToolResultResponse] = Field(default_factory=list)
    observations: list[ToolResultObservationLite] = Field(default_factory=list)
    artifacts: list[ToolArtifactRef] = Field(default_factory=list)
    errors: list[ToolResultError] = Field(default_factory=list)


class ToolRunStartRequest(BaseModel):
    """Request body for POST /v1/tools/runs/start."""
    command: dict[str, Any] = Field(default_factory=dict)
    execution_mode: str | None = None


class ToolRunStartResponse(BaseModel):
    tool_run_id: str
    campaign_id: str
    task_id: str = ""
    command_id: str = ""
    tool_name: str
    execution_mode: str = "sync"
    status: str = "finished"
    result: ToolResult | None = None
    tool_run: ToolRun | None = None
