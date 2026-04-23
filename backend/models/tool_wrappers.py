from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from backend.models.testing import ExecutionContext, TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ExecutionContext, TaskModel


WrapperStatus = Literal["ok", "error", "partial"]


class ToolBudget(BaseModel):
    max_requests: int = 0
    used_requests: int = 0
    duration_sec: float = 0
    max_duration_sec: int | None = None
    concurrency: int = 1
    termination_reason: str | None = None


class ToolArtifacts(BaseModel):
    stdout_path: str = ""
    stderr_path: str = ""
    raw_report_paths: list[str] = Field(default_factory=list)
    replay_pack_path: str = ""


class ToolReproduction(BaseModel):
    method: str = "GET"
    url: str = ""
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Any = None


class ToolWrapperRequest(BaseModel):
    tool_name: str
    execution_context: ExecutionContext
    task: TaskModel | None = None
    run_id: str | None = None
    target_url: str | None = None
    openapi_url: str | None = None
    openapi_spec_path: str | None = None
    auth_contexts: list[dict[str, Any]] = Field(default_factory=list)
    roles_json: list[dict[str, Any]] = Field(default_factory=list)
    task_metadata: dict[str, Any] = Field(default_factory=dict)
    arguments: dict[str, Any] = Field(default_factory=dict)
    budgets: ToolBudget = Field(default_factory=ToolBudget)
    output_dir: str | None = None


class ToolWrapperResult(BaseModel):
    schema_version: str = "tool-wrapper-result/v1"
    tool_name: str
    source_task_id: str = ""
    worker_role: str = ""
    auth_context_name: str | None = None
    status: WrapperStatus = "partial"
    summary: str = ""
    signals: list[str] = Field(default_factory=list)
    http_trace_refs: list[str] = Field(default_factory=list)
    artifacts: ToolArtifacts = Field(default_factory=ToolArtifacts)
    candidate_findings: list[dict[str, Any]] = Field(default_factory=list)
    reproduction: ToolReproduction = Field(default_factory=ToolReproduction)
    budget: ToolBudget = Field(default_factory=ToolBudget)
    termination_reason: str | None = None
    fallback_reason: str | None = None
    error: str | None = None


class JudgeReadyEvidence(BaseModel):
    schema_version: str = "judge-ready-evidence/v1"
    task_id: str = ""
    source_task_id: str = ""
    worker_role: str = ""
    tool_name: str = ""
    auth_context_name: str | None = None
    hypothesis: str = ""
    signals: list[str] = Field(default_factory=list)
    candidate_finding: dict[str, Any] = Field(default_factory=dict)
    tool_summary: dict[str, Any] = Field(default_factory=dict)
    reproduction: dict[str, Any] = Field(default_factory=dict)
    artifacts: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)
    termination_reason: str | None = None
    notes: list[str] = Field(default_factory=list)
