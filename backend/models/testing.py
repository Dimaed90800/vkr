from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ExecutionContext(BaseModel):
    toolbox_url: str | None = None
    target_url: HttpUrl
    openapi_url: str | None = None
    openapi_spec_text: str | None = None
    roles: list[dict[str, Any]] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    max_requests: int = 100
    max_duration_sec: int = 900
    max_retries_per_task: int = 1
    start_timestamp: str | None = None
    user_prompt: str | None = None


class AuthContext(BaseModel):
    owner_role: str | None = None
    other_role: str | None = None
    token_strategy: str | None = None


class TaskParams(BaseModel):
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    body_fields: list[str] = Field(default_factory=list)
    object_id_candidates: list[str | int] = Field(default_factory=list)
    selected_object_id: str | int | None = None
    requires_object_id_enrichment: bool = False
    object_param_name: str | None = None


class TaskModel(BaseModel):
    id: str
    class_name: str = Field(..., alias="class")
    subtype: str
    endpoint: str
    method: str
    params: TaskParams = Field(default_factory=TaskParams)
    auth_context: AuthContext = Field(default_factory=AuthContext)
    hypothesis: str
    priority: int = 50
    retry_count: int = 0
    rework_hint: str | None = None
    status: str = "pending"
    allowed_tools: list[str] = Field(default_factory=list)

    model_config = {"populate_by_name": True}


class ToolTestRequest(BaseModel):
    execution_context: ExecutionContext
    task: TaskModel
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class Artifact(BaseModel):
    type: str
    value: Any


class ToolTestResponse(BaseModel):
    request_summary: dict[str, Any] = Field(default_factory=dict)
    response_summary: dict[str, Any] = Field(default_factory=dict)
    raw_status: str = "ok"
    indicators: list[str] = Field(default_factory=list)
    artifacts: list[Artifact] = Field(default_factory=list)
