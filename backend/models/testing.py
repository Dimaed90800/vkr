from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ExecutionContext(BaseModel):
    toolbox_url: str | None = None
    target_url: HttpUrl
    run_id: str | None = None
    root_trace_id: str | None = None
    openapi_url: str | None = None
    openapi_spec_text: str | None = None
    roles: list[dict[str, Any]] = Field(default_factory=list)
    discovered_auth_endpoints: list[dict[str, Any]] = Field(default_factory=list)
    allowed_hosts: list[str] = Field(default_factory=list)
    traffic_requests: list[dict[str, Any]] = Field(default_factory=list)
    max_requests: int = 100
    max_duration_sec: int = 900
    max_retries_per_task: int = 1
    start_timestamp: str | None = None
    user_prompt: str | None = None
    capabilities: dict[str, bool] = Field(default_factory=dict)
    harvested_object_ids: list[str] = Field(default_factory=list)
    harvested_links: list[str] = Field(default_factory=list)
    prepared_objects: dict[str, Any] = Field(default_factory=dict)
    workflow_context: dict[str, Any] = Field(default_factory=dict)
    graph_state: dict[str, Any] = Field(default_factory=dict)


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


class TaskPrerequisites(BaseModel):
    requires_auth_context: bool = False
    requires_object_id: bool = False
    requires_valid_baseline: bool = False
    requires_success_path: bool = False
    requires_workflow_state: bool = False
    requires_creator_candidate: bool = False
    requires_list_candidate: bool = False


class ToolPreference(BaseModel):
    preferred_tool: str | None = None
    fallback_tools: list[str] = Field(default_factory=list)
    artifact_requirements: list[str] = Field(default_factory=list)
    budget_profile: str = "balanced"


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
    readiness: str = "ready_to_test"
    required_capabilities: list[str] = Field(default_factory=list)
    prerequisites: TaskPrerequisites = Field(default_factory=TaskPrerequisites)
    preparation_options: list[str] = Field(default_factory=list)
    test_strategy: str | None = None
    strategy_family: str | None = None
    capability_state: dict[str, bool] = Field(default_factory=dict)
    context_hints: dict[str, Any] = Field(default_factory=dict)
    hypothesis_family: str | None = None
    expected_evidence: list[str] = Field(default_factory=list)
    evidence_feasibility: float = 0.0
    noise_risk: float = 0.0
    recommended_next_step: str | None = None
    parent_task_id: str | None = None
    origin_reason: str | None = None
    followup_generation: int = 0
    failed_strategy: str | None = None
    payload_family: str | None = None
    resource_family: str | None = None
    context_source: str | None = None
    worker_role: str | None = None
    preferred_tool: str | None = None
    fallback_tools: list[str] = Field(default_factory=list)
    artifact_requirements: list[str] = Field(default_factory=list)
    budget_profile: str = "balanced"
    tool_preference: ToolPreference = Field(default_factory=ToolPreference)

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
    identities: list[dict[str, Any]] = Field(default_factory=list)
    created_object: dict[str, Any] | None = None
