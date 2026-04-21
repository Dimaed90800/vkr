from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from backend.models.api_surface import NormalizedApiSurface
    from backend.models.scheduling import FairnessConfig, SchedulerState
    from backend.models.synthesized_context import SynthesizedSecurityContext
    from backend.models.testing import ExecutionContext, TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface
    from models.scheduling import FairnessConfig, SchedulerState
    from models.synthesized_context import SynthesizedSecurityContext
    from models.testing import ExecutionContext, TaskModel


RoutingMode = Literal["backend_only", "hybrid", "llm_only", "mvp_openapi"]


class PlannerStats(BaseModel):
    generated_total: int = 0
    returned_total: int = 0
    router_candidate_total: int = 0


class PlannerMetadata(BaseModel):
    used_backend_generation: bool = False
    llm_router_required: bool = False
    filtered_duplicates: int = 0
    filtered_inactive: int = 0
    filtered_requires_enrichment: int = 0
    target_url: str | None = None
    notes: list[str] = Field(default_factory=list)
    scheduling_reason: str | None = None
    deferred_classes: list[str] = Field(default_factory=list)
    capabilities: dict[str, bool] = Field(default_factory=dict)
    synthesized_context_present: bool = False


def fresh_runtime_scheduler_state() -> SchedulerState:
    return SchedulerState(
        class_budget_used={},
        class_tasks_completed={},
        class_retries_used={},
        consecutive_class_count=0,
        last_executed_class=None,
        completed_task_fingerprints=[],
        confirmed_finding_fingerprints=[],
    )


class TaskPlanningRequest(BaseModel):
    execution_context: ExecutionContext | None = None
    normalized_surface: NormalizedApiSurface | None = None
    synthesized_security_context: SynthesizedSecurityContext | None = None
    generated_tasks: list[TaskModel] = Field(default_factory=list)
    routing_mode: RoutingMode = "backend_only"
    fairness_config: FairnessConfig = Field(default_factory=FairnessConfig)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)


class TaskPlanningResponse(BaseModel):
    routing_mode: RoutingMode
    planner_summary: str
    final_task_queue: list[TaskModel] = Field(default_factory=list)
    router_candidate_queue: list[TaskModel] = Field(default_factory=list)
    stats: PlannerStats = Field(default_factory=PlannerStats)
    metadata: PlannerMetadata = Field(default_factory=PlannerMetadata)
    normalized_surface: NormalizedApiSurface | None = None
    synthesized_security_context: SynthesizedSecurityContext | None = None
    generated_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=fresh_runtime_scheduler_state)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
