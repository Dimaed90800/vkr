from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from backend.models.testing import ExecutionContext, TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ExecutionContext, TaskModel


TaskClass = Literal["authorization", "injection", "business_logic"]


class FairnessConfig(BaseModel):
    max_consecutive_tasks_per_class: int = 3
    max_tasks_per_class_per_run: dict[str, int] = Field(
        default_factory=lambda: {
            "authorization": 8,
            "injection": 5,
            "business_logic": 6,
        }
    )


class SchedulerClassStats(BaseModel):
    budget_used: int = 0
    tasks_completed: int = 0
    retries_used: int = 0


class SchedulerState(BaseModel):
    run_id: str | None = None
    root_trace_id: str | None = None
    class_budget_used: dict[str, int] = Field(default_factory=dict)
    class_tasks_completed: dict[str, int] = Field(default_factory=dict)
    class_retries_used: dict[str, int] = Field(default_factory=dict)
    consecutive_class_count: int = 0
    last_executed_class: str | None = None
    completed_task_fingerprints: list[str] = Field(default_factory=list)
    confirmed_finding_fingerprints: list[str] = Field(default_factory=list)
    exploration_budget_used: int = 0
    deepening_budget_used: int = 0
    preparation_budget_used: int = 0
    root_followup_counts: dict[str, int] = Field(default_factory=dict)
    endpoint_family_attempts: dict[str, int] = Field(default_factory=dict)
    strategy_retry_counts: dict[str, int] = Field(default_factory=dict)


class SchedulerSelection(BaseModel):
    selected_task_id: str | None = None
    selected_class: str | None = None
    reason: str
    deferred_classes: list[str] = Field(default_factory=list)
    skipped_task_ids: list[str] = Field(default_factory=list)
    updated_state: SchedulerState = Field(default_factory=SchedulerState)


class ExecutabilityDecision(BaseModel):
    executable: bool = False
    execution_mode: str = "blocked"
    block_reason: str = ""
    missing_prerequisites: list[str] = Field(default_factory=list)
    preferred_tool: str | None = None
    preferred_strategy: str | None = None
    resolved_object_id: str | None = None
    available_object_ids_count: int = 0
    auth_context_available: bool = False
    baseline_valid: bool | None = None
    creator_candidate_count: int = 0
    list_candidate_count: int = 0
    success_path_feasibility: float = 0.0
    next_best_followup_strategies: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class NextTaskRequest(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    fairness_config: FairnessConfig = Field(default_factory=FairnessConfig)
    execution_context: ExecutionContext | None = None


class NextTaskResponse(BaseModel):
    next_task: TaskModel | None = None
    remaining_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    selection_reason: str
    deferred_classes: list[str] = Field(default_factory=list)
    skipped_task_ids: list[str] = Field(default_factory=list)
    should_stop: bool = False
    executable_test_task_count: int = 0
    executable_preparation_task_count: int = 0
    blocked_by_reason: dict[str, int] = Field(default_factory=dict)
    top_non_executable_tasks: list[dict[str, Any]] = Field(default_factory=list)


class QueueUpdateRequest(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    active_task: TaskModel | None = None
    verdict: str = "rejected"
    rework_hint: str | None = None
    evidence: dict = Field(default_factory=dict)
    max_retries: int = 1
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    fairness_config: FairnessConfig = Field(default_factory=FairnessConfig)
    execution_context: ExecutionContext | None = None


class QueueUpdateResponse(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    queue_update_reason: str
    requeued_task_id: str | None = None
    generated_followup_task_ids: list[str] = Field(default_factory=list)
    should_stop: bool = False
    updated_execution_context: ExecutionContext | None = None
    queue_enrichment: dict[str, Any] = Field(default_factory=dict)
