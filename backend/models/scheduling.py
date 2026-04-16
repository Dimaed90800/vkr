from typing import Literal

from pydantic import BaseModel, Field

try:
    from backend.models.testing import TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import TaskModel


TaskClass = Literal["authorization", "injection", "business_logic"]


class FairnessConfig(BaseModel):
    max_consecutive_tasks_per_class: int = 2
    max_tasks_per_class_per_run: dict[str, int] = Field(
        default_factory=lambda: {
            "authorization": 4,
            "injection": 4,
            "business_logic": 4,
        }
    )


class SchedulerClassStats(BaseModel):
    budget_used: int = 0
    tasks_completed: int = 0
    retries_used: int = 0


class SchedulerState(BaseModel):
    class_budget_used: dict[str, int] = Field(default_factory=dict)
    class_tasks_completed: dict[str, int] = Field(default_factory=dict)
    class_retries_used: dict[str, int] = Field(default_factory=dict)
    consecutive_class_count: int = 0
    last_executed_class: str | None = None
    completed_task_fingerprints: list[str] = Field(default_factory=list)
    confirmed_finding_fingerprints: list[str] = Field(default_factory=list)


class SchedulerSelection(BaseModel):
    selected_task_id: str | None = None
    selected_class: str | None = None
    reason: str
    deferred_classes: list[str] = Field(default_factory=list)
    skipped_task_ids: list[str] = Field(default_factory=list)
    updated_state: SchedulerState = Field(default_factory=SchedulerState)


class NextTaskRequest(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    fairness_config: FairnessConfig = Field(default_factory=FairnessConfig)


class NextTaskResponse(BaseModel):
    next_task: TaskModel | None = None
    remaining_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    selection_reason: str
    deferred_classes: list[str] = Field(default_factory=list)
    skipped_task_ids: list[str] = Field(default_factory=list)
    should_stop: bool = False


class QueueUpdateRequest(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    active_task: TaskModel | None = None
    verdict: str = "rejected"
    rework_hint: str | None = None
    max_retries: int = 1
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    fairness_config: FairnessConfig = Field(default_factory=FairnessConfig)


class QueueUpdateResponse(BaseModel):
    pending_tasks: list[TaskModel] = Field(default_factory=list)
    scheduler_state: SchedulerState = Field(default_factory=SchedulerState)
    queue_update_reason: str
    requeued_task_id: str | None = None
    should_stop: bool = False
