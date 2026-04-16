from typing import Any, Literal

from pydantic import BaseModel, Field

try:
    from backend.models.testing import TaskModel, ToolTestResponse
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import TaskModel, ToolTestResponse


FailureType = Literal[
    "invalid_object_id",
    "conversion_failure",
    "validation_failure",
    "non_authorization_error",
    "authorization_negative",
    "unknown",
]

ReplanDecision = Literal["retry_with_updated_inputs", "stop"]


class JudgeVerdictInput(BaseModel):
    task_id: str
    verdict: str
    reason: str = ""
    rework_hint: str | None = None
    severity: str | None = None
    finding_candidate_json: str | None = None


class FailureClassification(BaseModel):
    failure_type: FailureType = "unknown"
    should_retry: bool = False
    requires_new_object_id: bool = False
    reason: str = ""


class ReplanRequest(BaseModel):
    task: TaskModel
    judge_verdict: JudgeVerdictInput
    tool_response: ToolTestResponse
    known_object_id_candidates: list[str | int] = Field(default_factory=list)


class ReplanResponse(BaseModel):
    decision: ReplanDecision
    failure_classification: FailureClassification
    updated_task: TaskModel | None = None
    reason: str
    retry_count: int = 0
    candidate_pool: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
