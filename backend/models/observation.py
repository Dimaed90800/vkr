"""Phase 5.6 — Observation and VerificationPlan data contracts.

Observation is a normalized signal produced from ToolResult.
It is NOT a confirmed vulnerability, NOT judge-ready evidence.

VerificationPlan describes how to turn a signal into proof.
Plans are lightweight stubs; agents flesh them out later.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ObservationType(str, Enum):
    unexpected_500 = "unexpected_500"
    schema_mismatch = "schema_mismatch"
    auth_anomaly = "auth_anomaly"
    cross_role_access_signal = "cross_role_access_signal"
    validated_security_header_issue = "validated_security_header_issue"
    zap_alert = "zap_alert"
    nuclei_match = "nuclei_match"
    discovered_endpoint = "discovered_endpoint"
    hidden_parameter = "hidden_parameter"
    sensitive_field_seen = "sensitive_field_seen"
    state_changed_after_invalid_payload = "state_changed_after_invalid_payload"
    server_error_candidate = "server_error_candidate"
    unsupported_tool_signal = "unsupported_tool_signal"
    timeout_signal = "timeout_signal"
    tool_error = "tool_error"


class SecurityRelevance(str, Enum):
    unknown = "unknown"
    informational = "informational"
    low = "low"
    medium = "medium"
    high = "high"


class VerificationPlanStatus(str, Enum):
    pending = "pending"
    in_progress = "in_progress"
    completed = "completed"
    cancelled = "cancelled"


class Observation(BaseModel):
    schema_version: str = "observation/v1"
    observation_id: str
    campaign_id: str
    tool_run_id: str = ""
    task_id: str = ""
    command_id: str = ""
    source: str = ""
    type: ObservationType
    operation_id: str = ""
    request_id: str = ""
    auth_profile: str = ""
    status_code: int = 0
    confidence: float = 0.0
    security_relevance: SecurityRelevance = SecurityRelevance.unknown
    judge_worthy: bool = False
    recommended_next_action: str = ""
    details: dict[str, Any] = Field(default_factory=dict)
    artifact_refs: list[str] = Field(default_factory=list)
    created_at: str = ""


class VerificationPlanCommand(BaseModel):
    tool_name: str = ""
    strategy: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    budget: dict[str, Any] = Field(default_factory=dict)


class VerificationPlan(BaseModel):
    schema_version: str = "verification-plan/v1"
    verification_plan_id: str
    campaign_id: str
    parent_observation_id: str = ""
    parent_task_id: str = ""
    goal: str
    worker_class: str = ""
    strategy: str = ""
    required_evidence: list[str] = Field(default_factory=list)
    commands: list[VerificationPlanCommand] = Field(default_factory=list)
    status: VerificationPlanStatus = VerificationPlanStatus.pending
    created_at: str = ""


class NormalizeResponse(BaseModel):
    tool_run_id: str
    campaign_id: str
    observations_created: int = 0
    observations: list[Observation] = Field(default_factory=list)
    already_normalized: bool = False


class TriageResponse(BaseModel):
    observation: Observation
    verification_plan: VerificationPlan | None = None
