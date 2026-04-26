"""Phase 7 - Judge verdict application contracts.

These models describe the backend-owned application of an already-produced
Judge verdict. They do not call a Judge LLM and do not execute tools.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class JudgeVerdictKind(str, Enum):
    confirmed = "confirmed"
    rejected = "rejected"
    rework = "rework"
    duplicate = "duplicate"
    out_of_scope = "out_of_scope"
    inconclusive = "inconclusive"


class FindingCandidatePayload(BaseModel):
    title: str = ""
    severity: str = ""
    vulnerability_class: str = ""
    summary: str = ""
    extras: dict[str, Any] = Field(default_factory=dict)


class JudgeVerdictPayload(BaseModel):
    schema_version: str = "judge-verdict/v1"
    verdict: JudgeVerdictKind
    confidence: float = 0.0
    severity: str = ""
    reason: str = ""
    finding_candidate: FindingCandidatePayload = Field(default_factory=FindingCandidatePayload)
    duplicate_of_finding_id: str = ""
    judge_source: str = ""
    judge_model: str = ""


class JudgeApplyRequest(BaseModel):
    campaign_id: str
    evidence_id: str
    task_id: str = ""
    verdict: JudgeVerdictPayload
    rework_hint: str = ""
    max_rework_depth: int = 2
    create_rework_on_inconclusive: bool = False


class JudgeDecisionRecord(BaseModel):
    schema_version: str = "judge-decision/v1"
    decision_id: str
    campaign_id: str
    evidence_id: str
    observation_id: str = ""
    verification_plan_id: str = ""
    task_id: str = ""
    verdict: JudgeVerdictKind
    confidence: float = 0.0
    severity: str = ""
    reason: str = ""
    judge_source: str = ""
    judge_model: str = ""
    duplicate_of_finding_id: str = ""
    finding_id: str = ""
    created_followup_verification_plan_id: str = ""
    readiness_issues: list[str] = Field(default_factory=list)
    applied_status: str = "applied"
    notes: list[str] = Field(default_factory=list)
    created_at: str = ""


class ConfirmedFinding(BaseModel):
    schema_version: str = "confirmed-finding/v1"
    finding_id: str
    campaign_id: str
    evidence_id: str
    observation_id: str = ""
    verification_plan_id: str = ""
    task_id: str = ""
    decision_id: str = ""
    fingerprint: str = ""
    owasp_category: str = ""
    vulnerability_class: str = ""
    operation_id: str = ""
    endpoint: str = ""
    method: str = ""
    title: str = ""
    severity: str = ""
    confidence: float = 0.0
    summary: str = ""
    reproduction_pointer: dict[str, Any] = Field(default_factory=dict)
    candidate_extras: dict[str, Any] = Field(default_factory=dict)
    duplicates: list[str] = Field(default_factory=list)
    created_at: str = ""


class JudgeApplyResult(BaseModel):
    status: str = "applied"
    decision_id: str = ""
    decision: JudgeDecisionRecord | None = None
    finding_id: str = ""
    finding: ConfirmedFinding | None = None
    followup_verification_plan_id: str = ""
    followup_verification_plan: Any = None
    duplicate_of_finding_id: str = ""
    readiness_issues: list[str] = Field(default_factory=list)
    campaign_summary: dict[str, Any] = Field(default_factory=dict)
