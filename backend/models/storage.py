from typing import Any

from pydantic import BaseModel, Field


class EvidenceRecord(BaseModel):
    task_id: str
    worker_type: str
    request_summary: dict[str, Any] = Field(default_factory=dict)
    response_summary: dict[str, Any] = Field(default_factory=dict)
    raw_status: str = "unknown"
    indicators: list[str] = Field(default_factory=list)
    reasoning: str
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    timestamp: str


class FindingRecord(BaseModel):
    id: str | None = None
    title: str
    vuln_type: str
    endpoint: str
    method: str
    severity: str
    confidence: float | None = None
    evidence_summary: str
    reproduction_steps: list[str] = Field(default_factory=list)
    remediation: str
    source_task_id: str | None = None
    worker_type: str | None = None


class EvidenceStoreRequest(BaseModel):
    session_id: int | str | None = 0
    evidence: EvidenceRecord


class EvidenceStoreAck(BaseModel):
    evidence_id: str
    status: str


class FindingStoreRequest(BaseModel):
    session_id: int | str | None = 0
    finding: FindingRecord


class FindingStoreAck(BaseModel):
    finding_id: str
    status: str
