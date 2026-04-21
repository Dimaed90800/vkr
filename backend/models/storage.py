from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class StoredEvidence(BaseModel):
    task_id: str = ""
    content: dict[str, Any] = Field(default_factory=dict)


class EvidenceStoreRequest(BaseModel):
    session_id: str
    evidence: StoredEvidence


class EvidenceStoreAck(BaseModel):
    evidence_id: str
    status: str = "stored"


class StoredFinding(BaseModel):
    title: str = ""
    severity: str = "info"
    details: dict[str, Any] = Field(default_factory=dict)


class FindingStoreRequest(BaseModel):
    session_id: str
    finding: StoredFinding


class FindingStoreAck(BaseModel):
    finding_id: str
    status: str = "stored"
