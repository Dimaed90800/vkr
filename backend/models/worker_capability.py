"""Phase 17A.1 — Read-only worker capability metadata (catalog).

Does not drive PlannerService, ToolExecutor, or execution. Used for
ScenarioPlan / reporting / UI surfacing of what the toolbox can do.
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


CapabilityStatus = Literal["implemented", "partial", "planned"]
ExecutionMode = Literal["sync", "async", "none"]
RiskLevel = Literal["low", "medium", "high"]


class WorkerCapability(BaseModel):
    worker_name: str
    tool_name: str
    worker_class: str
    scenario_types: list[str] = Field(default_factory=list)
    observation_types: list[str] = Field(default_factory=list)
    owasp_categories: list[str] = Field(default_factory=list)
    status: CapabilityStatus
    adapter_available: bool
    execution_mode: ExecutionMode
    triage_support: bool
    evidence_support: bool
    judge_support: bool
    requires_auth: bool = False
    requires_seed: bool = False
    requires_openapi: bool = False
    requires_corpus: bool = False
    risk_level: RiskLevel = "medium"
    notes: str = ""


class WorkerCapabilityCatalogResponse(BaseModel):
    schema_version: str = "worker-capability-catalog/v1"
    workers: list[WorkerCapability] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)
