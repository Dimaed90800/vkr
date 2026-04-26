"""Phase 6 — EvidencePack v1 data contract.

EvidencePack is the structured artifact built by ``EvidencePackBuilder`` from
already-stored Observations, VerificationPlans, ToolResults, RequestCorpus
items, ApiGraph operations, and ToolArtifactRefs.

It is the canonical input for the Phase 7 Judge. It does NOT itself create
confirmed findings, NOR does it call any tool. Construction is read-only with
respect to all upstream services.

Phase 6 invariants:
* No confirmed findings created.
* No Judge calls.
* No tool execution.
* HTTP exchanges are referenced by ``request_id`` (corpus seed); raw bodies
  must never be embedded by the builder.
* ``judge_ready=True`` only when ``status == EvidencePackStatus.ready_for_judge``
  and ``missing_evidence == []``.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class EvidencePackStatus(str, Enum):
    ready_for_judge = "ready_for_judge"
    incomplete = "incomplete"
    not_judge_ready = "not_judge_ready"


class EvidenceHttpExchangeRef(BaseModel):
    """Pointer to a corpus exchange. Builder never inlines raw bodies."""

    request_id: str = ""
    role: str = ""
    method: str = ""
    path_template: str = ""
    url: str = ""
    status_code: int = 0
    classification: str = ""
    operation_id: str = ""


class EvidenceBaseline(BaseModel):
    """Legitimate / expected access (e.g. owner reading their own object)."""

    role: str = ""
    request_ref: EvidenceHttpExchangeRef | None = None
    description: str = ""


class EvidenceAttack(BaseModel):
    """The candidate violation request (e.g. attacker reading owner object)."""

    role: str = ""
    request_ref: EvidenceHttpExchangeRef | None = None
    description: str = ""


class EvidenceControl(BaseModel):
    """Negative / sanity control (e.g. attacker access to own resource is fine)."""

    name: str = ""
    role: str = ""
    request_ref: EvidenceHttpExchangeRef | None = None
    description: str = ""


class EvidenceOwnershipProof(BaseModel):
    """Evidence that the contested object actually belongs to the claimed owner.

    Required for cross-role / BOLA-style evidence packs. We model it as a pair
    of corpus references plus a short proof reason.
    """

    object_id: str = ""
    owner_role: str = ""
    owner_collection_request_ref: EvidenceHttpExchangeRef | None = None
    attacker_collection_request_ref: EvidenceHttpExchangeRef | None = None
    proof: str = ""


class EvidenceDiff(BaseModel):
    """Compact diff between baseline and attack exchanges."""

    status_code_baseline: int = 0
    status_code_attack: int = 0
    fields_present_in_attack: list[str] = Field(default_factory=list)
    fields_missing_in_attack: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class EvidenceReplayStep(BaseModel):
    """One reproducible step the Judge / a human can replay."""

    order: int = 0
    role: str = ""
    method: str = ""
    path_template: str = ""
    url: str = ""
    request_ref: EvidenceHttpExchangeRef | None = None
    description: str = ""


class EvidenceArtifactRef(BaseModel):
    """Reference to a stored artifact (stdout, stderr, json blob...)."""

    artifact_id: str = ""
    artifact_type: str = ""
    path: str = ""
    size_bytes: int = 0


class MissingEvidenceItem(BaseModel):
    """Explicit description of what is missing for ``ready_for_judge`` status."""

    code: str
    description: str = ""
    required_for: str = ""


class EvidencePack(BaseModel):
    """Structured judge-ready (or judge-not-ready-yet) evidence object."""

    schema_version: str = "evidence-pack/v1"
    evidence_id: str
    campaign_id: str
    task_id: str = ""

    observation_id: str = ""
    verification_plan_id: str = ""
    tool_run_ids: list[str] = Field(default_factory=list)

    owasp_category: str = ""
    vulnerability_class: str = ""

    operation_id: str = ""
    endpoint: str = ""
    method: str = ""

    hypothesis: str = ""

    baseline: EvidenceBaseline | None = None
    attack: EvidenceAttack | None = None
    controls: list[EvidenceControl] = Field(default_factory=list)
    ownership_proof: EvidenceOwnershipProof | None = None
    diff: EvidenceDiff | None = None

    derived_signals: list[str] = Field(default_factory=list)
    missing_evidence: list[MissingEvidenceItem] = Field(default_factory=list)
    replay_steps: list[EvidenceReplayStep] = Field(default_factory=list)
    artifact_refs: list[EvidenceArtifactRef] = Field(default_factory=list)

    confidence: float = 0.0

    status: EvidencePackStatus = EvidencePackStatus.incomplete
    judge_ready: bool = False
    created_at: str = ""


class EvidencePackBuildResponse(BaseModel):
    """Wrapper response so route can return ``existing=True/False`` cheaply."""

    evidence_pack: EvidencePack
    existing: bool = False
