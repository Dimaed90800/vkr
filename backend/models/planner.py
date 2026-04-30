"""Phase 12A — backend-owned WorkerCommand candidate planner.

The planner returns commands for callers to execute later. It does not execute
tools and does not create ToolRuns, EvidencePacks, Judge decisions, or findings.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

try:
    from backend.models.scenario_plan import ValidatedScenarioItem
    from backend.models.worker_command import WorkerCommand
except ModuleNotFoundError:  # pragma: no cover
    from models.scenario_plan import ValidatedScenarioItem
    from models.worker_command import WorkerCommand


class PlannerCandidateStatus(str, Enum):
    ready = "ready"
    blocked = "blocked"
    skipped_existing = "skipped_existing"


class PlannerCandidateKind(str, Enum):
    zap_discovery_passive = "zap_discovery_passive"
    js_endpoint_extractor = "js_endpoint_extractor"
    bola_replay_probe = "bola_replay_probe"
    security_header_validator = "security_header_validator"
    cors_validator = "cors_validator"
    cookie_flag_validator = "cookie_flag_validator"
    undocumented_endpoint_validator = "undocumented_endpoint_validator"
    ssrf_candidate_detector = "ssrf_candidate_detector"
    ssrf_probe = "ssrf_probe"
    schemathesis_negative_test = "schemathesis_negative_test"
    injection_test = "injection_test"
    property_mutation_test = "property_mutation_test"
    data_exposure_validator = "data_exposure_validator"
    resource_instance_extractor = "resource_instance_extractor"
    targeted_object_harvester = "targeted_object_harvester"
    auth_flow_detector = "auth_flow_detector"
    test_account_materializer = "test_account_materializer"
    resource_seed_worker = "resource_seed_worker"
    bola_object_pair_builder = "bola_object_pair_builder"
    scenario_plan_blocked = "scenario_plan_blocked"


class BolaObjectPairHint(BaseModel):
    object_id: str = ""
    attacker_own_object_id: str = ""
    object_url: str = ""
    attacker_own_object_url: str = ""
    collection_url: str = ""
    owner_role: str = ""
    attacker_role: str = ""
    operation_id: str = ""
    path_template: str = ""
    collection_path_template: str = ""
    collection_operation_id: str = ""


class ZapDiscoveryHint(BaseModel):
    enabled: bool = True
    target_url: str = ""
    zap_base_url: str = ""
    seed_urls: list[str] = Field(default_factory=list)
    use_spider: bool = True
    use_ajax_spider: bool = False
    max_duration_sec: int = 30
    max_discovered_urls: int = 100
    max_alerts: int = 100


class BolaPlannerHints(BaseModel):
    enabled: bool = True
    object_pairs: list[BolaObjectPairHint] = Field(default_factory=list)


class ScenarioPlanInput(BaseModel):
    """Optional Phase 15B payload: validated ScenarioPlan rows (hints only)."""

    source: str = ""
    scenarios: list[ValidatedScenarioItem] = Field(default_factory=list)


class PlannerRequest(BaseModel):
    include_blocked: bool = True
    max_candidates: int = 10
    zap: ZapDiscoveryHint = Field(default_factory=ZapDiscoveryHint)
    bola: BolaPlannerHints = Field(default_factory=BolaPlannerHints)
    scenario_plan: ScenarioPlanInput | None = None
    include_scenario_compiler: bool = True
    enable_cors_baseline: bool = False
    enable_cookie_baseline: bool = False
    enable_llm_candidate_advisor: bool = False


class PlannerCandidate(BaseModel):
    candidate_id: str
    kind: PlannerCandidateKind
    status: PlannerCandidateStatus
    priority: float = 0.0
    reason: str = ""
    missing_inputs: list[str] = Field(default_factory=list)
    dedup_key: str = ""
    command: WorkerCommand | None = None
    summary: dict[str, Any] = Field(default_factory=dict)


class PlannerResponse(BaseModel):
    campaign_id: str
    candidates_total: int = 0
    ready_count: int = 0
    blocked_count: int = 0
    skipped_existing_count: int = 0
    candidates: list[PlannerCandidate] = Field(default_factory=list)
    ready_candidates_by_kind_count: dict[str, int] = Field(default_factory=dict)
    blocked_candidates_by_kind_count: dict[str, int] = Field(default_factory=dict)
    ready_candidates_sample: list[dict[str, Any]] = Field(default_factory=list)
    blocked_candidates_sample: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
