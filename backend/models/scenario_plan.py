"""Phase 15A — LLM OpenAPI Scenario Planner (sidecar, stateless).

ScenarioPlan is analysis-only: no WorkerCommand, ToolRun, evidence, or findings.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class ScenarioType(str, Enum):
    access_control_bola = "access_control_bola"
    access_control_bfla = "access_control_bfla"
    mass_assignment = "mass_assignment"
    excessive_data_exposure = "excessive_data_exposure"
    schema_negative_testing = "schema_negative_testing"
    passive_signal_validation = "passive_signal_validation"
    discovery_expansion = "discovery_expansion"
    security_header_validation = "security_header_validation"
    injection_testing = "injection_testing"


SCENARIO_TYPES: frozenset[str] = frozenset(s.value for s in ScenarioType)


class ScenarioStatus(str, Enum):
    accepted = "accepted"
    blocked = "blocked"
    rejected = "rejected"


REQUIRED_PRECONDITIONS: frozenset[str] = frozenset({
    "two_authenticated_roles",
    "owner_object_id",
    "attacker_object_id",
    "admin_or_privileged_role",
    "object_id_operation",
    "writable_schema",
    "response_schema",
    "passive_signal_context",
    "openapi_schema",
    "parameter_context",
    "safe_payload_allowlist",
    "seed_url",
    "authenticated_session",
    "rate_limit_budget",
})


VULNERABILITY_CLASS_ALLOWLIST: frozenset[str] = frozenset({
    "BOLA",
    "BFLA",
    "BOPLA",
    "MASS_ASSIGNMENT",
    "DATA_EXPOSURE",
    "SCHEMA",
    "INVENTORY",
    "MISCONFIG",
    "RATE_LIMIT",
    "AUTH",
    "INJECTION",
})


class ScenarioLlmConfig(BaseModel):
    enabled: bool = False
    model: str = ""
    prompt_version: str = "scenario-planner/v1"


class ScenarioPlanRequestBody(BaseModel):
    max_operations: int = 120
    max_scenarios: int = 30
    llm: ScenarioLlmConfig = Field(default_factory=ScenarioLlmConfig)

    @field_validator("max_operations", "max_scenarios")
    @classmethod
    def _positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("must be >= 1")
        if v > 500:
            raise ValueError("must be <= 500")
        return v


class ValidatedScenarioItem(BaseModel):
    scenario_id: str
    status: ScenarioStatus
    scenario_type: str
    vulnerability_classes: list[str] = Field(default_factory=list)
    operation_ids: list[str] = Field(default_factory=list)
    resource_type: str = ""
    required_preconditions: list[str] = Field(default_factory=list)
    candidate_workers: list[str] = Field(default_factory=list)
    confidence: float = 0.0
    rationale: str = ""
    blocking_codes: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class ScenarioPlanResponse(BaseModel):
    schema_version: str = "scenario-plan-response/v1"
    campaign_id: str
    source: str = "llm_openapi_scenario_planner"
    graph_empty: bool = False
    warnings: list[str] = Field(default_factory=list)
    scenarios: list[ValidatedScenarioItem] = Field(default_factory=list)


class RawScenarioItem(BaseModel):
    """LLM / stub output shape before validation."""

    scenario_id: str = ""
    scenario_type: str = ""
    vulnerability_classes: list[str] = Field(default_factory=list)
    operation_ids: list[str] = Field(default_factory=list)
    resource_type: str = ""
    required_preconditions: list[str] = Field(default_factory=list)
    candidate_workers: list[str] = Field(default_factory=list)
    confidence: Any = 0.0
    rationale: str = ""

    model_config = {"extra": "ignore"}


class RawScenarioPlan(BaseModel):
    schema_version: str = ""
    campaign_id: str = ""
    source: str = ""
    scenarios: list[RawScenarioItem] = Field(default_factory=list)

    model_config = {"extra": "ignore"}
