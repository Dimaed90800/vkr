"""Phase Report-0 — backend-side structured report context models."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


REPORT_CONTEXT_SCHEMA_VERSION = "report-context/v1"


class ReportCampaignContext(BaseModel):
    campaign_id: str = ""
    target_url: str = ""
    openapi_url: str | None = None
    profile: str = ""
    started_at: str = ""
    finished_at: str | None = None
    stopped_reason: str = "not_available"


class ReportExecutiveSummary(BaseModel):
    confirmed_findings_count: int = 0
    pending_verification_count: int = 0
    iterations_run: int | str = "not_available"
    max_iterations: int | str = "not_available"
    tool_failures_count: int | str = "not_available"


class ReportDataQuality(BaseModel):
    runtime_state_attached: bool = False
    missing_sections: list[str] = Field(default_factory=list)


class ReportContext(BaseModel):
    schema_version: str = REPORT_CONTEXT_SCHEMA_VERSION
    campaign: ReportCampaignContext = Field(default_factory=ReportCampaignContext)
    executive_summary: ReportExecutiveSummary = Field(default_factory=ReportExecutiveSummary)
    owasp_coverage: dict[str, Any] = Field(default_factory=dict)
    confirmed_findings: list[dict[str, Any]] = Field(default_factory=list)
    finding_groups: list[dict[str, Any]] = Field(default_factory=list)
    pending_verification: list[dict[str, Any]] = Field(default_factory=list)
    blocked_checks: list[dict[str, Any]] = Field(default_factory=list)
    ready_but_not_executed: list[dict[str, Any]] = Field(default_factory=list)
    tool_failures: list[dict[str, Any]] = Field(default_factory=list)
    worker_execution_summary: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    recommendations_seed: list[dict[str, str]] = Field(default_factory=list)
    data_quality: ReportDataQuality = Field(default_factory=ReportDataQuality)
    auth_flow_diagnostics: dict[str, Any] = Field(default_factory=dict)
    adaptive_planner_diagnostics: dict[str, Any] = Field(default_factory=dict)
    api7_ssrf_pipeline_trace: dict[str, Any] = Field(default_factory=dict)
    compact_attempt_summary: list[dict[str, Any]] = Field(default_factory=list)
    last_observation_summary: dict[str, Any] = Field(default_factory=dict)


class ReportContextRequest(BaseModel):
    runtime_state_snapshot: dict[str, Any] | None = None
