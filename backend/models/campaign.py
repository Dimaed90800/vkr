from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class CampaignStatus(str, Enum):
    created = "created"
    running = "running"
    paused = "paused"
    stopped = "stopped"
    finished = "finished"


class CampaignLimits(BaseModel):
    max_requests: int = 1000
    max_duration_sec: int = 1800
    max_iterations: int = 50
    max_retries_per_task: int = 2


class Campaign(BaseModel):
    campaign_id: str
    run_id: str | None = None
    legacy_session_id: int | None = None
    target_url: str
    openapi_url: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    profile: str = "safe"
    limits: CampaignLimits = Field(default_factory=CampaignLimits)
    status: CampaignStatus = CampaignStatus.running
    roles_json: list[dict[str, Any]] = Field(default_factory=list)
    created_at: str = ""

    @property
    def legacy_run_id(self) -> str | None:
        """Compatibility alias for run_id."""
        return self.run_id


class CampaignCreateRequest(BaseModel):
    target_url: str
    openapi_url: str | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    profile: str = "safe"
    limits: CampaignLimits = Field(default_factory=CampaignLimits)
    roles_json: list[dict[str, Any]] = Field(default_factory=list)


class CampaignCreateResponse(BaseModel):
    campaign_id: str
    run_id: str
    status: CampaignStatus


class CampaignBudget(BaseModel):
    max_requests: int = 1000
    used_requests: int = 0
    remaining_requests: int = 1000
    max_duration_sec: int = 1800


class CampaignCounts(BaseModel):
    operations: int = 0
    corpus_items: int = 0
    pending_tasks: int = 0
    confirmed_findings: int = 0
    tool_runs: int = 0


class CampaignSummary(BaseModel):
    campaign_id: str
    run_id: str | None = None
    status: CampaignStatus
    target_url: str
    openapi_url: str | None = None
    limits: CampaignLimits = Field(default_factory=CampaignLimits)
    budget: CampaignBudget = Field(default_factory=CampaignBudget)
    counts: CampaignCounts = Field(default_factory=CampaignCounts)
    stop_reason: str | None = None
