from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.campaign import (
        Campaign,
        CampaignBudget,
        CampaignCounts,
        CampaignLimits,
        CampaignStatus,
        CampaignSummary,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import (
        Campaign,
        CampaignBudget,
        CampaignCounts,
        CampaignLimits,
        CampaignStatus,
        CampaignSummary,
    )
    from storage.memory_store import memory_store


class CampaignService:
    def create_campaign(
        self,
        *,
        target_url: str,
        openapi_url: str | None = None,
        allowed_hosts: list[str] | None = None,
        profile: str = "safe",
        limits: CampaignLimits | None = None,
        roles_json: list[dict[str, Any]] | None = None,
    ) -> Campaign:
        campaign_id = f"cmp_{uuid4().hex[:16]}"
        run_id = f"run-{uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        if allowed_hosts is None:
            from urllib.parse import urlparse
            parsed = urlparse(target_url)
            allowed_hosts = [parsed.hostname] if parsed.hostname else []

        campaign = Campaign(
            campaign_id=campaign_id,
            run_id=run_id,
            target_url=target_url,
            openapi_url=openapi_url,
            allowed_hosts=allowed_hosts,
            profile=profile,
            limits=limits or CampaignLimits(),
            status=CampaignStatus.running,
            roles_json=roles_json or [],
            created_at=now,
        )

        memory_store.store_campaign(
            campaign_id, campaign.model_dump(mode="json")
        )
        return campaign

    def get_campaign(self, campaign_id: str) -> Campaign | None:
        data = memory_store.get_campaign(campaign_id)
        if data is None:
            return None
        return Campaign.model_validate(data)

    def get_summary(self, campaign_id: str) -> CampaignSummary | None:
        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            return None

        used_requests = len(memory_store.evidence_by_session.get(campaign_id, []))
        confirmed_findings = len(
            memory_store.findings_by_session.get(campaign_id, [])
        )
        remaining_requests = max(campaign.limits.max_requests - used_requests, 0)
        graph_blob = memory_store.get_graph_for_campaign(campaign_id) or {}
        operations_count = int(graph_blob.get("operations_count") or 0)

        return CampaignSummary(
            campaign_id=campaign.campaign_id,
            run_id=campaign.run_id,
            status=campaign.status,
            target_url=campaign.target_url,
            openapi_url=campaign.openapi_url,
            limits=campaign.limits,
            budget=CampaignBudget(
                max_requests=campaign.limits.max_requests,
                used_requests=used_requests,
                remaining_requests=remaining_requests,
                max_duration_sec=campaign.limits.max_duration_sec,
            ),
            counts=CampaignCounts(
                operations=operations_count,
                corpus_items=len(
                    memory_store.corpus_by_campaign.get(campaign_id, [])
                ),
                pending_tasks=0,
                confirmed_findings=confirmed_findings,
                tool_runs=0,
            ),
            stop_reason=None,
        )

    def resolve_run_id(self, campaign_id: str) -> str | None:
        campaign = self.get_campaign(campaign_id)
        if campaign is None:
            return None
        return campaign.run_id

    def resolve_campaign_id(self, run_id: str) -> str | None:
        return memory_store.resolve_campaign_id_by_run_id(run_id)
