from __future__ import annotations

from collections import defaultdict
from uuid import uuid4


class MemoryStore:
    def __init__(self) -> None:
        self.evidence_records: list[dict] = []
        self.findings: list[dict] = []
        self.evidence_by_session: dict[str, list[dict]] = defaultdict(list)
        self.findings_by_session: dict[str, list[dict]] = defaultdict(list)

        self.campaigns: dict[str, dict] = {}
        self.campaign_by_run_id: dict[str, str] = {}
        self.campaign_by_session_id: dict[int, str] = {}

    def store_campaign(self, campaign_id: str, data: dict) -> None:
        self.campaigns[campaign_id] = data
        run_id = data.get("run_id")
        if run_id:
            self.campaign_by_run_id[run_id] = campaign_id
        session_id = data.get("legacy_session_id")
        if session_id is not None:
            self.campaign_by_session_id[session_id] = campaign_id

    def get_campaign(self, campaign_id: str) -> dict | None:
        return self.campaigns.get(campaign_id)

    def resolve_campaign_id_by_run_id(self, run_id: str) -> str | None:
        return self.campaign_by_run_id.get(run_id)

    def resolve_campaign_id_by_session_id(self, session_id: int) -> str | None:
        return self.campaign_by_session_id.get(session_id)

    def store_evidence(self, session_id: str, evidence) -> str:
        evidence_id = f"evidence-{uuid4().hex[:12]}"
        payload = {"id": evidence_id, "session_id": session_id, "evidence": evidence.model_dump(mode='json') if hasattr(evidence, 'model_dump') else evidence}
        self.evidence_records.append(payload)
        self.evidence_by_session[session_id].append(payload)
        return evidence_id

    def store_finding(self, session_id: str, finding) -> str:
        finding_id = f"finding-{uuid4().hex[:12]}"
        payload = {"id": finding_id, "session_id": session_id, "finding": finding.model_dump(mode='json') if hasattr(finding, 'model_dump') else finding}
        self.findings.append(payload)
        self.findings_by_session[session_id].append(payload)
        return finding_id


memory_store = MemoryStore()
