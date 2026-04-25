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

        self.corpus_items: dict[str, dict] = {}
        self.corpus_by_campaign: dict[str, list[str]] = defaultdict(list)
        self.resource_instances: dict[str, dict] = {}
        self.resources_by_campaign: dict[str, list[str]] = defaultdict(list)

        self.graphs_by_campaign: dict[str, dict] = {}

        self.commands: dict[str, dict] = {}
        self.commands_by_campaign: dict[str, list[str]] = defaultdict(list)
        self.command_fingerprints: dict[str, set[str]] = defaultdict(set)

        self.tool_runs: dict[str, dict] = {}
        self.tool_runs_by_campaign: dict[str, list[str]] = defaultdict(list)
        self.tool_results: dict[str, dict] = {}
        self.artifacts: dict[str, dict] = {}
        self.artifacts_by_run: dict[str, list[str]] = defaultdict(list)

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

    def store_corpus_item(self, request_id: str, campaign_id: str, data: dict) -> None:
        self.corpus_items[request_id] = data
        self.corpus_by_campaign[campaign_id].append(request_id)

    def get_corpus_item(self, request_id: str) -> dict | None:
        return self.corpus_items.get(request_id)

    def list_corpus_by_campaign(self, campaign_id: str) -> list[dict]:
        return [
            self.corpus_items[rid]
            for rid in self.corpus_by_campaign.get(campaign_id, [])
            if rid in self.corpus_items
        ]

    def store_resource_instance(
        self, resource_instance_id: str, campaign_id: str, data: dict
    ) -> None:
        self.resource_instances[resource_instance_id] = data
        self.resources_by_campaign[campaign_id].append(resource_instance_id)

    def list_resources_by_campaign(self, campaign_id: str) -> list[dict]:
        return [
            self.resource_instances[rid]
            for rid in self.resources_by_campaign.get(campaign_id, [])
            if rid in self.resource_instances
        ]

    def store_graph_for_campaign(self, campaign_id: str, data: dict) -> None:
        self.graphs_by_campaign[campaign_id] = data

    def get_graph_for_campaign(self, campaign_id: str) -> dict | None:
        return self.graphs_by_campaign.get(campaign_id)

    def replace_graph_for_campaign(self, campaign_id: str, data: dict) -> None:
        self.graphs_by_campaign[campaign_id] = data

    def store_command(self, command_id: str, campaign_id: str, data: dict) -> None:
        self.commands[command_id] = data
        self.commands_by_campaign[campaign_id].append(command_id)

    def get_command(self, command_id: str) -> dict | None:
        return self.commands.get(command_id)

    def list_commands_by_campaign(self, campaign_id: str) -> list[dict]:
        return [
            self.commands[cid]
            for cid in self.commands_by_campaign.get(campaign_id, [])
            if cid in self.commands
        ]

    def store_tool_run(self, tool_run_id: str, campaign_id: str, data: dict) -> None:
        self.tool_runs[tool_run_id] = data
        self.tool_runs_by_campaign[campaign_id].append(tool_run_id)

    def get_tool_run(self, tool_run_id: str) -> dict | None:
        return self.tool_runs.get(tool_run_id)

    def update_tool_run(self, tool_run_id: str, data: dict) -> None:
        if tool_run_id in self.tool_runs:
            self.tool_runs[tool_run_id].update(data)

    def list_tool_runs_by_campaign(self, campaign_id: str) -> list[dict]:
        return [
            self.tool_runs[rid]
            for rid in self.tool_runs_by_campaign.get(campaign_id, [])
            if rid in self.tool_runs
        ]

    def store_tool_result(self, tool_run_id: str, data: dict) -> None:
        self.tool_results[tool_run_id] = data

    def get_tool_result(self, tool_run_id: str) -> dict | None:
        return self.tool_results.get(tool_run_id)

    def store_artifact(self, artifact_id: str, tool_run_id: str, data: dict) -> None:
        self.artifacts[artifact_id] = data
        self.artifacts_by_run[tool_run_id].append(artifact_id)

    def get_artifact(self, artifact_id: str) -> dict | None:
        return self.artifacts.get(artifact_id)

    def list_artifacts_by_run(self, tool_run_id: str) -> list[dict]:
        return [
            self.artifacts[aid]
            for aid in self.artifacts_by_run.get(tool_run_id, [])
            if aid in self.artifacts
        ]

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
