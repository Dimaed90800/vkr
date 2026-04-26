"""Phase 12A — read-only backend WorkerCommand planner."""
from __future__ import annotations

import hashlib
import json
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.observation import Observation, ObservationType
    from backend.models.planner import (
        BolaObjectPairHint,
        PlannerCandidate,
        PlannerCandidateKind,
        PlannerCandidateStatus,
        PlannerRequest,
        PlannerResponse,
    )
    from backend.models.tool_run import ToolResult, ToolRun
    from backend.models.worker_command import CommandBudget, WorkerCommand
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.command_validator import CommandValidator
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.observation import Observation, ObservationType
    from models.planner import (
        BolaObjectPairHint,
        PlannerCandidate,
        PlannerCandidateKind,
        PlannerCandidateStatus,
        PlannerRequest,
        PlannerResponse,
    )
    from models.tool_run import ToolResult, ToolRun
    from models.worker_command import CommandBudget, WorkerCommand
    from services.api_graph_service import ApiGraphService
    from services.command_validator import CommandValidator
    from storage.memory_store import memory_store


class PlannerError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PlannerService:
    def __init__(self) -> None:
        self._graph = ApiGraphService()
        self._validator = CommandValidator()

    def plan(self, campaign_id: str, request: PlannerRequest) -> PlannerResponse:
        raw_campaign = memory_store.get_campaign(campaign_id)
        if raw_campaign is None:
            raise PlannerError(
                "campaign_not_found",
                f"Campaign '{campaign_id}' not found.",
            )
        campaign = Campaign.model_validate(raw_campaign)
        warnings: list[str] = []
        candidates: list[PlannerCandidate] = []

        graph_summary = self._graph.summary_for_planner(campaign_id)
        if graph_summary.operations_total == 0:
            warnings.append("api_graph_empty_or_missing")
        if not campaign.allowed_hosts:
            warnings.append("allowed_hosts_not_configured")

        if request.zap.enabled:
            candidates.append(self._zap_candidate(campaign, request, graph_summary.model_dump(mode="json")))

        if request.bola.enabled:
            candidates.extend(self._bola_candidates(campaign, request, graph_summary.model_dump(mode="json")))

        if not request.include_blocked:
            candidates = [
                item for item in candidates
                if item.status != PlannerCandidateStatus.blocked
            ]

        candidates = self._ordered(candidates)[:max(int(request.max_candidates or 0), 0)]

        return PlannerResponse(
            campaign_id=campaign_id,
            candidates_total=len(candidates),
            ready_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.ready),
            blocked_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.blocked),
            skipped_existing_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.skipped_existing),
            candidates=candidates,
            warnings=warnings,
        )

    def _zap_candidate(
        self,
        campaign: Campaign,
        request: PlannerRequest,
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        target_url = request.zap.target_url or campaign.target_url
        dedup_key = self._zap_dedup_key(campaign.campaign_id, target_url, request.zap.seed_urls)
        summary = {
            "target_url": target_url,
            "seed_urls_count": len(request.zap.seed_urls),
            "graph_summary": graph_summary,
        }

        existing = self._existing_zap_run(campaign.campaign_id, dedup_key)
        if existing is not None:
            return self._candidate(
                kind=PlannerCandidateKind.zap_discovery_passive,
                status=PlannerCandidateStatus.skipped_existing,
                priority=100.0,
                reason="Existing active/finished/partial zap_discovery_passive ToolRun found.",
                dedup_key=dedup_key,
                summary={**summary, "existing_tool_run_id": existing.get("tool_run_id", "")},
            )

        if not campaign.allowed_hosts:
            return self._candidate(
                kind=PlannerCandidateKind.zap_discovery_passive,
                status=PlannerCandidateStatus.blocked,
                priority=100.0,
                reason="Campaign allowed_hosts is empty; planner will not return ready outbound commands.",
                missing_inputs=["campaign.allowed_hosts"],
                dedup_key=dedup_key,
                summary=summary,
            )

        timeout_sec = max(60, int(request.zap.max_duration_sec or 0) + 10)
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id="task_zap_discovery_passive",
            worker_class="discovery_inventory",
            strategy="zap_discovery_passive",
            tool_name="zap_discovery_passive",
            operation_id="",
            seed_request_id="",
            inputs={
                "target_url": target_url,
                "zap_base_url": request.zap.zap_base_url,
                "seed_urls": list(request.zap.seed_urls),
                "use_spider": request.zap.use_spider,
                "use_ajax_spider": request.zap.use_ajax_spider,
                "max_duration_sec": request.zap.max_duration_sec,
                "max_discovered_urls": request.zap.max_discovered_urls,
                "max_alerts": request.zap.max_alerts,
            },
            budget=CommandBudget(max_requests=1, timeout_sec=timeout_sec),
            success_criteria=["zap_discovery_completed"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.zap_discovery_passive,
            priority=100.0,
            reason="ZAP discovery/passive has not run for this campaign.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _bola_candidates(
        self,
        campaign: Campaign,
        request: PlannerRequest,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        if not request.bola.object_pairs:
            return [
                self._candidate(
                    kind=PlannerCandidateKind.bola_replay_probe,
                    status=PlannerCandidateStatus.blocked,
                    priority=50.0,
                    reason="BOLA replay requires explicit owner/attacker object pair hints.",
                    missing_inputs=["bola.object_pairs"],
                    dedup_key=f"{campaign.campaign_id}|bola_replay_probe|missing_hints",
                    summary={"graph_summary": graph_summary},
                )
            ]

        results: list[PlannerCandidate] = []
        for index, hint in enumerate(request.bola.object_pairs):
            results.append(self._bola_candidate(campaign, hint, index, graph_summary))
        return results

    def _bola_candidate(
        self,
        campaign: Campaign,
        hint: BolaObjectPairHint,
        index: int,
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        missing = self._missing_bola_inputs(hint)
        dedup_key = self._bola_dedup_key(campaign.campaign_id, hint)
        summary = {
            "object_id": hint.object_id,
            "attacker_own_object_id": hint.attacker_own_object_id,
            "owner_role": hint.owner_role,
            "attacker_role": hint.attacker_role,
            "operation_id": hint.operation_id,
            "graph_summary": graph_summary,
        }
        if missing:
            return self._candidate(
                kind=PlannerCandidateKind.bola_replay_probe,
                status=PlannerCandidateStatus.blocked,
                priority=50.0,
                reason="BOLA replay object pair hint is incomplete.",
                missing_inputs=missing,
                dedup_key=dedup_key,
                summary=summary,
            )

        if self._existing_bola_signal(campaign.campaign_id, hint):
            return self._candidate(
                kind=PlannerCandidateKind.bola_replay_probe,
                status=PlannerCandidateStatus.skipped_existing,
                priority=50.0,
                reason="Matching cross_role_access_signal already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )
        if self._existing_bola_tool_result(campaign.campaign_id, hint):
            return self._candidate(
                kind=PlannerCandidateKind.bola_replay_probe,
                status=PlannerCandidateStatus.skipped_existing,
                priority=50.0,
                reason="Matching bola_replay_probe ToolResult signal already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )
        if not campaign.allowed_hosts:
            return self._candidate(
                kind=PlannerCandidateKind.bola_replay_probe,
                status=PlannerCandidateStatus.blocked,
                priority=50.0,
                reason="Campaign allowed_hosts is empty; planner will not return ready outbound commands.",
                missing_inputs=["campaign.allowed_hosts"],
                dedup_key=dedup_key,
                summary=summary,
            )

        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_bola_replay_probe_{index + 1}",
            worker_class="access_control",
            strategy="prove_bola",
            tool_name="bola_replay_probe",
            operation_id=hint.operation_id,
            seed_request_id="",
            inputs={
                "operation_id": hint.operation_id,
                "method": "GET",
                "object_url": hint.object_url,
                "attacker_own_object_url": hint.attacker_own_object_url,
                "collection_url": hint.collection_url,
                "path_template": hint.path_template,
                "collection_path_template": hint.collection_path_template,
                "collection_operation_id": hint.collection_operation_id,
                "object_id": hint.object_id,
                "attacker_own_object_id": hint.attacker_own_object_id,
                "owner_role": hint.owner_role,
                "attacker_role": hint.attacker_role,
            },
            budget=CommandBudget(max_requests=5, timeout_sec=30),
            success_criteria=["cross_role_access_signal_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.bola_replay_probe,
            priority=50.0,
            reason="Complete BOLA object pair hints are available.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _validated_candidate(
        self,
        *,
        kind: PlannerCandidateKind,
        priority: float,
        reason: str,
        dedup_key: str,
        command: WorkerCommand,
        summary: dict[str, Any],
    ) -> PlannerCandidate:
        validation = self._validator.validate(command)
        if validation.valid:
            return self._candidate(
                kind=kind,
                status=PlannerCandidateStatus.ready,
                priority=priority,
                reason=reason,
                dedup_key=dedup_key,
                command=command,
                summary={
                    **summary,
                    "validation_warnings": list(validation.warnings),
                },
            )
        return self._candidate(
            kind=kind,
            status=PlannerCandidateStatus.blocked,
            priority=priority,
            reason="Candidate command failed CommandValidator validation.",
            missing_inputs=[error.code for error in validation.errors],
            dedup_key=dedup_key,
            command=None,
            summary={
                **summary,
                "validation_errors": [
                    error.model_dump(mode="json") for error in validation.errors
                ],
                "validation_warnings": list(validation.warnings),
            },
        )

    def _candidate(
        self,
        *,
        kind: PlannerCandidateKind,
        status: PlannerCandidateStatus,
        priority: float,
        reason: str,
        missing_inputs: list[str] | None = None,
        dedup_key: str = "",
        command: WorkerCommand | None = None,
        summary: dict[str, Any] | None = None,
    ) -> PlannerCandidate:
        return PlannerCandidate(
            candidate_id=self._candidate_id(kind.value, dedup_key),
            kind=kind,
            status=status,
            priority=priority,
            reason=reason,
            missing_inputs=missing_inputs or [],
            dedup_key=dedup_key,
            command=command,
            summary=summary or {},
        )

    @staticmethod
    def _ordered(candidates: list[PlannerCandidate]) -> list[PlannerCandidate]:
        status_order = {
            PlannerCandidateStatus.ready: 0,
            PlannerCandidateStatus.blocked: 1,
            PlannerCandidateStatus.skipped_existing: 2,
        }
        kind_order = {
            PlannerCandidateKind.zap_discovery_passive: 0,
            PlannerCandidateKind.bola_replay_probe: 1,
        }
        return sorted(
            candidates,
            key=lambda item: (
                status_order[item.status],
                kind_order[item.kind],
                -item.priority,
                item.candidate_id,
            ),
        )

    @staticmethod
    def _candidate_id(kind: str, dedup_key: str) -> str:
        digest = hashlib.sha256(f"{kind}|{dedup_key}".encode()).hexdigest()[:16]
        return f"pcand_{digest}"

    @staticmethod
    def _zap_dedup_key(campaign_id: str, target_url: str, seed_urls: list[str]) -> str:
        seed_payload = json.dumps(sorted(seed_urls), sort_keys=True)
        seed_hash = hashlib.sha256(seed_payload.encode()).hexdigest()[:12]
        return f"{campaign_id}|zap_discovery_passive|{target_url}|{seed_hash}"

    @staticmethod
    def _bola_dedup_key(campaign_id: str, hint: BolaObjectPairHint) -> str:
        return "|".join([
            campaign_id,
            "bola_replay_probe",
            hint.operation_id,
            hint.object_id,
            hint.attacker_own_object_id,
            hint.owner_role,
            hint.attacker_role,
        ])

    @staticmethod
    def _missing_bola_inputs(hint: BolaObjectPairHint) -> list[str]:
        required = [
            "object_id",
            "attacker_own_object_id",
            "object_url",
            "attacker_own_object_url",
            "collection_url",
            "owner_role",
            "attacker_role",
            "operation_id",
            "path_template",
            "collection_path_template",
        ]
        return [name for name in required if not str(getattr(hint, name) or "").strip()]

    @staticmethod
    def _existing_zap_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> dict[str, Any] | None:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "zap_discovery_passive":
                continue
            if str(run.get("status") or "").lower() in active_or_done:
                existing_key = PlannerService._extract_zap_dedup_key(
                    campaign_id=campaign_id,
                    run=run,
                )
                if existing_key and existing_key == requested_dedup_key:
                    return run
        return None

    @staticmethod
    def _extract_zap_dedup_key(
        campaign_id: str,
        run: dict[str, Any],
    ) -> str | None:
        # Prefer explicit dedup metadata if a caller persisted it.
        explicit = str(run.get("dedup_key") or "").strip()
        if explicit:
            return explicit

        # Reconstruct from persisted WorkerCommand when available.
        command_id = str(run.get("command_id") or "").strip()
        if not command_id:
            return None
        command = memory_store.get_command(command_id) or {}
        inputs = command.get("inputs") if isinstance(command, dict) else None
        if not isinstance(inputs, dict):
            return None
        target_url = str(inputs.get("target_url") or "").strip()
        seed_urls_raw = inputs.get("seed_urls", [])
        if not target_url:
            return None
        if isinstance(seed_urls_raw, list):
            seed_urls = [str(item) for item in seed_urls_raw]
        else:
            seed_urls = []
        return PlannerService._zap_dedup_key(campaign_id, target_url, seed_urls)

    @staticmethod
    def _existing_bola_signal(campaign_id: str, hint: BolaObjectPairHint) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            try:
                obs = Observation.model_validate(raw)
            except Exception:
                continue
            if obs.type != ObservationType.cross_role_access_signal:
                continue
            details = obs.details or {}
            if (
                str(details.get("operation_id") or obs.operation_id or "") == hint.operation_id
                and str(details.get("object_id") or "") == hint.object_id
                and str(details.get("attacker_own_object_id") or "") == hint.attacker_own_object_id
                and str(details.get("owner_role") or "") == hint.owner_role
                and str(details.get("attacker_role") or "") == hint.attacker_role
            ):
                return True
        return False

    @staticmethod
    def _existing_bola_tool_result(campaign_id: str, hint: BolaObjectPairHint) -> bool:
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "bola_replay_probe":
                continue
            result_raw = memory_store.get_tool_result(str(run.get("tool_run_id") or ""))
            if not result_raw:
                continue
            try:
                result = ToolResult.model_validate(result_raw)
            except Exception:
                continue
            for obs in result.observations:
                if obs.observation_type != "cross_role_access_signal":
                    continue
                details = obs.details or {}
                if (
                    str(details.get("operation_id") or "") == hint.operation_id
                    and str(details.get("object_id") or "") == hint.object_id
                    and str(details.get("attacker_own_object_id") or "") == hint.attacker_own_object_id
                    and str(details.get("owner_role") or "") == hint.owner_role
                    and str(details.get("attacker_role") or "") == hint.attacker_role
                ):
                    return True
        return False
