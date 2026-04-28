"""Phase 12A — read-only backend WorkerCommand planner."""
from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import parse_qsl, urljoin, urlparse

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
    from backend.services.api_graph_path_matcher import (
        find_openapi_operation_match,
        is_static_or_service_asset,
        normalize_api_path,
    )
    from backend.services.command_validator import CommandValidator
    from backend.services.scenario_plan_compiler import ScenarioPlanCompiler
    from backend.services.http.safe_http_client import sanitize_url_for_storage
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
    from services.api_graph_path_matcher import (
        find_openapi_operation_match,
        is_static_or_service_asset,
        normalize_api_path,
    )
    from services.command_validator import CommandValidator
    from services.scenario_plan_compiler import ScenarioPlanCompiler
    from services.http.safe_http_client import sanitize_url_for_storage
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
        self._scenario_compiler = ScenarioPlanCompiler(validator=self._validator)

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
        candidates.extend(self._security_header_candidates(campaign, graph_summary.model_dump(mode="json")))
        candidates.extend(
            self._cors_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
                enable_baseline=bool(getattr(request, "enable_cors_baseline", False)),
            ),
        )
        candidates.extend(
            self._cookie_flag_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
                enable_baseline=bool(getattr(request, "enable_cookie_baseline", False)),
            ),
        )
        candidates.extend(
            self._js_endpoint_extractor_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
            ),
        )
        candidates.extend(
            self._undocumented_endpoint_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
            ),
        )

        operations = self._graph.list_operations(campaign_id)
        valid_op_ids = frozenset(op.operation_id for op in operations)
        compiled = self._scenario_compiler.compile(
            campaign=campaign,
            request=request,
            valid_operation_ids=valid_op_ids,
            graph_operations_total=int(graph_summary.operations_total or 0),
            base_candidates=candidates,
        )
        adjusted: list[PlannerCandidate] = []
        for item in candidates:
            add_p = compiled.priority_add_by_dedup_key.get(item.dedup_key, 0.0)
            if add_p:
                adjusted.append(
                    item.model_copy(
                        update={
                            "priority": float(item.priority) + add_p,
                            "summary": {
                                **(item.summary or {}),
                                "scenario_priority_boost": add_p,
                            },
                        },
                    ),
                )
            else:
                adjusted.append(item)
        candidates = adjusted + compiled.extra_candidates
        warnings.extend(compiled.warnings)

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

        existing_observation = self._existing_zap_output_observation(
            campaign_id=campaign.campaign_id,
            requested_target_url=target_url,
            seed_urls=request.zap.seed_urls,
            campaign_target_url=campaign.target_url,
        )
        if existing_observation is not None:
            return self._candidate(
                kind=PlannerCandidateKind.zap_discovery_passive,
                status=PlannerCandidateStatus.skipped_existing,
                priority=100.0,
                reason="ZAP discovery/passive already produced observations for this campaign.",
                dedup_key=dedup_key,
                summary={
                    **summary,
                    "existing_observation_id": str(
                        existing_observation.get("observation_id")
                        or existing_observation.get("id")
                        or ""
                    ),
                    "existing_observation_type": self._raw_observation_type(existing_observation),
                },
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

    def _security_header_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        candidates: list[PlannerCandidate] = []
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            if self._raw_observation_type(raw) != ObservationType.zap_alert.value:
                continue
            candidates.append(self._security_header_candidate(campaign, raw, graph_summary))
        return candidates

    def _cors_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
        *,
        enable_baseline: bool,
    ) -> list[PlannerCandidate]:
        candidates: list[PlannerCandidate] = []
        cors_urls_seen: set[str] = set()
        passive_context_exists = False
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            obs_type = self._raw_observation_type(raw)
            if obs_type in {ObservationType.zap_alert.value, ObservationType.discovered_endpoint.value}:
                passive_context_exists = True
            if obs_type != ObservationType.zap_alert.value:
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if not self._is_cors_alert(str(details.get("alert_name") or "")):
                continue
            candidate = self._cors_candidate(campaign, raw, graph_summary)
            candidates.append(candidate)
            req_url = ""
            if candidate.command is not None and isinstance(candidate.command.inputs, dict):
                req_url = str(candidate.command.inputs.get("request_url") or "").strip()
            if not req_url and isinstance(candidate.summary, dict):
                req_url = str(candidate.summary.get("request_url") or "").strip()
            canonical = sanitize_url_for_storage(req_url) if req_url else ""
            if canonical:
                cors_urls_seen.add(canonical)

        if enable_baseline and passive_context_exists and not candidates:
            baseline_url, baseline_source = self._select_cors_baseline_url(campaign)
            baseline = self._baseline_cors_candidate(
                campaign=campaign,
                graph_summary=graph_summary,
                request_url=baseline_url,
                candidate_source=baseline_source,
                seen_urls=cors_urls_seen,
            )
            candidates.append(baseline)
        return candidates

    def _cookie_flag_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
        *,
        enable_baseline: bool,
    ) -> list[PlannerCandidate]:
        if not enable_baseline:
            return []
        passive_context_exists = False
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            obs_type = self._raw_observation_type(raw)
            if obs_type in {ObservationType.zap_alert.value, ObservationType.discovered_endpoint.value}:
                passive_context_exists = True
                break
        if not passive_context_exists:
            return []

        baseline_url, baseline_source = self._select_cors_baseline_url(campaign)
        return [
            self._baseline_cookie_flag_candidate(
                campaign=campaign,
                graph_summary=graph_summary,
                request_url=baseline_url,
                candidate_source=baseline_source,
            )
        ]

    def _undocumented_endpoint_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        candidates: list[PlannerCandidate] = []
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            if self._raw_observation_type(raw) != ObservationType.discovered_endpoint.value:
                continue
            candidates.append(
                self._undocumented_endpoint_candidate(campaign, raw, graph_summary),
            )
        return candidates

    def _js_endpoint_extractor_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        candidates: list[PlannerCandidate] = []
        seen_js_urls: set[str] = set()
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            obs_type = self._raw_observation_type(raw)
            if obs_type not in {ObservationType.discovered_endpoint.value, ObservationType.zap_alert.value}:
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            request_url = self._extract_observation_request_url(campaign, details)
            if not self._looks_like_js_asset(request_url):
                continue
            normalized_js_url = _strip_query_and_fragment(
                sanitize_url_for_storage(request_url)
            ) if request_url else ""
            if normalized_js_url in seen_js_urls:
                continue
            if normalized_js_url:
                seen_js_urls.add(normalized_js_url)
            candidates.append(
                self._js_endpoint_extractor_candidate(campaign, raw, graph_summary),
            )
        return candidates

    def _select_cors_baseline_url(self, campaign: Campaign) -> tuple[str, str]:
        for raw in memory_store.list_observations_by_campaign(campaign.campaign_id):
            obs_type = self._raw_observation_type(raw)
            if obs_type not in {ObservationType.discovered_endpoint.value, ObservationType.zap_alert.value}:
                continue
            details = raw.get("details")
            if not isinstance(details, dict):
                continue
            url = self._extract_observation_request_url(campaign, details)
            if not url:
                continue
            if not self._is_allowed_url(campaign, url):
                continue
            return url, "passive_context"
        return campaign.target_url, "campaign_target"

    def _baseline_cors_candidate(
        self,
        *,
        campaign: Campaign,
        graph_summary: dict[str, Any],
        request_url: str,
        candidate_source: str,
        seen_urls: set[str],
    ) -> PlannerCandidate:
        safe_request_url = sanitize_url_for_storage(request_url) if request_url else ""
        dedup_key = "|".join([
            campaign.campaign_id,
            "cors_validator",
            "baseline",
            safe_request_url,
        ])
        summary = {
            "cors_candidate_source": "baseline",
            "baseline_url_source": candidate_source,
            "operation_id": "",
            "path_template": "",
            "request_url": safe_request_url,
            "validation_mode": "baseline_cors_check",
            "origin_probe_label": "evil_example_invalid",
            "audit_flags": [],
            "reason_codes": [],
            "graph_summary": graph_summary,
        }
        if safe_request_url and safe_request_url in seen_urls:
            return self._candidate(
                kind=PlannerCandidateKind.cors_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=37.0,
                reason="Baseline CORS candidate skipped: same request_url already covered by CORS alert candidate.",
                dedup_key=dedup_key,
                summary=summary,
            )

        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id="task_cors_validator_baseline",
            worker_class="misconfiguration",
            strategy="validate_cors_policy",
            tool_name="cors_validator",
            operation_id="",
            seed_request_id="",
            inputs={
                "target_url": campaign.target_url,
                "request_url": request_url,
                "operation_id": "",
                "path_template": "",
                "method": "GET",
                "origin_probe": "https://evil.example.invalid",
                "validation_mode": "single_replay_cors_check",
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=2, timeout_sec=15),
            success_criteria=["cors_validation_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.cors_validator,
            priority=37.0,
            reason="Baseline CORS validation candidate generated from safe campaign/passive context.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _baseline_cookie_flag_candidate(
        self,
        *,
        campaign: Campaign,
        graph_summary: dict[str, Any],
        request_url: str,
        candidate_source: str,
    ) -> PlannerCandidate:
        safe_request_url = sanitize_url_for_storage(request_url) if request_url else ""
        dedup_key = "|".join([
            campaign.campaign_id,
            "cookie_flag_validator",
            "baseline",
            safe_request_url,
        ])
        summary = {
            "cookie_candidate_source": "baseline",
            "baseline_url_source": candidate_source,
            "operation_id": "",
            "path_template": "",
            "request_url": safe_request_url,
            "validation_mode": "baseline_cookie_flag_check",
            "audit_flags": [],
            "reason_codes": [],
            "graph_summary": graph_summary,
        }
        if self._existing_cookie_flag_observation(
            campaign.campaign_id,
            safe_request_url,
            "baseline_cookie_flag_check",
        ):
            return self._candidate(
                kind=PlannerCandidateKind.cookie_flag_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=36.0,
                reason="Matching validated_cookie_flag_issue observation already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )
        existing_run = self._existing_cookie_flag_run(campaign.campaign_id, dedup_key)
        if existing_run is not None:
            return self._candidate(
                kind=PlannerCandidateKind.cookie_flag_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=36.0,
                reason="Existing active/finished cookie_flag_validator ToolRun found.",
                dedup_key=dedup_key,
                summary={**summary, "existing_tool_run_id": existing_run.get("tool_run_id", "")},
            )

        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id="task_cookie_flag_validator_baseline",
            worker_class="misconfiguration",
            strategy="validate_cookie_flags",
            tool_name="cookie_flag_validator",
            operation_id="",
            seed_request_id="",
            inputs={
                "target_url": campaign.target_url,
                "request_url": request_url,
                "operation_id": "",
                "path_template": "",
                "method": "GET",
                "validation_mode": "baseline_cookie_flag_check",
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=1, timeout_sec=15),
            success_criteria=["cookie_flag_validation_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.cookie_flag_validator,
            priority=36.0,
            reason="Baseline cookie flag validation candidate generated from safe campaign/passive context.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _js_endpoint_extractor_candidate(
        self,
        campaign: Campaign,
        raw_observation: dict[str, Any],
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        observation_id = str(
            raw_observation.get("observation_id")
            or raw_observation.get("id")
            or ""
        ).strip()
        details = raw_observation.get("details") if isinstance(raw_observation.get("details"), dict) else {}
        candidate_source = str(details.get("source") or raw_observation.get("source") or self._raw_observation_type(raw_observation)).strip() or "discovered_endpoint"
        js_url = self._extract_observation_request_url(campaign, details)
        safe_js_url = sanitize_url_for_storage(js_url) if js_url else ""
        summary = {
            "js_candidate_source": candidate_source,
            "js_url_sanitized": _strip_query_and_fragment(safe_js_url) if safe_js_url else "",
            "source_observation_id": observation_id,
            "validation_mode": "static_js_endpoint_extraction",
            "max_endpoints": 50,
            "reason_codes": [],
            "audit_flags": [],
            "graph_summary": graph_summary,
        }
        dedup_key = "|".join([
            campaign.campaign_id,
            "js_endpoint_extractor",
            _strip_query_and_fragment(safe_js_url) if safe_js_url else "",
        ])
        if not js_url:
            return self._candidate(
                kind=PlannerCandidateKind.js_endpoint_extractor,
                status=PlannerCandidateStatus.blocked,
                priority=34.0,
                reason="JS endpoint extraction requires a discovered js_url.",
                missing_inputs=["missing_js_url"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["missing_js_url"]},
            )
        if not self._looks_like_js_asset(js_url):
            return self._candidate(
                kind=PlannerCandidateKind.js_endpoint_extractor,
                status=PlannerCandidateStatus.blocked,
                priority=34.0,
                reason="JS endpoint extraction only supports .js assets.",
                missing_inputs=["not_js_asset"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["not_js_asset"]},
            )
        if not self._is_allowed_url(campaign, js_url):
            return self._candidate(
                kind=PlannerCandidateKind.js_endpoint_extractor,
                status=PlannerCandidateStatus.blocked,
                priority=34.0,
                reason="Discovered js_url is outside campaign scope.",
                missing_inputs=["host_not_allowed"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["host_not_allowed"]},
            )
        js_url_key = _strip_query_and_fragment(safe_js_url)
        if self._existing_js_endpoint_extraction_observation(
            campaign.campaign_id,
            js_url_key,
        ):
            prior = PlannerService._js_marker_summary_for_skip(campaign.campaign_id, js_url_key)
            return self._candidate(
                kind=PlannerCandidateKind.js_endpoint_extractor,
                status=PlannerCandidateStatus.skipped_existing,
                priority=34.0,
                reason="Matching js_endpoint_extractor observations already exist for this asset.",
                dedup_key=dedup_key,
                summary={**summary, **prior},
            )
        existing_run = self._existing_js_endpoint_extractor_run(
            campaign.campaign_id,
            dedup_key,
        )
        if existing_run is not None:
            return self._candidate(
                kind=PlannerCandidateKind.js_endpoint_extractor,
                status=PlannerCandidateStatus.skipped_existing,
                priority=34.0,
                reason="Existing active/finished js_endpoint_extractor ToolRun found.",
                dedup_key=dedup_key,
                summary={**summary, "existing_tool_run_id": existing_run.get("tool_run_id", "")},
            )

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_js_endpoint_extractor_{suffix}",
            worker_class="discovery_inventory",
            strategy="extract_js_endpoints",
            tool_name="js_endpoint_extractor",
            operation_id="",
            seed_request_id="",
            inputs={
                "target_url": campaign.target_url,
                "js_url": js_url,
                "source_observation_id": observation_id,
                "validation_mode": "static_js_endpoint_extraction",
                "max_js_bytes": 3000000,
                "max_endpoints": 50,
            },
            budget=CommandBudget(max_requests=1, timeout_sec=15),
            success_criteria=["js_endpoint_extraction_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.js_endpoint_extractor,
            priority=34.0,
            reason="Discovered in-scope JavaScript asset is eligible for safe endpoint extraction.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _undocumented_endpoint_candidate(
        self,
        campaign: Campaign,
        raw_observation: dict[str, Any],
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        observation_id = str(
            raw_observation.get("observation_id")
            or raw_observation.get("id")
            or ""
        ).strip()
        details = raw_observation.get("details") if isinstance(raw_observation.get("details"), dict) else {}
        method = str(details.get("method") or "GET").strip().upper() or "GET"
        request_url = self._extract_observation_request_url(campaign, details)
        normalized_path = normalize_api_path(str(details.get("path") or request_url))
        matched_operation_id = find_openapi_operation_match(
            campaign.campaign_id,
            method,
            normalized_path,
        )
        safe_request_url = sanitize_url_for_storage(request_url) if request_url else ""
        candidate_source = str(details.get("source") or raw_observation.get("source") or "discovered_endpoint").strip() or "discovered_endpoint"
        is_static_asset = is_static_or_service_asset(normalized_path)
        summary = {
            "undocumented_candidate_source": candidate_source,
            "method": method,
            "path": normalized_path,
            "request_url": safe_request_url,
            "openapi_match": bool(matched_operation_id),
            "matched_operation_id": matched_operation_id,
            "is_static_asset": is_static_asset,
            "source_observation_id": observation_id,
            "reason_codes": [],
            "audit_flags": [],
            "graph_summary": graph_summary,
        }
        dedup_key = "|".join([
            campaign.campaign_id,
            "undocumented_endpoint_validator",
            method,
            normalized_path,
        ])
        if not request_url:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Undocumented endpoint validation requires request_url from discovery.",
                missing_inputs=["missing_request_url"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["missing_request_url"]},
            )
        if not normalized_path:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Discovered endpoint is missing a usable path.",
                missing_inputs=["missing_path"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["missing_path"]},
            )
        if method in {"", "OPTIONS"}:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Undocumented endpoint validator supports only GET/HEAD discovery contexts.",
                missing_inputs=["method_not_safe"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["method_not_safe"]},
            )
        if method not in {"GET", "HEAD"}:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Undocumented endpoint validator supports only GET or HEAD.",
                missing_inputs=["method_not_safe"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["method_not_safe"]},
            )
        if is_static_asset:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Static/service assets are excluded from undocumented endpoint validation.",
                missing_inputs=["static_asset_ignored"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["static_asset_ignored"]},
            )
        if not self._is_allowed_url(campaign, request_url):
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Discovered endpoint request_url is outside campaign scope.",
                missing_inputs=["host_not_allowed"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["host_not_allowed"]},
            )
        if matched_operation_id:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.blocked,
                priority=35.0,
                reason="Discovered endpoint matches an OpenAPI operation and is not undocumented.",
                missing_inputs=["openapi_match_present"],
                dedup_key=dedup_key,
                summary={**summary, "reason_codes": ["openapi_match_present"]},
            )
        if self._existing_undocumented_endpoint_observation(
            campaign.campaign_id,
            method,
            normalized_path,
        ):
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=35.0,
                reason="Matching undocumented_endpoint_signal observation already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )
        if self._existing_undocumented_endpoint_evidence_or_finding(
            campaign.campaign_id,
            method,
            normalized_path,
        ):
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=35.0,
                reason="Existing undocumented endpoint evidence/finding already covers this method/path.",
                dedup_key=dedup_key,
                summary=summary,
            )
        existing_run = self._existing_undocumented_endpoint_run(
            campaign.campaign_id,
            dedup_key,
        )
        if existing_run is not None:
            return self._candidate(
                kind=PlannerCandidateKind.undocumented_endpoint_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=35.0,
                reason="Existing active/finished undocumented_endpoint_validator ToolRun found.",
                dedup_key=dedup_key,
                summary={**summary, "existing_tool_run_id": existing_run.get("tool_run_id", "")},
            )

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_undocumented_endpoint_validator_{suffix}",
            worker_class="discovery_inventory",
            strategy="validate_undocumented_endpoint",
            tool_name="undocumented_endpoint_validator",
            operation_id="",
            seed_request_id="",
            inputs={
                "target_url": campaign.target_url,
                "request_url": request_url,
                "method": method,
                "path": normalized_path,
                "source_observation_id": observation_id,
                "validation_mode": "one_shot_undocumented_endpoint_check",
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=1, timeout_sec=15),
            success_criteria=["undocumented_endpoint_validation_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.undocumented_endpoint_validator,
            priority=35.0,
            reason="Discovered runtime endpoint is outside the OpenAPI graph and eligible for safe validation.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _cors_candidate(
        self,
        campaign: Campaign,
        raw_observation: dict[str, Any],
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        observation_id = str(
            raw_observation.get("observation_id")
            or raw_observation.get("id")
            or ""
        ).strip()
        details = raw_observation.get("details")
        if not isinstance(details, dict):
            details = {}
        alert_name = str(details.get("alert_name") or "").strip()
        request_url = self._extract_observation_request_url(campaign, details)
        path_template = str(details.get("path_template") or details.get("path") or "").strip()
        operation_id = str(details.get("operation_id") or raw_observation.get("operation_id") or "").strip()
        method = str(details.get("method") or "GET").strip().upper() or "GET"
        summary = {
            "source_observation_id": observation_id,
            "alert_name": alert_name,
            "operation_id": operation_id,
            "path_template": path_template,
            "request_url": sanitize_url_for_storage(request_url) if request_url else "",
            "validation_mode": "single_replay_cors_check",
            "origin_probe_label": "evil_example_invalid",
            "graph_summary": graph_summary,
        }
        dedup_key = "|".join([
            campaign.campaign_id,
            "cors_validator",
            observation_id,
            operation_id,
            sanitize_url_for_storage(request_url) if request_url else "",
        ])
        if not self._is_cors_alert(alert_name):
            return self._candidate(
                kind=PlannerCandidateKind.cors_validator,
                status=PlannerCandidateStatus.blocked,
                priority=38.0,
                reason="ZAP alert is not a CORS validator context.",
                missing_inputs=["unsupported_context"],
                dedup_key=dedup_key,
                summary=summary,
            )
        if not request_url:
            return self._candidate(
                kind=PlannerCandidateKind.cors_validator,
                status=PlannerCandidateStatus.blocked,
                priority=38.0,
                reason="CORS validation requires request_url from passive signal.",
                missing_inputs=["missing_request_url"],
                dedup_key=dedup_key,
                summary=summary,
            )
        if method not in {"GET", "OPTIONS"}:
            return self._candidate(
                kind=PlannerCandidateKind.cors_validator,
                status=PlannerCandidateStatus.blocked,
                priority=38.0,
                reason="CORS validator supports only GET/OPTIONS contexts.",
                missing_inputs=["method_not_safe"],
                dedup_key=dedup_key,
                summary=summary,
            )

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_cors_validator_{suffix}",
            worker_class="misconfiguration",
            strategy="validate_cors_policy",
            tool_name="cors_validator",
            operation_id=operation_id,
            seed_request_id="",
            inputs={
                "target_url": campaign.target_url,
                "request_url": request_url,
                "operation_id": operation_id,
                "path_template": path_template,
                "method": method,
                "origin_probe": "https://evil.example.invalid",
                "validation_mode": "single_replay_cors_check",
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=2, timeout_sec=15),
            success_criteria=["cors_validation_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.cors_validator,
            priority=38.0,
            reason="Supported ZAP CORS alert is available for validation replay.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        )

    def _security_header_candidate(
        self,
        campaign: Campaign,
        raw_observation: dict[str, Any],
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate:
        observation_id = str(
            raw_observation.get("observation_id")
            or raw_observation.get("id")
            or ""
        ).strip()
        details = raw_observation.get("details")
        if not isinstance(details, dict):
            details = {}
        alert_name = str(details.get("alert_name") or "").strip()
        header_name = self._map_security_header_name(alert_name)
        direct_url = ""
        for key in ("request_url", "target_url", "url"):
            value = str(details.get(key) or "").strip()
            if value:
                direct_url = value
                break
        path_value = str(details.get("path") or "").strip()
        executable_url = self._extract_observation_request_url(campaign, details)
        canonical_source = direct_url or path_value or executable_url
        canonical_url = self._canonical_url_or_path(canonical_source) if canonical_source else ""
        raw_operation_id = str(
            details.get("operation_id")
            or raw_observation.get("operation_id")
            or ""
        ).strip()
        operation_id = raw_operation_id if int(graph_summary.get("operations_total") or 0) > 0 else ""
        path_template = str(details.get("path_template") or details.get("path") or "").strip()
        summary = {
            "source_observation_id": observation_id,
            "alert_name": alert_name,
            "header_name": header_name,
            "canonical_url": canonical_url,
            "path_template": path_template,
            "operation_id": operation_id,
            "observation_operation_id": raw_operation_id,
            "graph_summary": graph_summary,
        }
        dedup_key = self._security_header_dedup_key(
            campaign.campaign_id,
            observation_id,
            header_name,
            canonical_url,
        )

        if not header_name:
            return self._candidate(
                kind=PlannerCandidateKind.security_header_validator,
                status=PlannerCandidateStatus.blocked,
                priority=40.0,
                reason="ZAP alert does not map to a supported security-header validator rule.",
                missing_inputs=["supported_security_header_mapping"],
                dedup_key=dedup_key,
                summary=summary,
            )

        if not executable_url:
            return self._candidate(
                kind=PlannerCandidateKind.security_header_validator,
                status=PlannerCandidateStatus.blocked,
                priority=40.0,
                reason="ZAP alert is missing a usable request_url/target_url/url/path for validation replay.",
                missing_inputs=["request_url"],
                dedup_key=dedup_key,
                summary=summary,
            )

        if self._existing_validated_security_header_observation(
            campaign.campaign_id,
            observation_id,
            header_name,
            canonical_url,
            campaign.target_url,
        ):
            return self._candidate(
                kind=PlannerCandidateKind.security_header_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=40.0,
                reason="Matching validated_security_header_issue observation already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )

        if self._existing_validated_security_header_tool_result(
            campaign.campaign_id,
            observation_id,
            header_name,
            canonical_url,
            campaign.target_url,
        ):
            return self._candidate(
                kind=PlannerCandidateKind.security_header_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=40.0,
                reason="Matching validated_security_header_issue ToolResult observation already exists.",
                dedup_key=dedup_key,
                summary=summary,
            )

        existing_run = self._existing_security_header_run(
            campaign.campaign_id,
            dedup_key,
            campaign.target_url,
        )
        if existing_run is not None:
            return self._candidate(
                kind=PlannerCandidateKind.security_header_validator,
                status=PlannerCandidateStatus.skipped_existing,
                priority=40.0,
                reason="Existing active/finished security_header_validator ToolRun found.",
                dedup_key=dedup_key,
                summary={**summary, "existing_tool_run_id": existing_run.get("tool_run_id", "")},
            )

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_security_header_validator_{suffix}",
            worker_class="misconfiguration",
            strategy="validate_security_header",
            tool_name="security_header_validator",
            operation_id=operation_id,
            seed_request_id="",
            inputs={
                "request_url": executable_url,
                "target_url": executable_url,
                "method": "GET",
                "header_name": header_name,
                "alert_name": alert_name,
                "operation_id": operation_id,
                "path_template": path_template,
                "source_observation_id": observation_id,
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=1, timeout_sec=15),
            success_criteria=["security_header_validation_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.security_header_validator,
            priority=40.0,
            reason="Supported ZAP security-header alert is available for validation replay.",
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
            PlannerCandidateKind.bola_replay_probe: 0,
            PlannerCandidateKind.security_header_validator: 1,
            PlannerCandidateKind.cors_validator: 2,
            PlannerCandidateKind.cookie_flag_validator: 3,
            PlannerCandidateKind.schemathesis_negative_test: 4,
            PlannerCandidateKind.injection_test: 5,
            PlannerCandidateKind.property_mutation_test: 6,
            PlannerCandidateKind.zap_discovery_passive: 7,
            PlannerCandidateKind.js_endpoint_extractor: 8,
            PlannerCandidateKind.undocumented_endpoint_validator: 9,
            PlannerCandidateKind.scenario_plan_blocked: 10,
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
    def _security_header_dedup_key(
        campaign_id: str,
        source_observation_id: str,
        header_name: str,
        canonical_url_or_path: str,
    ) -> str:
        return "|".join([
            campaign_id,
            "security_header_validator",
            source_observation_id,
            header_name,
            canonical_url_or_path,
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
    def _existing_zap_output_observation(
        campaign_id: str,
        requested_target_url: str,
        seed_urls: list[str],
        campaign_target_url: str,
    ) -> dict[str, Any] | None:
        requested_scopes = [
            url for url in [requested_target_url, *seed_urls]
            if str(url or "").strip()
        ]
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) not in {"zap_alert", "discovered_endpoint"}:
                continue
            details = raw.get("details")
            if not isinstance(details, dict):
                continue
            if PlannerService._observation_matches_zap_scope(
                details=details,
                requested_scopes=requested_scopes,
                campaign_target_url=campaign_target_url,
            ):
                return raw
        return None

    @staticmethod
    def _observation_matches_zap_scope(
        *,
        details: dict[str, Any],
        requested_scopes: list[str],
        campaign_target_url: str,
    ) -> bool:
        observation_url = PlannerService._extract_observation_location(
            details=details,
            base_url=campaign_target_url,
        )
        if not observation_url:
            return False
        return any(
            PlannerService._url_matches_scope(observation_url, scope)
            for scope in requested_scopes
        )

    @staticmethod
    def _extract_observation_location(details: dict[str, Any], base_url: str) -> str:
        for key in ("request_url", "target_url", "url"):
            value = str(details.get(key) or "").strip()
            if value:
                return value
        path = str(details.get("path") or "").strip()
        if not path:
            return ""
        if urlparse(path).scheme:
            return path
        if not base_url:
            return path
        return urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))

    @staticmethod
    def _url_matches_scope(candidate_url: str, scope_url: str) -> bool:
        candidate = urlparse(str(candidate_url or "").strip())
        scope = urlparse(str(scope_url or "").strip())
        if not candidate.path and not candidate.netloc:
            return False
        if not scope.path and not scope.netloc:
            return False
        if candidate.scheme and scope.scheme:
            candidate_port = candidate.port or PlannerService._default_port(candidate.scheme)
            scope_port = scope.port or PlannerService._default_port(scope.scheme)
            if (
                candidate.scheme.lower() != scope.scheme.lower()
                or (candidate.hostname or "").lower() != (scope.hostname or "").lower()
                or candidate_port != scope_port
            ):
                return False
        scope_path = scope.path or "/"
        candidate_path = candidate.path or "/"
        if scope_path in {"", "/"}:
            return True
        normalized_scope = scope_path.rstrip("/") or "/"
        normalized_candidate = candidate_path.rstrip("/") or "/"
        return (
            normalized_candidate == normalized_scope
            or normalized_candidate.startswith(normalized_scope + "/")
        )

    @staticmethod
    def _default_port(scheme: str) -> int | None:
        normalized = str(scheme or "").strip().lower()
        if normalized == "http":
            return 80
        if normalized == "https":
            return 443
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

    @staticmethod
    def _raw_observation_type(raw: dict[str, Any]) -> str:
        for key in ("type", "observation_type"):
            value = raw.get(key)
            if value:
                return str(value)
        return ""

    @staticmethod
    def _map_security_header_name(alert_name: str) -> str:
        normalized = str(alert_name or "").strip().lower()
        mapping = {
            "x-frame-options header not set": "X-Frame-Options",
            "x-content-type-options header missing": "X-Content-Type-Options",
            "content security policy (csp) header not set": "Content-Security-Policy",
            "strict-transport-security header not set": "Strict-Transport-Security",
        }
        return mapping.get(normalized, "")

    @staticmethod
    def _is_cors_alert(alert_name: str) -> bool:
        normalized = str(alert_name or "").strip().lower()
        if not normalized:
            return False
        return "cross-origin" in normalized or "access-control-allow-origin" in normalized or "cors" in normalized

    @staticmethod
    def _extract_observation_request_url(campaign: Campaign, details: dict[str, Any]) -> str:
        for key in ("request_url", "target_url", "url"):
            value = str(details.get(key) or "").strip()
            if value:
                return value
        path = str(details.get("path") or "").strip()
        if not path:
            return ""
        if urlparse(path).scheme:
            return path
        return urljoin(campaign.target_url.rstrip("/") + "/", path.lstrip("/"))

    @staticmethod
    def _canonical_url_or_path(url_or_path: str) -> str:
        raw = str(url_or_path or "").strip()
        if not raw:
            return ""
        parsed = urlparse(raw)
        if parsed.scheme:
            return sanitize_url_for_storage(raw)
        return PlannerService._redact_path_query(raw)

    @staticmethod
    def _is_allowed_url(campaign: Campaign, raw_url: str) -> bool:
        parsed = urlparse(str(raw_url or "").strip())
        if not parsed.scheme:
            return True
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower()
        host_port = f"{host}:{parsed.port}" if parsed.port is not None else host
        allowed = {str(h or "").lower() for h in (campaign.allowed_hosts or []) if str(h or "").strip()}
        return bool(allowed) and (host in allowed or host_port in allowed)

    @staticmethod
    def _existing_validated_security_header_observation(
        campaign_id: str,
        source_observation_id: str,
        header_name: str,
        canonical_url: str,
        campaign_target_url: str,
    ) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "validated_security_header_issue":
                continue
            details = raw.get("details")
            if not isinstance(details, dict):
                continue
            existing_source_observation_id = str(details.get("source_observation_id") or "").strip()
            existing_header_name = str(details.get("header_name") or "").strip()
            existing_canonical_url = PlannerService._canonical_from_details(details, campaign_target_url)
            if (
                existing_source_observation_id == source_observation_id
                and existing_header_name == header_name
                and existing_canonical_url == canonical_url
            ):
                return True
        return False

    @staticmethod
    def _existing_validated_security_header_tool_result(
        campaign_id: str,
        source_observation_id: str,
        header_name: str,
        canonical_url: str,
        campaign_target_url: str,
    ) -> bool:
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            result_raw = memory_store.get_tool_result(str(run.get("tool_run_id") or ""))
            if not result_raw:
                continue
            try:
                result = ToolResult.model_validate(result_raw)
            except Exception:
                continue
            for obs in result.observations:
                if obs.observation_type != "validated_security_header_issue":
                    continue
                details = obs.details or {}
                existing_source_observation_id = str(details.get("source_observation_id") or "").strip()
                existing_header_name = str(details.get("header_name") or "").strip()
                existing_canonical_url = PlannerService._canonical_from_details(details, campaign_target_url)
                if (
                    existing_source_observation_id == source_observation_id
                    and existing_header_name == header_name
                    and existing_canonical_url == canonical_url
                ):
                    return True
        return False

    @staticmethod
    def _existing_security_header_run(
        campaign_id: str,
        requested_dedup_key: str,
        campaign_target_url: str,
    ) -> dict[str, Any] | None:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "security_header_validator":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            existing_key = PlannerService._extract_security_header_dedup_key(
                campaign_id=campaign_id,
                run=run,
                campaign_target_url=campaign_target_url,
            )
            if existing_key and existing_key == requested_dedup_key:
                return run
        return None

    @staticmethod
    def _extract_security_header_dedup_key(
        campaign_id: str,
        run: dict[str, Any],
        campaign_target_url: str,
    ) -> str | None:
        explicit = str(run.get("dedup_key") or "").strip()
        if explicit:
            return explicit

        command_id = str(run.get("command_id") or "").strip()
        if not command_id:
            return None
        command = memory_store.get_command(command_id) or {}
        inputs = command.get("inputs") if isinstance(command, dict) else None
        if not isinstance(inputs, dict):
            return None
        source_observation_id = str(inputs.get("source_observation_id") or "").strip()
        header_name = str(inputs.get("header_name") or "").strip()
        canonical_url = PlannerService._canonical_from_details(inputs, campaign_target_url)
        if not source_observation_id or not header_name or not canonical_url:
            return None
        return PlannerService._security_header_dedup_key(
            campaign_id,
            source_observation_id,
            header_name,
            canonical_url,
        )

    @staticmethod
    def _canonical_from_details(details: dict[str, Any], campaign_target_url: str) -> str:
        for key in ("request_url", "target_url", "url"):
            value = str(details.get(key) or "").strip()
            if value:
                return PlannerService._canonical_url_or_path(value)
        path = str(details.get("path") or details.get("path_template") or "").strip()
        if not path:
            return ""
        if urlparse(path).scheme:
            return PlannerService._canonical_url_or_path(path)
        if campaign_target_url:
            resolved = urljoin(campaign_target_url.rstrip("/") + "/", path.lstrip("/"))
            return PlannerService._canonical_url_or_path(resolved)
        return path

    @staticmethod
    def _existing_cookie_flag_observation(
        campaign_id: str,
        request_url: str,
        validation_mode: str,
    ) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "validated_cookie_flag_issue":
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            existing_request_url = sanitize_url_for_storage(str(details.get("request_url") or "").strip())
            existing_validation_mode = str(details.get("validation_mode") or "").strip()
            if existing_request_url == request_url and existing_validation_mode == validation_mode:
                return True
        return False

    @staticmethod
    def _existing_cookie_flag_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> dict[str, Any] | None:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "cookie_flag_validator":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return run
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            existing_key = "|".join([
                campaign_id,
                "cookie_flag_validator",
                "baseline",
                sanitize_url_for_storage(str(inputs.get("request_url") or "").strip()),
            ])
            if existing_key == requested_dedup_key:
                return run
        return None

    @staticmethod
    def _existing_undocumented_endpoint_observation(
        campaign_id: str,
        method: str,
        path: str,
    ) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "undocumented_endpoint_signal":
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            existing_method = str(details.get("method") or raw.get("method") or "").strip().upper()
            existing_path = normalize_api_path(str(details.get("path") or details.get("url_sanitized") or ""))
            if existing_method == method and existing_path == path:
                return True
        return False

    @staticmethod
    def _existing_undocumented_endpoint_evidence_or_finding(
        campaign_id: str,
        method: str,
        path: str,
    ) -> bool:
        for evidence in memory_store.list_evidence_packs_by_campaign(campaign_id):
            if str(evidence.get("vulnerability_class") or "") != "undocumented_api_endpoint":
                continue
            existing_method = str(evidence.get("method") or "").strip().upper()
            existing_path = normalize_api_path(str(evidence.get("endpoint") or ""))
            if existing_method == method and existing_path == path:
                return True
        for finding in memory_store.list_confirmed_findings_by_campaign(campaign_id):
            if str(finding.get("vulnerability_class") or "") != "undocumented_api_endpoint":
                continue
            existing_method = str(finding.get("method") or "").strip().upper()
            existing_path = normalize_api_path(str(finding.get("endpoint") or ""))
            if existing_method == method and existing_path == path:
                return True
        return False

    @staticmethod
    def _existing_undocumented_endpoint_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> dict[str, Any] | None:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "undocumented_endpoint_validator":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return run
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            existing_key = "|".join([
                campaign_id,
                "undocumented_endpoint_validator",
                str(inputs.get("method") or "").strip().upper(),
                normalize_api_path(str(inputs.get("path") or inputs.get("request_url") or "")),
            ])
            if existing_key == requested_dedup_key:
                return run
        return None

    @staticmethod
    def _js_marker_summary_for_skip(campaign_id: str, js_url_sanitized: str) -> dict[str, Any]:
        if not js_url_sanitized:
            return {}
        ref16 = hashlib.sha256(js_url_sanitized.encode("utf-8")).hexdigest()[:16]
        latest_ts = ""
        latest_details: dict[str, Any] | None = None
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "js_endpoint_extraction_result":
                continue
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(details.get("source") or "").strip() != "js_endpoint_extractor":
                continue
            d_url = str(details.get("js_url_sanitized") or "").strip()
            d_ref = str(details.get("source_js_ref") or "").strip()
            if d_url != js_url_sanitized and d_ref != ref16:
                continue
            ts = str(raw.get("created_at") or "")
            if ts >= latest_ts:
                latest_ts = ts
                latest_details = details
        if not latest_details:
            return {}
        out: dict[str, Any] = {}
        res = latest_details.get("result")
        if res is not None and str(res).strip():
            out["prior_result"] = res
        rc = latest_details.get("reason_codes")
        if isinstance(rc, list) and rc:
            out["prior_reason_codes"] = rc
        return out

    @staticmethod
    def _existing_js_endpoint_extraction_observation(
        campaign_id: str,
        js_url_sanitized: str,
    ) -> bool:
        if not js_url_sanitized:
            return False
        ref16 = hashlib.sha256(js_url_sanitized.encode("utf-8")).hexdigest()[:16]
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            otype = PlannerService._raw_observation_type(raw)
            details = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if otype == "js_endpoint_extraction_result":
                if str(details.get("source") or "").strip() != "js_endpoint_extractor":
                    continue
                d_url = str(details.get("js_url_sanitized") or "").strip()
                d_ref = str(details.get("source_js_ref") or "").strip()
                if d_url == js_url_sanitized or d_ref == ref16:
                    return True
                continue
            if otype != "discovered_endpoint":
                continue
            if str(details.get("source") or "").strip() != "js_endpoint_extractor":
                continue
            source_js_ref = str(details.get("source_js_ref") or "").strip()
            if source_js_ref and source_js_ref == ref16:
                return True
        return False

    @staticmethod
    def _existing_js_endpoint_extractor_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> dict[str, Any] | None:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "js_endpoint_extractor":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return run
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            existing_key = "|".join([
                campaign_id,
                "js_endpoint_extractor",
                _strip_query_and_fragment(
                    sanitize_url_for_storage(str(inputs.get("js_url") or "").strip())
                ),
            ])
            if existing_key == requested_dedup_key:
                return run
        return None

    @staticmethod
    def _looks_like_js_asset(raw_url: str) -> bool:
        parsed = urlparse(str(raw_url or "").strip())
        path = parsed.path if parsed.scheme or parsed.netloc else str(raw_url or "").split("?", 1)[0].split("#", 1)[0]
        return str(path or "").strip().lower().endswith(".js")

    @staticmethod
    def _redact_path_query(path_value: str) -> str:
        parsed = urlparse(str(path_value or ""))
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        if query_pairs:
            redacted_query = "&".join(f"{key}=<redacted>" for key, _ in query_pairs)
        else:
            redacted_query = ""
        out = parsed.path or "/"
        if redacted_query:
            out = f"{out}?{redacted_query}"
        if parsed.fragment:
            out = f"{out}#{parsed.fragment}"
        return out


def _strip_query_and_fragment(url: str) -> str:
    parsed = urlparse(str(url or ""))
    return parsed._replace(query="", fragment="").geturl()
