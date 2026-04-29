"""Phase 12A — read-only backend WorkerCommand planner."""
from __future__ import annotations

import hashlib
import json
import re
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
    from backend.models.api_graph import Operation
    from backend.services.command_validator import CommandValidator
    from backend.services.scenario_plan_compiler import ScenarioPlanCompiler
    from backend.services.llm_candidate_advisor import LlmCandidateAdvisor
    from backend.services.bola_object_pair_store import BolaObjectPairStore
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
    from models.api_graph import Operation
    from services.command_validator import CommandValidator
    from services.scenario_plan_compiler import ScenarioPlanCompiler
    from services.llm_candidate_advisor import LlmCandidateAdvisor
    from services.bola_object_pair_store import BolaObjectPairStore
    from services.http.safe_http_client import sanitize_url_for_storage
    from storage.memory_store import memory_store


class PlannerError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


class PlannerService:
    def __init__(self, advisor: LlmCandidateAdvisor | None = None) -> None:
        self._graph = ApiGraphService()
        self._validator = CommandValidator()
        self._scenario_compiler = ScenarioPlanCompiler(validator=self._validator)
        self._advisor = advisor if advisor is not None else LlmCandidateAdvisor()
        self._bola_pairs = BolaObjectPairStore()

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
        candidates.extend(
            self._data_exposure_validator_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
                request,
            ),
        )
        candidates.extend(
            self._resource_instance_extractor_candidates(
                campaign,
            ),
        )
        candidates.extend(
            self._bola_object_pair_builder_candidates(
                campaign,
            ),
        )
        candidates.extend(
            self._ssrf_candidate_detector_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
            ),
        )
        candidates.extend(self._ssrf_probe_candidates(campaign))
        candidates.extend(
            self._auth_flow_detector_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
            ),
        )
        candidates.extend(
            self._test_account_materializer_candidates(
                campaign,
                graph_summary.model_dump(mode="json"),
            ),
        )
        candidates.extend(
            self._resource_seed_worker_candidates(
                campaign,
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
        ready_counts, blocked_counts, ready_sample, blocked_sample = self._build_safe_candidate_samples(candidates)

        return PlannerResponse(
            campaign_id=campaign_id,
            candidates_total=len(candidates),
            ready_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.ready),
            blocked_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.blocked),
            skipped_existing_count=sum(1 for c in candidates if c.status == PlannerCandidateStatus.skipped_existing),
            candidates=candidates,
            ready_candidates_by_kind_count=ready_counts,
            blocked_candidates_by_kind_count=blocked_counts,
            ready_candidates_sample=ready_sample,
            blocked_candidates_sample=blocked_sample,
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
        pair_candidates = self._bola_object_pair_replay_candidates(campaign, graph_summary)
        if pair_candidates:
            return pair_candidates
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

    def _bola_object_pair_replay_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        results: list[PlannerCandidate] = []
        replay_results = self._bola_replay_results_by_pair(campaign.campaign_id)
        granted_exists = any(
            bool(v.get("access_granted") is True)
            for v in replay_results.values()
            if isinstance(v, dict)
        )
        operations_by_id = {
            str(op.operation_id or "").strip(): op
            for op in self._graph.list_operations(campaign.campaign_id)
            if str(op.operation_id or "").strip()
        }
        eligible_rows: list[tuple[float, int, dict[str, Any]]] = []
        for index, row in enumerate(self._bola_pairs.list_bola_object_pairs(campaign.campaign_id)):
            if not isinstance(row, dict):
                continue
            object_pair_id = str(row.get("object_pair_id") or "").strip()
            target_method = str(row.get("target_method") or "GET").strip().upper() or "GET"
            confidence = str(row.get("confidence") or "low").strip().lower()
            attacker_auth_profile_id = str(row.get("attacker_auth_profile_id") or "").strip()
            owner_auth_profile_id = str(row.get("owner_auth_profile_id") or "").strip()
            if not object_pair_id or target_method != "GET" or confidence not in {"high", "medium"} or not attacker_auth_profile_id:
                continue
            score, score_reasons = self._score_bola_object_pair_row(
                row,
                operations_by_id.get(str(row.get("target_operation_id") or "").strip()),
                replay_results,
            )
            row["_baseline_probability_reasons"] = score_reasons
            eligible_rows.append((score, index, row))

        # Highest score first; stable order by original index.
        eligible_rows.sort(key=lambda item: (-float(item[0]), int(item[1])))
        next_ready_emitted = False
        for score, index, row in eligible_rows:
            object_pair_id = str(row.get("object_pair_id") or "").strip()
            target_method = str(row.get("target_method") or "GET").strip().upper() or "GET"
            attacker_auth_profile_id = str(row.get("attacker_auth_profile_id") or "").strip()
            owner_auth_profile_id = str(row.get("owner_auth_profile_id") or "").strip()
            dedup_key = "|".join([campaign.campaign_id, "bola_replay_probe", "bola_replay", object_pair_id])
            replay_for_pair = replay_results.get(object_pair_id, {})
            replay_result_code = str(replay_for_pair.get("result") or "").strip()
            replay_access_granted = bool(replay_for_pair.get("access_granted") is True)
            summary = {
                "validation_mode": "bola_replay",
                "object_pair_id": object_pair_id,
                "resource_type": str(row.get("resource_type") or "unknown"),
                "target_operation_id": str(row.get("target_operation_id") or ""),
                "target_method": target_method,
                "target_path_template": str(row.get("target_path_template") or ""),
                "attacker_auth_profile_id": attacker_auth_profile_id,
                "owner_auth_profile_id": owner_auth_profile_id,
                "bola_replay_candidate_source": "bola_object_pair",
                "reason_codes": ["bola_object_pair_available"],
                "object_pair_score": float(score),
                "baseline_probability_score": float(row.get("baseline_probability_score") or score),
                "baseline_probability_reasons": list(row.get("_baseline_probability_reasons") or []),
                "invalid_pair_penalty": float(row.get("invalid_pair_penalty") or 0.0),
                "previous_owner_status_code": int(row.get("previous_owner_status_code") or 0),
                "object_ref_confidence": str(row.get("object_ref_confidence") or ""),
                "dependency_edge_confidence": str(row.get("dependency_edge_confidence") or ""),
                "baseline_block_reasons": list(row.get("baseline_block_reasons") or []),
                "semantic_id_kind": str(row.get("semantic_id_kind") or ""),
                "path_param_name": str(row.get("path_param_name") or ""),
                "object_id_field": str(row.get("object_id_field") or ""),
                "id_json_path": str(row.get("id_json_path") or ""),
                "source_operation_id": str(row.get("source_operation_id") or ""),
                "source_status_code": int(row.get("source_status_code") or 0),
                "source_reason_codes": list(row.get("source_reason_codes") or []),
                "owner_evidence": bool(row.get("owner_evidence")),
                "dependency_producer_operation_id": str(row.get("dependency_producer_operation_id") or ""),
                "graph_summary": graph_summary,
            }
            if replay_access_granted or granted_exists:
                results.append(self._candidate(
                    kind=PlannerCandidateKind.bola_replay_probe,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=50.0,
                    reason="BOLA replay already granted on this campaign; additional replay candidates are skipped.",
                    dedup_key=dedup_key,
                    summary={**summary, "prior_result": replay_result_code or "attacker_access_granted"},
                ))
                continue
            if replay_result_code:
                results.append(self._candidate(
                    kind=PlannerCandidateKind.bola_replay_probe,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=50.0,
                    reason="Matching bola_replay_result already exists for this object pair.",
                    dedup_key=dedup_key,
                    summary={
                        **summary,
                        "prior_result": replay_result_code,
                        "rework_created": replay_result_code == "invalid_object_pair",
                        "next_pair_available": True,
                    },
                ))
                continue
            if next_ready_emitted:
                # Rotate one pair at a time to avoid consuming budget on parallel replay probes.
                results.append(self._candidate(
                    kind=PlannerCandidateKind.bola_replay_probe,
                    status=PlannerCandidateStatus.blocked,
                    priority=49.0,
                    reason="Replay rotation: waiting for result of a higher-priority untried object pair.",
                    missing_inputs=["prior_untried_object_pair_pending"],
                    dedup_key=dedup_key,
                    summary={**summary, "prior_result": "not_replayed"},
                ))
                continue
            block_reasons = [str(x) for x in (row.get("baseline_block_reasons") or []) if str(x).strip()]
            has_semantic_context = bool(str(row.get("semantic_id_kind") or "").strip()) or bool(str(row.get("object_id_field") or "").strip())
            if block_reasons or (has_semantic_context and float(score) < 50.0):
                missing_inputs = ["low_baseline_probability"] if (has_semantic_context and float(score) < 50.0) else []
                if {"semantic_id_mismatch", "object_id_field_semantic_mismatch", "path_param_semantic_mismatch"} & set(block_reasons):
                    missing_inputs.append("semantic_id_mismatch")
                if "weak_object_ref_provenance" in block_reasons:
                    missing_inputs.append("weak_object_ref_provenance")
                for code in (
                    "object_id_field_semantic_mismatch",
                    "path_param_semantic_mismatch",
                    "source_seed_creation_non_2xx",
                    "source_seed_blocked_required_object_ref",
                ):
                    if code in block_reasons:
                        missing_inputs.append(code)
                results.append(self._candidate(
                    kind=PlannerCandidateKind.bola_replay_probe,
                    status=PlannerCandidateStatus.blocked,
                    priority=49.0,
                    reason="BOLA object pair was deprioritized due to semantic incompatibility or weak baseline probability.",
                    missing_inputs=missing_inputs[:5],
                    dedup_key=dedup_key,
                    summary={**summary, "prior_result": "not_replayed"},
                ))
                continue
            command = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=f"task_bola_replay_probe_{index + 1}",
                worker_class="access_control",
                strategy="replay_bola_object_pair",
                tool_name="bola_replay_probe",
                operation_id=str(row.get("target_operation_id") or ""),
                seed_request_id="",
                inputs={
                    "validation_mode": "bola_replay",
                    "object_pair_id": object_pair_id,
                    "max_requests": 1,
                },
                budget=CommandBudget(max_requests=1, timeout_sec=15),
                success_criteria=["bola_replay_result_recorded"],
            )
            results.append(self._validated_candidate(
                kind=PlannerCandidateKind.bola_replay_probe,
                priority=50.0,
                reason="Prepared BOLA object pair is available for bounded attacker replay.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            ))
            next_ready_emitted = True
        return results

    def _score_bola_object_pair_row(
        self,
        row: dict[str, Any],
        operation: Operation | None,
        replay_results: dict[str, dict[str, Any]],
    ) -> tuple[float, list[str]]:
        score = 0.0
        reasons: list[str] = []
        method = str(row.get("target_method") or "GET").strip().upper()
        confidence = str(row.get("confidence") or "low").strip().lower()
        resource_type = str(row.get("resource_type") or "").strip().lower()
        path_param_name = str(row.get("path_param_name") or "").strip().lower()
        object_id_field = str(row.get("object_id_field") or "").strip().lower()
        target_operation_id = str(row.get("target_operation_id") or "").strip()
        target_path_template = str(row.get("target_path_template") or "").strip()
        metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
        reason_codes = {
            str(code).strip().lower()
            for code in (row.get("reason_codes") or [])
            if isinstance(code, str)
        }
        meta_base_score = float(metadata.get("baseline_probability_score") or 0.0)
        if meta_base_score > 0:
            score += min(meta_base_score, 100.0) * 0.35
            reasons.append("pair_builder_baseline_probability_score")
        semantic_id_kind = str(metadata.get("semantic_id_kind") or row.get("semantic_id_kind") or "").strip().lower()
        source_reason_codes = {
            str(x).strip().lower()
            for x in (metadata.get("source_reason_codes") or row.get("source_reason_codes") or [])
            if str(x).strip()
        }
        owner_evidence = bool(metadata.get("owner_evidence") or row.get("owner_evidence"))
        block_reasons: list[str] = []

        if method == "GET":
            score += 20.0
            reasons.append("consumer_method_get")
        if confidence == "high":
            score += 15.0
            reasons.append("pair_confidence_high")
        elif confidence == "medium":
            score += 9.0
            reasons.append("pair_confidence_medium")

        if "path_param_resource_match" in reason_codes:
            score += 8.0
            reasons.append("path_param_resource_match")
        if any(token and token in path_param_name for token in (resource_type, "id")):
            score += 4.0
            reasons.append("path_param_name_id_like")
        if any(token and token in object_id_field for token in (resource_type, "id")):
            score += 3.0
            reasons.append("object_field_id_like")
        if owner_evidence:
            score += 25.0
            reasons.append("owner_evidence_true")
        else:
            score -= 12.0
            reasons.append("owner_evidence_missing_penalty")
        source_status_code = int(metadata.get("source_status_code") or row.get("source_status_code") or 0)
        if 200 <= source_status_code <= 299:
            score += 20.0
            reasons.append("source_status_2xx")
        elif source_status_code:
            score -= 60.0
            reasons.append("source_status_non_2xx")
            block_reasons.append("weak_object_ref_provenance")
        if semantic_id_kind in {"author_id", "owner_id", "user_id"} and path_param_name in {
            "postid", "post_id", "articleid", "vehicleid", "vehicle_id", "orderid", "order_id", "videoid", "video_id"
        }:
            score -= 100.0
            reasons.append("path_param_semantic_mismatch")
            reasons.append("object_id_field_semantic_mismatch")
            block_reasons.append("object_id_field_semantic_mismatch")
            block_reasons.append("path_param_semantic_mismatch")
        if "creation_non_2xx" in source_reason_codes:
            score -= 40.0
            reasons.append("seed_creation_non_2xx_penalty")
            block_reasons.append("source_seed_creation_non_2xx")
            block_reasons.append("weak_object_ref_provenance")
        if "blocked_required_object_ref" in source_reason_codes:
            score -= 40.0
            reasons.append("blocked_required_object_ref_penalty")
            block_reasons.append("source_seed_blocked_required_object_ref")
            block_reasons.append("weak_object_ref_provenance")

        if operation is not None:
            if bool(operation.auth_required):
                score += 6.0
                reasons.append("consumer_auth_required")
            if operation.response_fields:
                score += 4.0
                reasons.append("consumer_has_response_fields")
            op_resource = str(operation.resource_type or "").strip().lower()
            if resource_type and op_resource and resource_type == op_resource:
                score += 5.0
                reasons.append("consumer_resource_type_match")
            if operation.path_params:
                params = {str(p or "").strip().lower() for p in operation.path_params}
                if path_param_name and path_param_name in params:
                    score += 3.0
                    reasons.append("path_param_declared")

        # Penalize operation/resource combos that previously failed owner baseline / invalid pair.
        invalid_pair_penalty = 0.0
        previous_owner_status_code = 0
        for prev in replay_results.values():
            if not isinstance(prev, dict):
                continue
            if str(prev.get("target_operation_id") or "") != target_operation_id:
                continue
            if str(prev.get("resource_type") or "").strip().lower() != resource_type:
                continue
            prev_result = str(prev.get("result") or prev.get("replay_classification") or "").strip().lower()
            prev_owner_status = int(prev.get("owner_status_code") or 0)
            if prev_owner_status:
                previous_owner_status_code = max(previous_owner_status_code, prev_owner_status)
            if prev_result == "invalid_object_pair":
                invalid_pair_penalty -= 22.0
                reasons.append("previous_invalid_object_pair_penalty")
            if prev_owner_status in {400, 404}:
                invalid_pair_penalty -= 80.0
                reasons.append("previous_owner_baseline_non_2xx_penalty")
            if prev_result in {"replay_error", "inconclusive"}:
                invalid_pair_penalty -= 8.0
                reasons.append("previous_replay_error_penalty")
        score += invalid_pair_penalty

        # Deterministic generic preference when scores tie.
        if resource_type == "vehicle":
            score += 0.2
            reasons.append("resource_type_vehicle_tiebreak")
        elif resource_type == "post":
            score += 0.1
            reasons.append("resource_type_post_tiebreak")

        row["baseline_probability_score"] = float(score)
        row["baseline_probability_reasons"] = reasons[:20]
        row["invalid_pair_penalty"] = float(invalid_pair_penalty)
        row["previous_owner_status_code"] = int(previous_owner_status_code)
        row["object_ref_confidence"] = confidence
        dep_conf = ""
        if isinstance(metadata.get("dependency_edge"), dict):
            dep_conf = str(metadata.get("dependency_edge", {}).get("confidence") or "")
        row["dependency_edge_confidence"] = dep_conf
        row["baseline_block_reasons"] = block_reasons[:20]
        row["semantic_id_kind"] = semantic_id_kind
        row["source_operation_id"] = str(metadata.get("source_operation_id") or row.get("source_operation_id") or "")
        row["source_status_code"] = int(metadata.get("source_status_code") or row.get("source_status_code") or 0)
        row["source_reason_codes"] = [str(x) for x in (metadata.get("source_reason_codes") or row.get("source_reason_codes") or []) if str(x).strip()][:20]
        row["id_json_path"] = str(metadata.get("id_json_path") or row.get("id_json_path") or "")
        row["owner_evidence"] = bool(owner_evidence)
        row["dependency_producer_operation_id"] = str(metadata.get("dependency_producer_operation_id") or "")
        return score, reasons[:20]

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

    def _ssrf_candidate_detector_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        out: list[PlannerCandidate] = []
        for op in self._graph.list_operations(campaign.campaign_id):
            candidate = self._ssrf_candidate_detector_candidate(campaign, op, graph_summary)
            if candidate is not None:
                out.append(candidate)
        return out

    def _ssrf_probe_candidates(self, campaign: Campaign) -> list[PlannerCandidate]:
        """Emit callback-based SSRF proof probes from existing ssrf_candidate_signal observations."""
        auth_ctx = self._latest_test_account_materialization_details(campaign.campaign_id)
        owner_auth_profile_id = ""
        owner_role_hint = "owner"
        if isinstance(auth_ctx, dict):
            owner_auth_profile_id = str(auth_ctx.get("owner_auth_profile_id") or "").strip()
            if owner_auth_profile_id:
                profile = memory_store.get_auth_profile(owner_auth_profile_id) or {}
                owner_role_hint = str(profile.get("role_hint") or "owner")

        stats = self._ssrf_probe_attempt_stats(campaign.campaign_id)
        if stats["any_callback_received"]:
            return [
                self._candidate(
                    kind=PlannerCandidateKind.ssrf_probe,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=25.0,
                    reason="Existing ssrf_probe_result with callback_received=true stops further SSRF probe rotation.",
                    dedup_key=f"{campaign.campaign_id}|ssrf_probe|callback_confirmed",
                    summary={
                        "ssrf_probe_candidate_source": "callback_already_received",
                        "validation_mode": "ssrf_callback_probe",
                        "reason_codes": ["callback_received_already"],
                        "audit_flags": [],
                    },
                ),
            ]

        out: list[PlannerCandidate] = []
        ready_pool: list[tuple[float, str, WorkerCommand, dict[str, Any]]] = []
        seen_signal_keys: set[tuple[str, str]] = set()
        for raw in reversed(memory_store.list_observations_by_campaign(campaign.campaign_id)):
            if PlannerService._raw_observation_type(raw) != "ssrf_candidate_signal":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("validation_mode") or "").strip() != "ssrf_candidate_detection":
                continue
            operation_id = str(det.get("operation_id") or "").strip()
            method = str(det.get("method") or "").strip().upper()
            path = str(det.get("path") or "").strip()
            field_name = str(det.get("field_name") or "").strip()
            field_path = str(det.get("field_path") or "").strip()
            schema_format = str(det.get("schema_format") or "").strip().lower()
            confidence = str(det.get("confidence") or "").strip().lower()
            required_body_fields = [str(x) for x in (det.get("required_body_fields") or []) if str(x).strip()]
            allowed_body_fields = [str(x) for x in (det.get("allowed_body_fields") or []) if str(x).strip()]
            body_field_summaries = [dict(x) for x in (det.get("body_field_summaries") or []) if isinstance(x, dict)]
            schema_summary_source = str(det.get("schema_summary_source") or ("api_graph" if body_field_summaries else "none")).strip() or "none"
            if not (operation_id and method and path and field_name and field_path):
                continue
            if method not in {"POST", "PUT", "PATCH"}:
                continue
            seen_signal_keys.add((operation_id, field_path))

            validation_mode = "ssrf_callback_probe"
            auth_mode = "authenticated" if owner_auth_profile_id else "unauthenticated"
            auth_profile_id = owner_auth_profile_id if owner_auth_profile_id else ""
            role_hint = owner_role_hint if owner_auth_profile_id else ""

            dedup_key = "|".join([
                campaign.campaign_id,
                "ssrf_probe",
                operation_id,
                field_path,
                validation_mode,
                auth_mode,
                auth_profile_id,
            ])
            candidate_key = self._ssrf_probe_candidate_key(
                operation_id=operation_id,
                field_path=field_path,
                validation_mode=validation_mode,
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
            )
            attempted_count = int(stats["attempted_count_by_candidate"].get(candidate_key, 0))
            previous_result = str(stats["latest_result_by_candidate"].get(candidate_key, "") or "")

            if attempted_count > 0:
                attempted_reason_codes = ["ssrf_candidate_already_attempted", "already_attempted"]
                if previous_result in {"target_non_2xx", "target_4xx", "target_5xx", "probe_error", "no_callback_observed"}:
                    attempted_reason_codes.append("previous_failure_penalty")
                out.append(self._candidate(
                    kind=PlannerCandidateKind.ssrf_probe,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=18.0,
                    reason="This SSRF candidate was already attempted; planner rotates to another unattempted candidate.",
                    dedup_key=dedup_key,
                    summary={
                        "validation_mode": validation_mode,
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "auth_mode": auth_mode,
                        "auth_profile_id": auth_profile_id,
                        "role_hint": role_hint,
                        "ssrf_probe_candidate_source": "already_attempted",
                        "previous_result": previous_result,
                        "attempted_count_for_candidate": attempted_count,
                        "ssrf_score": 0.0,
                        "ssrf_score_reasons": ["already_attempted"],
                        "reason_codes": attempted_reason_codes,
                        "audit_flags": [],
                    },
                ))
                continue

            if "{" in path and "}" in path:
                out.append(self._candidate(
                    kind=PlannerCandidateKind.ssrf_probe,
                    status=PlannerCandidateStatus.blocked,
                    priority=22.0,
                    reason="Path parameters require a corpus seed before SSRF callback probe.",
                    missing_inputs=["path_params_seed"],
                    dedup_key=dedup_key,
                    summary={
                        "validation_mode": validation_mode,
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "auth_mode": auth_mode,
                        "auth_profile_id": auth_profile_id,
                        "role_hint": role_hint,
                        "ssrf_probe_candidate_source": "path_params_missing_seed",
                        "previous_result": previous_result,
                        "attempted_count_for_candidate": attempted_count,
                        "ssrf_score": 0.0,
                        "ssrf_score_reasons": ["path_params_present_without_seed"],
                        "reason_codes": ["path_params_require_seed"],
                        "audit_flags": ["path_params_present"],
                    },
                ))
                continue
            if bool(det.get("requires_object_ref")):
                out.append(self._candidate(
                    kind=PlannerCandidateKind.ssrf_probe,
                    status=PlannerCandidateStatus.blocked,
                    priority=22.0,
                    reason="Candidate requires object ref seed before SSRF callback probe.",
                    missing_inputs=["object_ref_seed"],
                    dedup_key=dedup_key,
                    summary={
                        "validation_mode": validation_mode,
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "auth_mode": auth_mode,
                        "auth_profile_id": auth_profile_id,
                        "role_hint": role_hint,
                        "ssrf_probe_candidate_source": "missing_object_ref",
                        "previous_result": previous_result,
                        "attempted_count_for_candidate": attempted_count,
                        "ssrf_score": 0.0,
                        "ssrf_score_reasons": ["object_ref_required"],
                        "reason_codes": ["object_ref_required"],
                        "audit_flags": ["object_ref_required"],
                    },
                ))
                continue

            score, score_reasons = self._ssrf_probe_score(
                operation_id=operation_id,
                method=method,
                path=path,
                field_name=field_name,
                field_path=field_path,
                schema_format=schema_format,
                confidence=confidence,
                auth_mode=auth_mode,
                has_path_params=False,
                requires_object_ref=False,
                attempted_count=attempted_count,
                previous_result=previous_result,
            )

            suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
            cmd = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=f"task_ssrf_probe_{suffix}",
                worker_class="ssrf_external",
                strategy="callback_ssrf_probe",
                tool_name="ssrf_probe",
                operation_id=operation_id,
                inputs={
                    "validation_mode": validation_mode,
                    "operation_id": operation_id,
                    "method": method,
                    "path": path,
                    "field_name": field_name,
                    "field_path": field_path,
                    "auth_mode": auth_mode,
                    "auth_profile_id": auth_profile_id,
                    "role_hint": role_hint,
                    "required_body_fields": required_body_fields,
                    "allowed_body_fields": allowed_body_fields,
                    "body_field_summaries": body_field_summaries,
                    "schema_summary_source": schema_summary_source,
                    "ssrf_target_field": {
                        "field_name": field_name,
                        "field_path": field_path,
                    },
                },
                budget=CommandBudget(max_requests=1, timeout_sec=15),
                success_criteria=["ssrf_callback_probe_recorded"],
            )
            ready_pool.append((
                score,
                dedup_key,
                cmd,
                {
                    "validation_mode": validation_mode,
                    "operation_id": operation_id,
                    "method": method,
                    "path": path,
                    "field_name": field_name,
                    "field_path": field_path,
                    "auth_mode": auth_mode,
                    "auth_profile_id": auth_profile_id,
                    "role_hint": role_hint,
                    "ssrf_probe_candidate_source": "ssrf_candidate_signal",
                    "previous_result": previous_result,
                    "attempted_count_for_candidate": attempted_count,
                    "required_body_fields": required_body_fields,
                    "allowed_body_fields": allowed_body_fields,
                    "body_field_summaries": body_field_summaries,
                    "schema_summary_source": schema_summary_source,
                    "ssrf_target_field": {
                        "field_name": field_name,
                        "field_path": field_path,
                    },
                    "ssrf_score": float(score),
                    "ssrf_score_reasons": score_reasons,
                    "reason_codes": ["url_like_field_mutated_planned"] + (["missing_schema_context"] if schema_summary_source == "none" else []),
                    "audit_flags": [],
                },
            ))

        # Fallback: keep a richer SSRF candidate pool even when detector observations are sparse.
        for op in self._graph.list_operations(campaign.campaign_id):
            operation_id = str(op.operation_id or "").strip()
            method = str(op.method or "").strip().upper()
            path = normalize_api_path(str(op.path_template or ""))
            if not (operation_id and path and method in {"POST", "PUT", "PATCH"}):
                continue
            fields = _detect_ssrf_candidate_fields(
                body_fields=list(op.body_fields or []),
                body_field_summaries=list(op.body_field_summaries or []),
                body_required_fields=list(op.body_required_fields or []),
                operation_tags=list(op.tags or []),
                query_params=list(op.query_params or []),
                operation_id=operation_id,
                path_template=path,
                method=method,
            )
            for field in fields:
                field_name = str(field.get("field_name") or "").strip()
                field_path = str(field.get("field_path") or "").strip()
                schema_format = str(field.get("schema_format") or "").strip().lower()
                confidence = str(field.get("confidence") or "").strip().lower()
                required_body_fields = [str(x) for x in (field.get("required_body_fields") or []) if str(x).strip()]
                allowed_body_fields = [str(x) for x in (field.get("allowed_body_fields") or []) if str(x).strip()]
                body_field_summaries = [dict(x) for x in (field.get("body_field_summaries") or []) if isinstance(x, dict)]
                schema_summary_source = str(field.get("schema_summary_source") or ("api_graph" if body_field_summaries else "none")).strip() or "none"
                if not (field_name and field_path):
                    continue
                if (operation_id, field_path) in seen_signal_keys:
                    continue
                validation_mode = "ssrf_callback_probe"
                auth_mode = "authenticated" if owner_auth_profile_id else "unauthenticated"
                auth_profile_id = owner_auth_profile_id if owner_auth_profile_id else ""
                role_hint = owner_role_hint if owner_auth_profile_id else ""
                dedup_key = "|".join([
                    campaign.campaign_id,
                    "ssrf_probe",
                    operation_id,
                    field_path,
                    validation_mode,
                    auth_mode,
                    auth_profile_id,
                ])
                candidate_key = self._ssrf_probe_candidate_key(
                    operation_id=operation_id,
                    field_path=field_path,
                    validation_mode=validation_mode,
                    auth_mode=auth_mode,
                    auth_profile_id=auth_profile_id,
                )
                attempted_count = int(stats["attempted_count_by_candidate"].get(candidate_key, 0))
                previous_result = str(stats["latest_result_by_candidate"].get(candidate_key, "") or "")
                if attempted_count > 0:
                    out.append(self._candidate(
                        kind=PlannerCandidateKind.ssrf_probe,
                        status=PlannerCandidateStatus.skipped_existing,
                        priority=18.0,
                        reason="This SSRF candidate was already attempted; planner rotates to another unattempted candidate.",
                        dedup_key=dedup_key,
                        summary={
                            "validation_mode": validation_mode,
                            "operation_id": operation_id,
                            "method": method,
                            "path": path,
                            "field_name": field_name,
                            "field_path": field_path,
                            "auth_mode": auth_mode,
                            "auth_profile_id": auth_profile_id,
                            "role_hint": role_hint,
                            "ssrf_probe_candidate_source": "openapi_fallback_already_attempted",
                            "previous_result": previous_result,
                            "attempted_count_for_candidate": attempted_count,
                            "required_body_fields": required_body_fields,
                            "allowed_body_fields": allowed_body_fields,
                            "body_field_summaries": body_field_summaries,
                            "schema_summary_source": schema_summary_source,
                            "ssrf_score": 0.0,
                            "ssrf_score_reasons": ["already_attempted"],
                            "reason_codes": ["ssrf_candidate_already_attempted", "already_attempted"] + (
                                ["previous_failure_penalty"]
                                if previous_result in {"target_non_2xx", "target_4xx", "target_5xx", "probe_error", "no_callback_observed"}
                                else []
                            ),
                            "audit_flags": [],
                        },
                    ))
                    continue
                has_path_params = "{" in path and "}" in path
                if has_path_params:
                    out.append(self._candidate(
                        kind=PlannerCandidateKind.ssrf_probe,
                        status=PlannerCandidateStatus.blocked,
                        priority=22.0,
                        reason="Path parameters require a corpus seed before SSRF callback probe.",
                        missing_inputs=["path_params_seed"],
                        dedup_key=dedup_key,
                        summary={
                            "validation_mode": validation_mode,
                            "operation_id": operation_id,
                            "method": method,
                            "path": path,
                            "field_name": field_name,
                            "field_path": field_path,
                            "auth_mode": auth_mode,
                            "auth_profile_id": auth_profile_id,
                            "role_hint": role_hint,
                            "ssrf_probe_candidate_source": "openapi_fallback_path_params_missing_seed",
                            "previous_result": previous_result,
                            "attempted_count_for_candidate": attempted_count,
                            "required_body_fields": required_body_fields,
                            "allowed_body_fields": allowed_body_fields,
                            "body_field_summaries": body_field_summaries,
                            "schema_summary_source": schema_summary_source,
                            "ssrf_score": 0.0,
                            "ssrf_score_reasons": ["path_params_present_without_seed"],
                            "reason_codes": ["path_params_require_seed"],
                            "audit_flags": ["path_params_present"],
                        },
                    ))
                    continue
                score, score_reasons = self._ssrf_probe_score(
                    operation_id=operation_id,
                    method=method,
                    path=path,
                    field_name=field_name,
                    field_path=field_path,
                    schema_format=schema_format,
                    confidence=confidence,
                    auth_mode=auth_mode,
                    has_path_params=False,
                    requires_object_ref=False,
                    attempted_count=attempted_count,
                    previous_result=previous_result,
                )
                suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
                cmd = WorkerCommand(
                    campaign_id=campaign.campaign_id,
                    task_id=f"task_ssrf_probe_{suffix}",
                    worker_class="ssrf_external",
                    strategy="callback_ssrf_probe",
                    tool_name="ssrf_probe",
                    operation_id=operation_id,
                    inputs={
                        "validation_mode": validation_mode,
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "auth_mode": auth_mode,
                        "auth_profile_id": auth_profile_id,
                        "role_hint": role_hint,
                        "required_body_fields": required_body_fields,
                        "allowed_body_fields": allowed_body_fields,
                        "body_field_summaries": body_field_summaries,
                        "schema_summary_source": schema_summary_source,
                        "ssrf_target_field": {
                            "field_name": field_name,
                            "field_path": field_path,
                        },
                    },
                    budget=CommandBudget(max_requests=1, timeout_sec=15),
                    success_criteria=["ssrf_callback_probe_recorded"],
                )
                ready_pool.append((
                    score,
                    dedup_key,
                    cmd,
                    {
                        "validation_mode": validation_mode,
                        "operation_id": operation_id,
                        "method": method,
                        "path": path,
                        "field_name": field_name,
                        "field_path": field_path,
                        "auth_mode": auth_mode,
                        "auth_profile_id": auth_profile_id,
                        "role_hint": role_hint,
                        "ssrf_probe_candidate_source": "openapi_fallback",
                        "previous_result": previous_result,
                        "attempted_count_for_candidate": attempted_count,
                        "required_body_fields": required_body_fields,
                        "allowed_body_fields": allowed_body_fields,
                        "body_field_summaries": body_field_summaries,
                        "schema_summary_source": schema_summary_source,
                        "ssrf_target_field": {
                            "field_name": field_name,
                            "field_path": field_path,
                        },
                        "ssrf_score": float(score),
                        "ssrf_score_reasons": score_reasons,
                        "reason_codes": _aggregate_ssrf_reason_codes([field]) + (["missing_schema_context"] if schema_summary_source == "none" else []),
                        "audit_flags": [],
                    },
                ))

        # Emit at most one ready ssrf_probe per planning cycle; preserve blocked/skipped diagnostics.
        if ready_pool:
            ready_pool.sort(key=lambda item: item[0], reverse=True)
            best_score, best_key, best_cmd, best_summary = ready_pool[0]
            out.append(self._validated_candidate(
                kind=PlannerCandidateKind.ssrf_probe,
                priority=float(best_score),
                reason="SSRF callback probe candidate selected by bounded rotation among unattempted candidates.",
                dedup_key=best_key,
                command=best_cmd,
                summary=best_summary,
            ))
            for score, dedup_key, _cmd, summary in ready_pool[1:10]:
                out.append(self._candidate(
                    kind=PlannerCandidateKind.ssrf_probe,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=float(score),
                    reason="Candidate retained in SSRF pool but deprioritized this cycle.",
                    dedup_key=dedup_key,
                    summary={
                        **summary,
                        "ssrf_probe_candidate_source": str(summary.get("ssrf_probe_candidate_source") or "ssrf_candidate_signal"),
                        "reason_codes": list(summary.get("reason_codes") or []) + ["deprioritized_this_cycle", "lower_ranked_candidate"],
                        "audit_flags": list(summary.get("audit_flags") or []),
                    },
                ))
        return out[:12]

    @staticmethod
    def _ssrf_probe_attempt_stats(campaign_id: str) -> dict[str, Any]:
        attempted_count_by_candidate: dict[str, int] = {}
        latest_result_by_candidate: dict[str, str] = {}
        any_callback_received = False
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "ssrf_probe_result":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            key = PlannerService._ssrf_probe_candidate_key(
                operation_id=str(det.get("operation_id") or "").strip(),
                field_path=str(det.get("field_path") or "").strip(),
                validation_mode=str(det.get("validation_mode") or "").strip() or "ssrf_callback_probe",
                auth_mode=str(det.get("auth_mode") or "").strip() or "unauthenticated",
                auth_profile_id=str(det.get("auth_profile_id") or "").strip(),
            )
            if not key:
                continue
            attempted_count_by_candidate[key] = int(attempted_count_by_candidate.get(key, 0) or 0) + 1
            latest_result_by_candidate[key] = str(det.get("result") or "")
            if bool(det.get("callback_received")):
                any_callback_received = True
        return {
            "attempted_count_by_candidate": attempted_count_by_candidate,
            "latest_result_by_candidate": latest_result_by_candidate,
            "any_callback_received": any_callback_received,
        }

    @staticmethod
    def _ssrf_probe_candidate_key(
        *,
        operation_id: str,
        field_path: str,
        validation_mode: str,
        auth_mode: str,
        auth_profile_id: str,
    ) -> str:
        op = str(operation_id or "").strip()
        fp = str(field_path or "").strip()
        vm = str(validation_mode or "").strip()
        am = str(auth_mode or "").strip()
        ap = str(auth_profile_id or "").strip()
        if not (op and fp and vm and am):
            return ""
        return "|".join([op, fp, vm, am, ap])

    @staticmethod
    def _ssrf_probe_score(
        *,
        operation_id: str,
        method: str,
        path: str,
        field_name: str,
        field_path: str,
        schema_format: str,
        confidence: str,
        auth_mode: str,
        has_path_params: bool,
        requires_object_ref: bool,
        attempted_count: int,
        previous_result: str,
    ) -> tuple[float, list[str]]:
        score = 20.0
        reasons: list[str] = []
        op_id = str(operation_id or "").strip().lower()
        m = str(method or "").strip().upper()
        p = str(path or "").strip().lower()
        fn = str(field_name or "").strip().lower()
        fp = str(field_path or "").strip().lower()
        sf = str(schema_format or "").strip().lower()
        conf = str(confidence or "").strip().lower()
        prev = str(previous_result or "").strip().lower()

        if not has_path_params and "{" not in p and "}" not in p:
            score += 3.0
            reasons.append("no_path_params")
        elif has_path_params or ("{" in p and "}" in p):
            score -= 4.0
            reasons.append("path_params_penalty")
        if conf == "high":
            score += 4.0
            reasons.append("high_confidence")
        elif conf == "medium":
            score += 2.0
            reasons.append("medium_confidence")
        if sf in {"uri", "url"}:
            score += 3.0
            reasons.append("schema_format_uri")
        if m in {"POST", "PUT", "PATCH"}:
            score += 2.0
            reasons.append("mutation_method")
        positive_hints = (
            "api", "endpoint", "callback", "webhook", "url", "uri", "contact", "notify",
            "target", "destination", "service",
        )
        if any(h in fn for h in positive_hints) or any(h in fp for h in positive_hints):
            score += 3.0
            reasons.append("ssrf_field_semantic_hints")
        op_positive_hints = ("contact", "callback", "webhook", "notify", "request", "report", "mechanic", "integration", "connect")
        if any(h in p for h in op_positive_hints) or any(h in op_id for h in op_positive_hints):
            score += 2.5
            reasons.append("ssrf_operation_semantic_hints")
        if auth_mode == "authenticated":
            score += 0.5
            reasons.append("authenticated_context")
        negative_hints = ("product", "image", "video", "file", "upload", "media", "avatar", "logo", "picture")
        if any(h in fn for h in negative_hints) or any(h in p for h in negative_hints) or any(h in fp for h in negative_hints):
            score -= 4.0
            reasons.append("media_or_asset_bias_down")
        if requires_object_ref:
            score -= 6.0
            reasons.append("requires_object_ref_without_seed")
        if attempted_count > 0:
            score -= 8.0
            reasons.append("already_attempted")
        if prev in {"target_non_2xx", "probe_error", "no_callback_observed", "no_callback"}:
            score -= 6.0
            reasons.append("previous_failed_result_penalty")
        return score, reasons

    def _ssrf_candidate_detector_candidate(
        self,
        campaign: Campaign,
        op: Operation,
        graph_summary: dict[str, Any],
    ) -> PlannerCandidate | None:
        method = str(op.method or "GET").strip().upper() or "GET"
        path_template = normalize_api_path(str(op.path_template or ""))
        if not op.operation_id or not path_template or path_template == "/":
            return None
        candidate_fields = _detect_ssrf_candidate_fields(
            body_fields=list(op.body_fields or []),
            body_field_summaries=list(op.body_field_summaries or []),
            body_required_fields=list(op.body_required_fields or []),
            operation_tags=list(op.tags or []),
            query_params=list(op.query_params or []),
            operation_id=str(op.operation_id or ""),
            path_template=path_template,
            method=method,
        )
        if not candidate_fields:
            return None

        validation_mode = "ssrf_candidate_detection"
        dedup_key = "|".join([
            campaign.campaign_id,
            "ssrf_candidate_detector",
            str(op.operation_id).strip(),
            validation_mode,
        ])
        reason_codes = _aggregate_ssrf_reason_codes(candidate_fields)
        summary = {
            "validation_mode": validation_mode,
            "operation_id": op.operation_id,
            "path_template": path_template,
            "method": method,
            "ssrf_candidate_source": "openapi_schema",
            "candidate_field_count": len(candidate_fields),
            "candidate_fields_sample": [dict(item) for item in candidate_fields[:10]],
            "reason_codes": reason_codes,
            "audit_flags": [],
            "graph_summary": graph_summary,
        }
        existing_obs = self._existing_ssrf_candidate_signal(
            campaign.campaign_id,
            str(op.operation_id).strip(),
            validation_mode,
        )
        if existing_obs:
            return self._candidate(
                kind=PlannerCandidateKind.ssrf_candidate_detector,
                status=PlannerCandidateStatus.skipped_existing,
                priority=19.0,
                reason="Matching ssrf_candidate_signal observation already exists for this operation.",
                dedup_key=dedup_key,
                summary=summary,
            )
        if self._existing_ssrf_candidate_detector_run(campaign.campaign_id, dedup_key):
            return self._candidate(
                kind=PlannerCandidateKind.ssrf_candidate_detector,
                status=PlannerCandidateStatus.skipped_existing,
                priority=19.0,
                reason="Existing ssrf_candidate_detector ToolRun found for this operation.",
                dedup_key=dedup_key,
                summary=summary,
            )

        path_lower = path_template.lower()
        priority = 18.0
        if method in {"POST", "PUT", "PATCH"}:
            priority += 4.0
        if any(hint in path_lower for hint in ("/report", "/mechanic", "/image", "/webhook", "/callback", "/import", "/fetch")):
            priority += 2.0
        if any(str(item.get("confidence") or "").strip().lower() == "high" for item in candidate_fields):
            priority += 1.0

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_ssrf_candidate_detector_{suffix}",
            worker_class="input_validation",
            strategy="detect_ssrf_candidate_fields",
            tool_name="ssrf_candidate_detector",
            operation_id=op.operation_id,
            inputs={
                "target_url": str(campaign.target_url or "").strip(),
                "operation_id": op.operation_id,
                "path_template": path_template,
                "method": method,
                "validation_mode": validation_mode,
                "candidate_fields": [dict(item) for item in candidate_fields[:10]],
            },
            budget=CommandBudget(max_requests=0, timeout_sec=15),
            success_criteria=["ssrf_candidate_detection_recorded"],
        )
        return self._validated_candidate(
            kind=PlannerCandidateKind.ssrf_candidate_detector,
            priority=priority,
            reason="OpenAPI operation contains URL-like request fields that are SSRF-relevant candidates.",
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

    def _build_safe_candidate_samples(
        self,
        candidates: list[PlannerCandidate],
        *,
        sample_limit: int = 10,
    ) -> tuple[dict[str, int], dict[str, int], list[dict[str, Any]], list[dict[str, Any]]]:
        ready_counts: dict[str, int] = {}
        blocked_counts: dict[str, int] = {}
        ready_sample: list[dict[str, Any]] = []
        blocked_sample: list[dict[str, Any]] = []
        for candidate in candidates:
            kind_name = candidate.kind.value
            row = self._safe_candidate_summary(candidate)
            if candidate.status == PlannerCandidateStatus.ready:
                ready_counts[kind_name] = int(ready_counts.get(kind_name, 0) or 0) + 1
                if len(ready_sample) < sample_limit:
                    ready_sample.append(row)
            elif candidate.status == PlannerCandidateStatus.blocked:
                blocked_counts[kind_name] = int(blocked_counts.get(kind_name, 0) or 0) + 1
                if len(blocked_sample) < sample_limit:
                    blocked_sample.append(row)
        return ready_counts, blocked_counts, ready_sample, blocked_sample

    def _safe_candidate_summary(self, candidate: PlannerCandidate) -> dict[str, Any]:
        summary = candidate.summary if isinstance(candidate.summary, dict) else {}
        command = candidate.command.model_dump(mode="json") if candidate.command is not None else {}
        inputs = command.get("inputs") if isinstance(command.get("inputs"), dict) else {}

        def _first_text(*values: Any) -> str:
            for value in values:
                text = str(value or "").strip()
                if text:
                    return text
            return ""

        def _list_texts(value: Any) -> list[str]:
            if not isinstance(value, list):
                return []
            out: list[str] = []
            for item in value:
                text = str(item or "").strip()
                if text:
                    out.append(text)
            return out[:20]

        return {
            "candidate_id": str(candidate.candidate_id or ""),
            "dedup_key": str(candidate.dedup_key or ""),
            "kind": candidate.kind.value,
            "status": candidate.status.value,
            "operation_id": _first_text(
                summary.get("operation_id"),
                summary.get("target_operation_id"),
                command.get("operation_id"),
                inputs.get("operation_id"),
            ),
            "method": _first_text(
                summary.get("method"),
                summary.get("target_method"),
                inputs.get("method"),
            ).upper(),
            "path": _first_text(
                summary.get("path"),
                summary.get("target_path_template"),
                summary.get("path_template"),
                inputs.get("path"),
                inputs.get("path_template"),
            ),
            "path_template": _first_text(
                summary.get("path_template"),
                summary.get("target_path_template"),
                summary.get("path"),
                inputs.get("path_template"),
                inputs.get("path"),
            ),
            "field_name": _first_text(summary.get("field_name"), inputs.get("field_name")),
            "field_path": _first_text(summary.get("field_path"), inputs.get("field_path")),
            "object_pair_id": _first_text(summary.get("object_pair_id"), inputs.get("object_pair_id")),
            "resource_type": _first_text(summary.get("resource_type")),
            "auth_mode": _first_text(summary.get("auth_mode"), inputs.get("auth_mode")),
            "has_path_params": bool(
                "{" in _first_text(
                    summary.get("path"),
                    summary.get("target_path_template"),
                    summary.get("path_template"),
                    inputs.get("path"),
                    inputs.get("path_template"),
                ) and "}" in _first_text(
                    summary.get("path"),
                    summary.get("target_path_template"),
                    summary.get("path_template"),
                    inputs.get("path"),
                    inputs.get("path_template"),
                )
            ),
            "auth_required": bool(summary.get("auth_required")),
            "auth_profile_id": _first_text(summary.get("auth_profile_id"), inputs.get("auth_profile_id")),
            "confidence": _first_text(summary.get("confidence")),
            "previous_result": _first_text(summary.get("previous_result")),
            "utility_score": float(summary.get("utility_score") or summary.get("ssrf_score") or candidate.priority or 0.0),
            "reason_codes": _list_texts(summary.get("reason_codes")),
            "missing_inputs": [str(item) for item in (candidate.missing_inputs or []) if str(item or "").strip()][:20],
            "validation_mode": _first_text(summary.get("validation_mode"), inputs.get("validation_mode")),
            "required_body_fields": _list_texts(summary.get("required_body_fields") or inputs.get("required_body_fields")),
            "allowed_body_fields": _list_texts(summary.get("allowed_body_fields") or inputs.get("allowed_body_fields")),
            "body_field_summaries": [
                item for item in (
                    summary.get("body_field_summaries")
                    if isinstance(summary.get("body_field_summaries"), list)
                    else (inputs.get("body_field_summaries") if isinstance(inputs.get("body_field_summaries"), list) else [])
                )
                if isinstance(item, dict)
            ][:50],
            "schema_summary_source": _first_text(summary.get("schema_summary_source"), inputs.get("schema_summary_source")),
            "ssrf_target_field": (
                summary.get("ssrf_target_field")
                if isinstance(summary.get("ssrf_target_field"), dict)
                else (inputs.get("ssrf_target_field") if isinstance(inputs.get("ssrf_target_field"), dict) else {})
            ),
        }

    def _data_exposure_validator_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
        request: PlannerRequest,
    ) -> list[PlannerCandidate]:
        out: list[PlannerCandidate] = []
        operations = self._graph.list_operations(campaign.campaign_id)
        object_id_ops = frozenset(
            str(x) for x in (graph_summary.get("object_id_operations") or []) if str(x).strip()
        )
        high_resource = frozenset({"user", "vehicle", "order", "post", "mechanic", "report", "video"})
        collection_aliases = (
            "vehicle", "vehicles", "car", "cars", "vin",
            "order", "orders", "purchase",
            "post", "posts", "article", "message",
            "report", "reports",
            "video", "videos", "media",
            "user", "users", "account", "profile",
        )
        auth_ctx = self._latest_test_account_materialization_details(campaign.campaign_id)
        owner_auth_profile_id = ""
        owner_role_hint = "unknown"
        if auth_ctx is not None:
            owner_auth_profile_id = str(auth_ctx.get("owner_auth_profile_id") or "").strip()
            if owner_auth_profile_id:
                profile = memory_store.get_auth_profile(owner_auth_profile_id) or {}
                owner_role_hint = str(profile.get("role_hint") or "owner")

        scored: list[tuple[float, Operation]] = []
        for op in operations:
            method_u = str(op.method or "").strip().upper()
            if method_u != "GET":
                continue
            path_t = normalize_api_path(str(op.path_template or ""))
            if not path_t or path_t == "/":
                continue
            if is_static_or_service_asset(path_t):
                continue
            if not self._is_allowed_url(campaign, self._join_target_path(campaign, path_t)):
                continue
            score = 20.0
            if op.auth_required:
                score += 12.0
            if op.response_fields:
                score += 10.0
            if op.operation_id in object_id_ops:
                score += 30.0
            rt = str(op.resource_type or "").strip().lower()
            if rt in high_resource:
                score += 15.0
            lowered = path_t.lower()
            for hint in collection_aliases:
                if f"/{hint}" in lowered or lowered.rstrip("/").endswith(hint):
                    score += 8.0
                    break
            if "{" in path_t and "}" in path_t:
                score -= 12.0
            if any(token in lowered for token in ("/list", "/search", "/feed", "/all")):
                score += 4.0
            if any(token in lowered for token in ("id", "_id")):
                score += 3.0
            scored.append((score, op))

        scored.sort(key=lambda x: (-x[0], x[1].operation_id))
        max_cands = 25
        rank_slice = scored[:max_cands]
        summaries = [
            LlmCandidateAdvisor.operation_to_safe_summary(op, deterministic_score=prio)
            for prio, op in rank_slice
        ]
        advisor_out = self._advisor.rank_data_exposure_candidates(
            campaign.campaign_id,
            summaries,
            max_candidates=10,
            enable_llm=bool(getattr(request, "enable_llm_candidate_advisor", False)),
        )
        advisor_used = bool(advisor_out.get("advisor_available"))
        rank_rows = advisor_out.get("ranked_candidates") if isinstance(advisor_out.get("ranked_candidates"), list) else []
        rank_meta: dict[str, dict[str, Any]] = {}
        for row in rank_rows:
            if isinstance(row, dict) and row.get("operation_id"):
                rank_meta[str(row["operation_id"])] = row
        op_by_id = {op.operation_id: op for _, op in rank_slice}
        score_by_id = {op.operation_id: float(prio) for prio, op in rank_slice}
        ordered_ops: list[Operation] = []
        seen_ids: set[str] = set()
        for row in rank_rows:
            if not isinstance(row, dict):
                continue
            oid = str(row.get("operation_id") or "").strip()
            op = op_by_id.get(oid)
            if op and oid not in seen_ids:
                ordered_ops.append(op)
                seen_ids.add(oid)
        for _prio, op in rank_slice:
            if op.operation_id not in seen_ids:
                ordered_ops.append(op)
                seen_ids.add(op.operation_id)

        for op in ordered_ops:
            _prio = score_by_id.get(op.operation_id, 20.0)
            path_t = normalize_api_path(str(op.path_template or ""))
            request_url = self._join_target_path(campaign, path_t)
            prior_obs = self._find_prior_data_exposure_execution(
                campaign.campaign_id, op.operation_id, path_t,
            )
            dedup_key = self._data_exposure_dedup_key(
                campaign_id=campaign.campaign_id,
                operation_id=str(op.operation_id or "").strip(),
                path_template=path_t,
                validation_mode="response_field_inventory_check",
                auth_mode="unauthenticated",
                auth_profile_id="",
            )
            if prior_obs is not None:
                row0 = rank_meta.get(op.operation_id) or {}
                adv0: dict[str, Any] = {"llm_candidate_advisor_used": advisor_used}
                if advisor_used and row0:
                    adv0["llm_candidate_priority"] = int(row0.get("priority", 0))
                    adv0["llm_candidate_reason"] = str(row0.get("reason") or "")[:500]
                    adv0["llm_requires_seed"] = bool(row0.get("requires_seed", False))
                    adv0["llm_requires_auth"] = bool(row0.get("requires_auth", False))
                skip_summary: dict[str, Any] = {
                    **adv0,
                    "validation_mode": "response_field_inventory_check",
                    "operation_id": op.operation_id,
                    "path_template": path_t,
                    "method": "GET",
                    "data_exposure_candidate_source": "openapi_graph",
                    "reason_codes": [prior_obs.get("reason_code") or "existing_data_exposure_execution"],
                    "audit_flags": [],
                }
                if prior_obs.get("observation_type") == "data_exposure_probe_result":
                    pr = prior_obs.get("prior_result")
                    if pr is not None:
                        skip_summary["prior_result"] = pr
                    if prior_obs.get("prior_status_code") is not None:
                        skip_summary["prior_status_code"] = prior_obs.get("prior_status_code")
                    prc = prior_obs.get("prior_reason_codes")
                    if prc is not None:
                        skip_summary["prior_reason_codes"] = prc
                out.append(self._candidate(
                    kind=PlannerCandidateKind.data_exposure_validator,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=25.0,
                    reason="Data exposure validator already executed for this operation.",
                    dedup_key=dedup_key,
                    summary=skip_summary,
                ))
                if owner_auth_profile_id and not op.path_params:
                    auth_prior = self._find_prior_data_exposure_execution(
                        campaign.campaign_id,
                        op.operation_id,
                        path_t,
                        auth_mode="authenticated",
                        auth_profile_id=owner_auth_profile_id,
                    )
                    auth_dedup_key = self._data_exposure_dedup_key(
                        campaign_id=campaign.campaign_id,
                        operation_id=str(op.operation_id or "").strip(),
                        path_template=path_t,
                        validation_mode="response_field_inventory_check",
                        auth_mode="authenticated",
                        auth_profile_id=owner_auth_profile_id,
                    )
                    if auth_prior is not None:
                        out.append(self._candidate(
                            kind=PlannerCandidateKind.data_exposure_validator,
                            status=PlannerCandidateStatus.skipped_existing,
                            priority=25.5,
                            reason="Authenticated data exposure validator already executed for this operation.",
                            dedup_key=auth_dedup_key,
                            summary={
                                **adv0,
                                "validation_mode": "response_field_inventory_check",
                                "auth_mode": "authenticated",
                                "auth_profile_id": owner_auth_profile_id,
                                "role_hint": owner_role_hint,
                                "operation_id": op.operation_id,
                                "path_template": path_t,
                                "method": "GET",
                                "data_exposure_candidate_source": "auth_profile_followup",
                                "reason_codes": [auth_prior.get("reason_code") or "existing_authenticated_data_exposure_execution"],
                                "audit_flags": [],
                            },
                        ))
                    elif not self._existing_data_exposure_validator_run(campaign.campaign_id, auth_dedup_key):
                        unauth_retry_status = prior_obs.get("prior_status_code")
                        if unauth_retry_status in {401, 403} or not op.path_params:
                            auth_command = WorkerCommand(
                                campaign_id=campaign.campaign_id,
                                task_id=f"task_data_exposure_auth_{hashlib.sha256(auth_dedup_key.encode()).hexdigest()[:8]}",
                                worker_class="access_control",
                                strategy="validate_response_field_exposure",
                                tool_name="data_exposure_validator",
                                operation_id=op.operation_id,
                                inputs={
                                    "target_url": str(campaign.target_url or "").strip(),
                                    "request_url": request_url,
                                    "operation_id": op.operation_id,
                                    "path_template": path_t,
                                    "method": "GET",
                                    "validation_mode": "response_field_inventory_check",
                                    "max_response_bytes": 262144,
                                    "max_depth": 6,
                                    "max_fields": 200,
                                    "auth_mode": "authenticated",
                                    "auth_profile_id": owner_auth_profile_id,
                                },
                                budget=CommandBudget(max_requests=1, timeout_sec=15),
                                success_criteria=["response_field_inventory_recorded"],
                            )
                            out.append(self._validated_candidate(
                                kind=PlannerCandidateKind.data_exposure_validator,
                                priority=27.0 if unauth_retry_status in {401, 403} else 25.75,
                                reason="Authenticated follow-up with owner auth profile can retry safe GET response inventory.",
                                dedup_key=auth_dedup_key,
                                command=auth_command,
                                summary={
                                    **adv0,
                                    "validation_mode": "response_field_inventory_check",
                                    "auth_mode": "authenticated",
                                    "auth_profile_id": owner_auth_profile_id,
                                    "role_hint": owner_role_hint,
                                    "operation_id": op.operation_id,
                                    "path_template": path_t,
                                    "method": "GET",
                                    "data_exposure_candidate_source": "auth_profile_followup",
                                    "prior_unauth_status_code": unauth_retry_status if unauth_retry_status in {401, 403} else None,
                                    "reason_codes": (
                                        ["auth_profile_available", f"retry_after_unauth_{unauth_retry_status}"]
                                        if unauth_retry_status in {401, 403}
                                        else ["auth_profile_available"]
                                    ),
                                    "audit_flags": [],
                                },
                            ))
                continue
            if self._existing_data_exposure_validator_run(campaign.campaign_id, dedup_key):
                row = rank_meta.get(op.operation_id) or {}
                adv_skip = {"llm_candidate_advisor_used": advisor_used}
                if advisor_used and row:
                    adv_skip["llm_candidate_priority"] = int(row.get("priority", 0))
                    adv_skip["llm_candidate_reason"] = str(row.get("reason") or "")[:500]
                    adv_skip["llm_requires_seed"] = bool(row.get("requires_seed", False))
                    adv_skip["llm_requires_auth"] = bool(row.get("requires_auth", False))
                out.append(self._candidate(
                    kind=PlannerCandidateKind.data_exposure_validator,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=25.0,
                    reason="Existing data_exposure_validator ToolRun for this operation.",
                    dedup_key=dedup_key,
                    summary={
                        **adv_skip,
                        "validation_mode": "response_field_inventory_check",
                        "operation_id": op.operation_id,
                        "path_template": path_t,
                        "method": "GET",
                        "data_exposure_candidate_source": "openapi_graph",
                        "reason_codes": ["existing_tool_run"],
                        "audit_flags": [],
                    },
                ))
                continue

            row = rank_meta.get(op.operation_id) or {}
            base_pri = 25.0 + min(10.0, _prio / 10.0)
            if advisor_used and row:
                try:
                    pidx = float(row.get("priority", 99))
                except Exception:
                    pidx = 99.0
                base_pri += max(0.0, 4.0 - min(pidx, 4.0)) * 0.25

            advisor_fields: dict[str, Any] = {"llm_candidate_advisor_used": advisor_used}
            if advisor_used and row:
                advisor_fields["llm_candidate_priority"] = int(row.get("priority", 0))
                advisor_fields["llm_candidate_reason"] = str(row.get("reason") or "")[:500]
                advisor_fields["llm_requires_seed"] = bool(row.get("requires_seed", False))
                advisor_fields["llm_requires_auth"] = bool(row.get("requires_auth", False))

            seeds = list(op.successful_seed_request_ids or [])
            has_seed_for_path_params = bool(seeds)
            auth_mode_blocked_by_path_params = bool(op.path_params and not has_seed_for_path_params)
            if owner_auth_profile_id and auth_mode_blocked_by_path_params:
                auth_dedup_key = self._data_exposure_dedup_key(
                    campaign_id=campaign.campaign_id,
                    operation_id=str(op.operation_id or "").strip(),
                    path_template=path_t,
                    validation_mode="response_field_inventory_check",
                    auth_mode="authenticated",
                    auth_profile_id=owner_auth_profile_id,
                )
                out.append(self._candidate(
                    kind=PlannerCandidateKind.data_exposure_validator,
                    status=PlannerCandidateStatus.blocked,
                    priority=base_pri + 0.5,
                    reason="Path parameters require corpus seed request before authenticated safe GET replay.",
                    missing_inputs=["path_params_without_seed"],
                    dedup_key=auth_dedup_key,
                    command=None,
                    summary={
                        **advisor_fields,
                        "validation_mode": "response_field_inventory_check",
                        "auth_mode": "authenticated",
                        "auth_profile_id": owner_auth_profile_id,
                        "role_hint": owner_role_hint,
                        "operation_id": op.operation_id,
                        "path_template": path_t,
                        "method": "GET",
                        "data_exposure_candidate_source": "auth_profile_followup",
                        "reason_codes": ["path_params_without_seed"],
                        "audit_flags": ["backend_hard_rule_after_advisor"],
                    },
                ))
            if op.path_params and not seeds:
                out.append(self._candidate(
                    kind=PlannerCandidateKind.data_exposure_validator,
                    status=PlannerCandidateStatus.blocked,
                    priority=base_pri,
                    reason="Path parameters require a corpus seed request before safe GET replay for data_exposure_validator.",
                    missing_inputs=["path_params_without_seed"],
                    dedup_key=dedup_key,
                    command=None,
                    summary={
                        **advisor_fields,
                        "validation_mode": "response_field_inventory_check",
                        "operation_id": op.operation_id,
                        "path_template": path_t,
                        "method": "GET",
                        "data_exposure_candidate_source": "openapi_graph",
                        "reason_codes": ["path_params_without_seed"],
                        "audit_flags": ["backend_hard_rule_after_advisor"],
                    },
                ))
                continue

            suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
            command = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=f"task_data_exposure_{suffix}",
                worker_class="access_control",
                strategy="validate_response_field_exposure",
                tool_name="data_exposure_validator",
                operation_id=op.operation_id,
                inputs={
                    "target_url": str(campaign.target_url or "").strip(),
                    "request_url": request_url,
                    "operation_id": op.operation_id,
                    "path_template": path_t,
                    "method": "GET",
                    "validation_mode": "response_field_inventory_check",
                    "max_response_bytes": 262144,
                    "max_depth": 6,
                    "max_fields": 200,
                },
                budget=CommandBudget(max_requests=1, timeout_sec=15),
                success_criteria=["response_field_inventory_recorded"],
            )
            summary = {
                **advisor_fields,
                "validation_mode": "response_field_inventory_check",
                "operation_id": op.operation_id,
                "path_template": path_t,
                "method": "GET",
                "data_exposure_candidate_source": "openapi_graph",
                "reason_codes": [],
                "audit_flags": [],
            }
            out.append(self._validated_candidate(
                kind=PlannerCandidateKind.data_exposure_validator,
                priority=base_pri,
                reason="GET operation from API graph eligible for safe response field inventory.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            ))
            if owner_auth_profile_id and (not op.path_params or has_seed_for_path_params):
                auth_prior = self._find_prior_data_exposure_execution(
                    campaign.campaign_id,
                    op.operation_id,
                    path_t,
                    auth_mode="authenticated",
                    auth_profile_id=owner_auth_profile_id,
                )
                auth_dedup_key = self._data_exposure_dedup_key(
                    campaign_id=campaign.campaign_id,
                    operation_id=str(op.operation_id or "").strip(),
                    path_template=path_t,
                    validation_mode="response_field_inventory_check",
                    auth_mode="authenticated",
                    auth_profile_id=owner_auth_profile_id,
                )
                if auth_prior is not None:
                    out.append(self._candidate(
                        kind=PlannerCandidateKind.data_exposure_validator,
                        status=PlannerCandidateStatus.skipped_existing,
                        priority=base_pri + 0.5,
                        reason="Authenticated data exposure validator already executed for this operation.",
                        dedup_key=auth_dedup_key,
                        summary={
                            **advisor_fields,
                            "validation_mode": "response_field_inventory_check",
                            "auth_mode": "authenticated",
                            "auth_profile_id": owner_auth_profile_id,
                            "role_hint": owner_role_hint,
                            "operation_id": op.operation_id,
                            "path_template": path_t,
                            "method": "GET",
                            "data_exposure_candidate_source": "auth_profile_followup",
                            "reason_codes": [auth_prior.get("reason_code") or "existing_authenticated_data_exposure_execution"],
                            "audit_flags": [],
                        },
                    ))
                    continue
                if self._existing_data_exposure_validator_run(campaign.campaign_id, auth_dedup_key):
                    out.append(self._candidate(
                        kind=PlannerCandidateKind.data_exposure_validator,
                        status=PlannerCandidateStatus.skipped_existing,
                        priority=base_pri + 0.5,
                        reason="Existing authenticated data_exposure_validator ToolRun for this operation.",
                        dedup_key=auth_dedup_key,
                        summary={
                            **advisor_fields,
                            "validation_mode": "response_field_inventory_check",
                            "auth_mode": "authenticated",
                            "auth_profile_id": owner_auth_profile_id,
                            "role_hint": owner_role_hint,
                            "operation_id": op.operation_id,
                            "path_template": path_t,
                            "method": "GET",
                            "data_exposure_candidate_source": "auth_profile_followup",
                            "reason_codes": ["existing_tool_run"],
                            "audit_flags": [],
                        },
                    ))
                    continue
                unauth_retry_status = None
                if prior_obs is not None:
                    unauth_retry_status = prior_obs.get("prior_status_code")
                if unauth_retry_status in {401, 403} or (not op.path_params or has_seed_for_path_params):
                    auth_command = WorkerCommand(
                        campaign_id=campaign.campaign_id,
                        task_id=f"task_data_exposure_auth_{hashlib.sha256(auth_dedup_key.encode()).hexdigest()[:8]}",
                        worker_class="access_control",
                        strategy="validate_response_field_exposure",
                        tool_name="data_exposure_validator",
                        operation_id=op.operation_id,
                        inputs={
                            "target_url": str(campaign.target_url or "").strip(),
                            "request_url": request_url,
                            "operation_id": op.operation_id,
                            "path_template": path_t,
                            "method": "GET",
                            "validation_mode": "response_field_inventory_check",
                            "max_response_bytes": 262144,
                            "max_depth": 6,
                            "max_fields": 200,
                            "auth_mode": "authenticated",
                            "auth_profile_id": owner_auth_profile_id,
                        },
                        budget=CommandBudget(max_requests=1, timeout_sec=15),
                        success_criteria=["response_field_inventory_recorded"],
                    )
                    reason_codes = ["auth_profile_available"]
                    if unauth_retry_status in {401, 403}:
                        reason_codes.append(f"retry_after_unauth_{unauth_retry_status}")
                    auth_summary = {
                        **advisor_fields,
                        "validation_mode": "response_field_inventory_check",
                        "auth_mode": "authenticated",
                        "auth_profile_id": owner_auth_profile_id,
                        "role_hint": owner_role_hint,
                        "operation_id": op.operation_id,
                        "path_template": path_t,
                        "method": "GET",
                        "data_exposure_candidate_source": "auth_profile_followup",
                        "prior_unauth_status_code": unauth_retry_status if unauth_retry_status in {401, 403} else None,
                        "reason_codes": reason_codes,
                        "audit_flags": [],
                    }
                    out.append(self._validated_candidate(
                        kind=PlannerCandidateKind.data_exposure_validator,
                        priority=base_pri + (2.0 if unauth_retry_status in {401, 403} else 0.75),
                        reason="Authenticated follow-up with owner auth profile can retry safe GET response inventory.",
                        dedup_key=auth_dedup_key,
                        command=auth_command,
                        summary=auth_summary,
                    ))
        return out

    def _resource_instance_extractor_candidates(
        self,
        campaign: Campaign,
    ) -> list[PlannerCandidate]:
        out: list[PlannerCandidate] = []
        seen_dedup: set[str] = set()
        observations = memory_store.list_observations_by_campaign(campaign.campaign_id)
        for raw in observations:
            otype = self._raw_observation_type(raw)
            if otype not in {"response_field_inventory", "data_exposure_signal"}:
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("tool_name") or "").strip() != "data_exposure_validator":
                continue
            if str(det.get("auth_mode") or "unauthenticated").strip() != "authenticated":
                continue
            auth_profile_id = str(det.get("auth_profile_id") or "").strip()
            if not auth_profile_id:
                continue
            field_count = self._safe_int(det.get("field_count"), 0)
            sensitive_field_count = self._safe_int(det.get("sensitive_field_count"), 0)
            if otype == "response_field_inventory" and field_count <= 0:
                continue
            source_observation_id = str(raw.get("observation_id") or "").strip()
            if not source_observation_id:
                continue
            operation_id = str(det.get("operation_id") or raw.get("operation_id") or "").strip()
            source_path = normalize_api_path(str(det.get("path") or ""))
            dedup_key = "|".join([
                campaign.campaign_id,
                "resource_instance_extractor",
                source_observation_id or operation_id or source_path,
                "resource_instance_extraction",
            ])
            if dedup_key in seen_dedup:
                continue
            seen_dedup.add(dedup_key)
            summary = {
                "validation_mode": "resource_instance_extraction",
                "source_observation_id": source_observation_id,
                "source_operation_id": operation_id,
                "source_path": source_path,
                "auth_profile_id": auth_profile_id,
                "role_hint": str(det.get("role_hint") or "unknown"),
                "resource_instance_candidate_source": "authenticated_inventory",
                "field_count": field_count,
                "sensitive_field_count": sensitive_field_count,
                "reason_codes": ["authenticated_inventory_available"],
            }
            if self._existing_resource_instance_inventory_for_source(campaign.campaign_id, source_observation_id):
                out.append(self._candidate(
                    kind=PlannerCandidateKind.resource_instance_extractor,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=24.6,
                    reason="Resource instance inventory already exists for this source observation.",
                    dedup_key=dedup_key,
                    summary=summary,
                ))
                continue
            if self._existing_resource_instance_extractor_run(campaign.campaign_id, dedup_key):
                out.append(self._candidate(
                    kind=PlannerCandidateKind.resource_instance_extractor,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=24.6,
                    reason="Existing resource_instance_extractor ToolRun found for this source observation.",
                    dedup_key=dedup_key,
                    summary=summary,
                ))
                continue
            command = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=f"task_resource_instance_{hashlib.sha256(dedup_key.encode()).hexdigest()[:8]}",
                worker_class="auth_context",
                strategy="extract_resource_instances",
                tool_name="resource_instance_extractor",
                operation_id=operation_id,
                inputs={
                    "source_observation_id": source_observation_id,
                    "source_operation_id": operation_id,
                    "source_path": source_path,
                    "auth_profile_id": auth_profile_id,
                    "role_hint": str(det.get("role_hint") or "unknown"),
                    "validation_mode": "resource_instance_extraction",
                    "max_instances": 20,
                },
                budget=CommandBudget(max_requests=0, timeout_sec=15),
                success_criteria=["resource_instance_inventory_recorded"],
            )
            out.append(self._validated_candidate(
                kind=PlannerCandidateKind.resource_instance_extractor,
                priority=24.75,
                reason="Authenticated inventory can be mined for safe object-id refs.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            ))
        return out

    def _resource_seed_worker_candidates(
        self,
        campaign: Campaign,
    ) -> list[PlannerCandidate]:
        det = self._latest_test_account_materialization_details(campaign.campaign_id)
        if det is None:
            return []
        owner_auth_profile_id = str(det.get("owner_auth_profile_id") or "").strip()
        if not owner_auth_profile_id:
            return []

        existing_refs = memory_store.list_runtime_resource_instances_by_campaign(campaign.campaign_id)
        object_refs_count = len(existing_refs) if isinstance(existing_refs, list) else 0
        if object_refs_count > 0:
            return []

        existing_seed = self._existing_resource_seed_result(campaign.campaign_id)
        if existing_seed is not None:
            return [
                self._candidate(
                    kind=PlannerCandidateKind.resource_seed_worker,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=24.2,
                    reason="Resource seed worker already executed for this campaign.",
                    dedup_key=f"{campaign.campaign_id}|resource_seed_worker|resource_seed",
                    summary={
                        "validation_mode": "resource_seed",
                        "resource_seed_candidate_source": "auth_profile_no_object_refs",
                        "owner_auth_profile_id": owner_auth_profile_id,
                        "object_refs_count": 0,
                        "reason_codes": ["existing_resource_seed_result", f"seed_status_{existing_seed}"],
                    },
                )
            ]

        dedup_key = "|".join([campaign.campaign_id, "resource_seed_worker", "resource_seed", owner_auth_profile_id])
        if self._existing_resource_seed_worker_run(campaign.campaign_id, dedup_key):
            return [
                self._candidate(
                    kind=PlannerCandidateKind.resource_seed_worker,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=24.2,
                    reason="Existing resource_seed_worker ToolRun found.",
                    dedup_key=dedup_key,
                    summary={
                        "validation_mode": "resource_seed",
                        "resource_seed_candidate_source": "auth_profile_no_object_refs",
                        "owner_auth_profile_id": owner_auth_profile_id,
                        "object_refs_count": 0,
                        "reason_codes": ["existing_resource_seed_worker_run"],
                    },
                )
            ]

        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_resource_seed_{hashlib.sha256(dedup_key.encode()).hexdigest()[:8]}",
            worker_class="auth_context",
            strategy="seed_resource_instance",
            tool_name="resource_seed_worker",
            operation_id="",
            inputs={
                "validation_mode": "resource_seed",
                "owner_auth_profile_id": owner_auth_profile_id,
                "max_seed_attempts": 3,
                "max_followup_requests": 1,
            },
            budget=CommandBudget(max_requests=3, timeout_sec=15),
            success_criteria=["resource_seed_result_recorded"],
        )
        summary = {
            "validation_mode": "resource_seed",
            "resource_seed_candidate_source": "auth_profile_no_object_refs",
            "owner_auth_profile_id": owner_auth_profile_id,
            "object_refs_count": 0,
            "reason_codes": ["auth_profile_available", "object_refs_missing"],
        }
        return [
            self._validated_candidate(
                kind=PlannerCandidateKind.resource_seed_worker,
                priority=24.25,
                reason="Owner auth profile available but no object refs exist; seed one safe resource id for diagnostics.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            )
        ]

    def _bola_object_pair_builder_candidates(
        self,
        campaign: Campaign,
    ) -> list[PlannerCandidate]:
        det = self._latest_test_account_materialization_details(campaign.campaign_id)
        if det is None:
            return []
        owner_auth_profile_id = str(det.get("owner_auth_profile_id") or "").strip()
        attacker_auth_profile_id = str(det.get("attacker_auth_profile_id") or "").strip()
        if not owner_auth_profile_id:
            return []
        if not attacker_auth_profile_id:
            return [
                self._candidate(
                    kind=PlannerCandidateKind.bola_object_pair_builder,
                    status=PlannerCandidateStatus.blocked,
                    priority=24.4,
                    reason="BOLA object pair building requires attacker auth profile.",
                    dedup_key=f"{campaign.campaign_id}|bola_object_pair_builder|bola_object_pair_building|missing_attacker",
                    missing_inputs=["attacker_auth_profile_id"],
                    summary={
                        "validation_mode": "bola_object_pair_building",
                        "owner_auth_profile_id": owner_auth_profile_id,
                        "attacker_auth_profile_id": "",
                        "resource_instances_count": 0,
                        "object_refs_count": 0,
                        "resource_types": [],
                        "bola_pair_candidate_source": "resource_instances_available",
                        "reason_codes": ["attacker_auth_profile_missing"],
                    },
                )
            ]
        resource_instances = memory_store.list_runtime_resource_instances_by_campaign(campaign.campaign_id)
        if not isinstance(resource_instances, list) or not resource_instances:
            return []
        if self._existing_bola_object_pair_inventory(campaign.campaign_id):
            return [
                self._candidate(
                    kind=PlannerCandidateKind.bola_object_pair_builder,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=24.4,
                    reason="BOLA object pair inventory already exists for this campaign.",
                    dedup_key=f"{campaign.campaign_id}|bola_object_pair_builder|bola_object_pair_building|{owner_auth_profile_id}|{attacker_auth_profile_id}",
                    summary={
                        "validation_mode": "bola_object_pair_building",
                        "owner_auth_profile_id": owner_auth_profile_id,
                        "attacker_auth_profile_id": attacker_auth_profile_id,
                        "resource_instances_count": len(resource_instances),
                        "object_refs_count": len(resource_instances),
                        "resource_types": sorted({str(x.get('resource_type') or 'unknown') for x in resource_instances if isinstance(x, dict)})[:20],
                        "bola_pair_candidate_source": "resource_instances_available",
                        "reason_codes": ["existing_bola_object_pair_inventory"],
                    },
                )
            ]
        dedup_key = f"{campaign.campaign_id}|bola_object_pair_builder|bola_object_pair_building|{owner_auth_profile_id}|{attacker_auth_profile_id}"
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_bola_pair_{hashlib.sha256(dedup_key.encode()).hexdigest()[:8]}",
            worker_class="access_control",
            strategy="build_bola_object_pairs",
            tool_name="bola_object_pair_builder",
            operation_id="",
            inputs={
                "validation_mode": "bola_object_pair_building",
                "owner_auth_profile_id": owner_auth_profile_id,
                "attacker_auth_profile_id": attacker_auth_profile_id,
                "resource_instances_count": len(resource_instances),
                "object_refs_count": len(resource_instances),
                "resource_types": sorted({str(x.get('resource_type') or 'unknown') for x in resource_instances if isinstance(x, dict)})[:20],
                "max_object_pairs": 10,
            },
            budget=CommandBudget(max_requests=0, timeout_sec=15),
            success_criteria=["bola_object_pair_inventory_recorded"],
        )
        summary = {
            "validation_mode": "bola_object_pair_building",
            "owner_auth_profile_id": owner_auth_profile_id,
            "attacker_auth_profile_id": attacker_auth_profile_id,
            "resource_instances_count": len(resource_instances),
            "object_refs_count": len(resource_instances),
            "resource_types": sorted({str(x.get('resource_type') or 'unknown') for x in resource_instances if isinstance(x, dict)})[:20],
            "bola_pair_candidate_source": "resource_instances_available",
            "reason_codes": ["auth_profiles_available", "object_refs_available"],
        }
        return [
            self._validated_candidate(
                kind=PlannerCandidateKind.bola_object_pair_builder,
                priority=24.45,
                reason="Auth profiles and object refs are available for safe BOLA object-pair inventory building.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            )
        ]

    def _auth_flow_detector_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        out: list[PlannerCandidate] = []
        if int(graph_summary.get("operations_total") or 0) <= 0:
            return out
        dedup_key = "|".join([campaign.campaign_id, "auth_flow_detector", "auth_flow_detection"])
        if self._existing_auth_flow_detection_observation(campaign.campaign_id):
            out.append(self._candidate(
                kind=PlannerCandidateKind.auth_flow_detector,
                status=PlannerCandidateStatus.skipped_existing,
                priority=22.0,
                reason="Auth flow detector already executed for this campaign.",
                dedup_key=dedup_key,
                summary={
                    "validation_mode": "auth_flow_detection",
                    "operation_id": "",
                    "path_template": "",
                    "method": "N/A",
                    "data_source": "openapi_graph",
                    "reason_codes": ["existing_auth_flow_signal"],
                },
            ))
            return out

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_auth_flow_{suffix}",
            worker_class="auth_context",
            strategy="detect_auth_flow",
            tool_name="auth_flow_detector",
            operation_id="",
            inputs={
                "validation_mode": "auth_flow_detection",
                "max_operations_scanned": 200,
            },
            budget=CommandBudget(max_requests=0, timeout_sec=10),
            success_criteria=["auth_flow_signal_recorded"],
        )
        summary = {
            "validation_mode": "auth_flow_detection",
            "operation_id": "",
            "path_template": "",
            "method": "N/A",
            "data_source": "openapi_graph",
            "reason_codes": [],
            "audit_flags": [],
        }
        out.append(self._validated_candidate(
            kind=PlannerCandidateKind.auth_flow_detector,
            priority=22.0,
            reason="OpenAPI graph available for diagnostic auth-flow candidate detection.",
            dedup_key=dedup_key,
            command=command,
            summary=summary,
        ))
        return out

    def _test_account_materializer_candidates(
        self,
        campaign: Campaign,
        graph_summary: dict[str, Any],
    ) -> list[PlannerCandidate]:
        _ = graph_summary
        details = self._latest_auth_flow_signal_details(campaign.campaign_id)
        if details is None:
            return []

        signup_candidates = details.get("signup_candidates") if isinstance(details.get("signup_candidates"), list) else []
        login_candidates = details.get("login_candidates") if isinstance(details.get("login_candidates"), list) else []
        token_candidates = details.get("token_response_candidates") if isinstance(details.get("token_response_candidates"), list) else []
        detected = bool(details.get("auth_flow_detected"))
        if not detected:
            return []

        signup = signup_candidates[0] if signup_candidates else {}
        login = login_candidates[0] if login_candidates else {}
        signup_operation_id = str(signup.get("operation_id") or "").strip()
        login_operation_id = str(login.get("operation_id") or "").strip()
        token_operation_id = str((token_candidates[0] if token_candidates else {}).get("operation_id") or "").strip()

        dedup_key = "|".join([
            campaign.campaign_id,
            "test_account_materializer",
            signup_operation_id,
            login_operation_id,
        ])
        summary = {
            "validation_mode": "test_account_materialization",
            "signup_operation_id": signup_operation_id,
            "login_operation_id": login_operation_id,
            "token_operation_id": token_operation_id,
            "auth_flow_detected": True,
            "signup_candidate_count": len(signup_candidates),
            "login_candidate_count": len(login_candidates),
            "token_response_candidate_count": len(token_candidates),
            "reason_codes": ["auth_flow_signal_present"],
            "audit_flags": [],
        }

        if self._existing_test_account_materialization_observation(campaign.campaign_id):
            return [
                self._candidate(
                    kind=PlannerCandidateKind.test_account_materializer,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=21.0,
                    reason="Existing test_account_materialization_result already created two auth profiles.",
                    dedup_key=dedup_key,
                    summary={**summary, "reason_codes": ["existing_test_account_materialization_result"]},
                )
            ]
        if self._existing_test_account_materializer_run(campaign.campaign_id, dedup_key):
            return [
                self._candidate(
                    kind=PlannerCandidateKind.test_account_materializer,
                    status=PlannerCandidateStatus.skipped_existing,
                    priority=21.0,
                    reason="Existing active/finished test_account_materializer ToolRun found.",
                    dedup_key=dedup_key,
                    summary={**summary, "reason_codes": ["existing_test_account_materializer_run"]},
                )
            ]
        if not signup_operation_id or not login_operation_id:
            missing_inputs: list[str] = []
            if not signup_operation_id:
                missing_inputs.append("signup_operation_id_missing")
            if not login_operation_id:
                missing_inputs.append("login_operation_id_missing")
            return [
                self._candidate(
                    kind=PlannerCandidateKind.test_account_materializer,
                    status=PlannerCandidateStatus.blocked,
                    priority=21.0,
                    reason="Auth flow was detected but signup/login operation pair is incomplete.",
                    missing_inputs=missing_inputs,
                    dedup_key=dedup_key,
                    summary={**summary, "reason_codes": missing_inputs},
                )
            ]

        suffix = hashlib.sha256(dedup_key.encode()).hexdigest()[:8]
        command = WorkerCommand(
            campaign_id=campaign.campaign_id,
            task_id=f"task_test_account_materializer_{suffix}",
            worker_class="auth_context",
            strategy="materialize_test_accounts",
            tool_name="test_account_materializer",
            operation_id=signup_operation_id,
            inputs={
                "target_url": campaign.target_url,
                "signup_operation_id": signup_operation_id,
                "login_operation_id": login_operation_id,
                "validation_mode": "test_account_materialization",
                "max_accounts": 2,
                "max_response_bytes": 262144,
            },
            budget=CommandBudget(max_requests=6, timeout_sec=15),
            success_criteria=["test_account_materialization_result_recorded"],
        )
        return [
            self._validated_candidate(
                kind=PlannerCandidateKind.test_account_materializer,
                priority=21.0,
                reason="Detected signup/login auth flow supports bounded owner/attacker test account materialization.",
                dedup_key=dedup_key,
                command=command,
                summary=summary,
            )
        ]

    @staticmethod
    def _existing_auth_flow_detection_observation(campaign_id: str) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            otype = PlannerService._raw_observation_type(raw)
            if otype != "auth_flow_signal":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("source") or "").strip() != "auth_flow_detector":
                continue
            mode = str(det.get("validation_mode") or "").strip()
            if mode != "auth_flow_detection":
                continue
            return True
        return False

    @staticmethod
    def _latest_auth_flow_signal_details(campaign_id: str) -> dict[str, Any] | None:
        for raw in reversed(memory_store.list_observations_by_campaign(campaign_id)):
            otype = PlannerService._raw_observation_type(raw)
            if otype != "auth_flow_signal":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("source") or "").strip() != "auth_flow_detector":
                continue
            if str(det.get("validation_mode") or "").strip() != "auth_flow_detection":
                continue
            return det
        return None

    @staticmethod
    def _existing_test_account_materialization_observation(campaign_id: str) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            otype = PlannerService._raw_observation_type(raw)
            if otype != "test_account_materialization_result":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("source") or "").strip() != "test_account_materializer":
                continue
            try:
                if int(det.get("auth_profiles_created_count") or 0) >= 2:
                    return True
            except Exception:
                pass
        return False

    @staticmethod
    def _latest_test_account_materialization_details(campaign_id: str) -> dict[str, Any] | None:
        for raw in reversed(memory_store.list_observations_by_campaign(campaign_id)):
            if PlannerService._raw_observation_type(raw) != "test_account_materialization_result":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("source") or "").strip() != "test_account_materializer":
                continue
            status = str(det.get("test_account_materialization_status") or "").strip().lower()
            created_count = 0
            try:
                created_count = int(det.get("auth_profiles_created_count") or 0)
            except Exception:
                created_count = 0
            if status == "materialized" or created_count >= 2:
                return det
        return None

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    @staticmethod
    def _existing_resource_instance_inventory_for_source(
        campaign_id: str,
        source_observation_id: str,
    ) -> bool:
        source_id = str(source_observation_id or "").strip()
        if not source_id:
            return False
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "resource_instance_inventory":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("source") or "").strip() != "resource_instance_extractor":
                continue
            if str(det.get("source_observation_id") or "").strip() == source_id:
                return True
        return False

    @staticmethod
    def _existing_resource_instance_extractor_run(campaign_id: str, dedup_key: str) -> bool:
        for raw in memory_store.list_commands_by_campaign(campaign_id):
            if str(raw.get("tool_name") or "").strip() != "resource_instance_extractor":
                continue
            inputs = raw.get("inputs") if isinstance(raw.get("inputs"), dict) else {}
            source_observation_id = str(inputs.get("source_observation_id") or "").strip()
            op_id = str(raw.get("operation_id") or inputs.get("source_operation_id") or "").strip()
            auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
            candidate_key = "|".join([
                campaign_id,
                "resource_instance_extractor",
                source_observation_id or op_id or str(inputs.get("source_path") or "").strip(),
                str(inputs.get("validation_mode") or "resource_instance_extraction").strip() or "resource_instance_extraction",
            ])
            if candidate_key != dedup_key:
                continue
            cmd_id = str(raw.get("command_id") or "").strip()
            for run in memory_store.list_tool_runs_by_campaign(campaign_id):
                if str(run.get("command_id") or "").strip() != cmd_id:
                    continue
                if str(run.get("status") or "").strip() in {"accepted", "queued", "running", "finished"}:
                    return True
        return False

    @staticmethod
    def _existing_resource_seed_result(campaign_id: str) -> str | None:
        """Return last terminal seed_status if a diagnostic seed attempt already ran."""
        terminal = {"seeded", "no_seedable_operation", "creation_non_2xx", "no_object_id_found", "blocked"}
        for raw in reversed(memory_store.list_observations_by_campaign(campaign_id)):
            if PlannerService._raw_observation_type(raw) != "resource_seed_result":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("validation_mode") or "").strip() != "resource_seed":
                continue
            status = str(det.get("seed_status") or "").strip()
            if status in terminal:
                return status
        return None

    @staticmethod
    def _existing_resource_seed_worker_run(campaign_id: str, dedup_key: str) -> bool:
        for raw in memory_store.list_commands_by_campaign(campaign_id):
            if str(raw.get("tool_name") or "").strip() != "resource_seed_worker":
                continue
            inputs = raw.get("inputs") if isinstance(raw.get("inputs"), dict) else {}
            owner_auth_profile_id = str(inputs.get("owner_auth_profile_id") or "").strip()
            candidate_key = "|".join([
                campaign_id,
                "resource_seed_worker",
                str(inputs.get("validation_mode") or "resource_seed").strip() or "resource_seed",
                owner_auth_profile_id,
            ])
            if candidate_key != dedup_key:
                continue
            cmd_id = str(raw.get("command_id") or "").strip()
            for run in memory_store.list_tool_runs_by_campaign(campaign_id):
                if str(run.get("command_id") or "").strip() != cmd_id:
                    continue
                if str(run.get("status") or "").strip() in {"accepted", "queued", "running", "finished"}:
                    return True
        return False

    @staticmethod
    def _existing_bola_object_pair_inventory(campaign_id: str) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "bola_object_pair_inventory":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if str(det.get("validation_mode") or "").strip() == "bola_object_pair_building":
                return True
        return False

    @staticmethod
    def _data_exposure_dedup_key(
        *,
        campaign_id: str,
        operation_id: str,
        path_template: str,
        validation_mode: str,
        auth_mode: str,
        auth_profile_id: str,
    ) -> str:
        return "|".join([
            campaign_id,
            "data_exposure_validator",
            str(operation_id or "").strip(),
            normalize_api_path(path_template),
            validation_mode or "response_field_inventory_check",
            auth_mode or "unauthenticated",
            auth_profile_id or "",
        ])

    @staticmethod
    def _join_target_path(campaign: Campaign, path: str) -> str:
        return urljoin(str(campaign.target_url or "").rstrip("/") + "/", str(path or "").lstrip("/"))

    @staticmethod
    def _data_exposure_observation_from_validator(details: dict[str, Any], otype: str) -> bool:
        if str(details.get("tool_name") or "").strip() == "data_exposure_validator":
            return True
        if otype == "data_exposure_probe_result" and str(details.get("source") or "").strip() == "data_exposure_validator":
            return True
        return False

    @staticmethod
    def _find_prior_data_exposure_execution(
        campaign_id: str,
        operation_id: str,
        path_template: str,
        auth_mode: str = "unauthenticated",
        auth_profile_id: str = "",
    ) -> dict[str, Any] | None:
        """Match prior response_field_inventory, data_exposure_signal, or data_exposure_probe_result.

        Primary: same validation_mode, GET, normalized path, and operation_id (when both sides have it).
        Fallback: path + method + validation_mode when observation has no operation_id in details/top-level.
        """
        mode_expected = "response_field_inventory_check"
        path_c = normalize_api_path(path_template)
        cand_op = str(operation_id or "").strip()

        def _append_reason_codes(out: dict[str, Any], det: dict[str, Any]) -> None:
            rc = det.get("reason_codes")
            if isinstance(rc, list):
                out["prior_reason_codes"] = list(rc)
            elif rc is not None:
                out["prior_reason_codes"] = rc

        for raw in reversed(memory_store.list_observations_by_campaign(campaign_id)):
            otype = PlannerService._raw_observation_type(raw)
            if otype not in {"response_field_inventory", "data_exposure_signal", "data_exposure_probe_result"}:
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            if not PlannerService._data_exposure_observation_from_validator(det, otype):
                continue
            mode = str(det.get("validation_mode") or mode_expected).strip() or mode_expected
            if mode != mode_expected:
                continue
            obs_auth_mode = str(det.get("auth_mode") or "unauthenticated").strip() or "unauthenticated"
            if obs_auth_mode != auth_mode:
                continue
            obs_auth_profile_id = str(det.get("auth_profile_id") or "").strip()
            if auth_mode == "authenticated" and obs_auth_profile_id != auth_profile_id:
                continue
            meth = str(det.get("method") or "GET").strip().upper() or "GET"
            if meth != "GET":
                continue
            path_obs = normalize_api_path(str(det.get("path") or ""))
            if path_obs != path_c:
                continue
            obs_op = str(det.get("operation_id") or raw.get("operation_id") or "").strip()
            if cand_op:
                if obs_op:
                    if obs_op != cand_op:
                        continue
            else:
                if obs_op:
                    continue

            out: dict[str, Any] = {
                "observation_type": otype,
                "reason_code": "existing_data_exposure_probe"
                if otype == "data_exposure_probe_result"
                else "existing_inventory_or_signal",
            }
            if otype == "data_exposure_probe_result":
                out["prior_result"] = det.get("result")
                sc = det.get("status_code")
                if sc is not None and str(sc).strip() != "":
                    try:
                        out["prior_status_code"] = int(sc)
                    except Exception:
                        out["prior_status_code"] = sc
                _append_reason_codes(out, det)
            out["auth_mode"] = obs_auth_mode
            out["auth_profile_id"] = obs_auth_profile_id
            return out
        return None

    @staticmethod
    def _existing_data_exposure_validator_run(campaign_id: str, requested_dedup_key: str) -> bool:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "data_exposure_validator":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return True
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            op = str(inputs.get("operation_id") or "").strip()
            path = normalize_api_path(str(inputs.get("path_template") or ""))
            mode = str(inputs.get("validation_mode") or "").strip()
            auth_mode = str(inputs.get("auth_mode") or "unauthenticated").strip() or "unauthenticated"
            auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
            key = PlannerService._data_exposure_dedup_key(
                campaign_id=campaign_id,
                operation_id=op,
                path_template=path,
                validation_mode=mode or "response_field_inventory_check",
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
            )
            if key == requested_dedup_key:
                return True
        return False

    @staticmethod
    def _existing_ssrf_candidate_signal(
        campaign_id: str,
        operation_id: str,
        validation_mode: str,
    ) -> bool:
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            if PlannerService._raw_observation_type(raw) != "ssrf_candidate_signal":
                continue
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            existing_op = str(det.get("operation_id") or raw.get("operation_id") or "").strip()
            existing_mode = str(det.get("validation_mode") or "ssrf_candidate_detection").strip()
            if existing_op == operation_id and existing_mode == validation_mode:
                return True
        return False

    @staticmethod
    def _existing_ssrf_candidate_detector_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> bool:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "ssrf_candidate_detector":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return True
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            op = str(command.get("operation_id") or inputs.get("operation_id") or "").strip()
            mode = str(inputs.get("validation_mode") or "ssrf_candidate_detection").strip()
            key = "|".join([
                campaign_id,
                "ssrf_candidate_detector",
                op,
                mode or "ssrf_candidate_detection",
            ])
            if key == requested_dedup_key:
                return True
        return False

    @staticmethod
    def _existing_test_account_materializer_run(
        campaign_id: str,
        requested_dedup_key: str,
    ) -> bool:
        active_or_done = {"accepted", "queued", "running", "finished", "partial"}
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "test_account_materializer":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            if str(run.get("dedup_key") or "").strip() == requested_dedup_key:
                return True
            command_id = str(run.get("command_id") or "").strip()
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            inputs = command.get("inputs") if isinstance(command, dict) else None
            if not isinstance(inputs, dict):
                continue
            signup_op = str(inputs.get("signup_operation_id") or "").strip()
            login_op = str(inputs.get("login_operation_id") or "").strip()
            key = "|".join([
                campaign_id,
                "test_account_materializer",
                signup_op,
                login_op,
            ])
            if key == requested_dedup_key:
                return True
        return False

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
            PlannerCandidateKind.data_exposure_validator: 6,
            PlannerCandidateKind.resource_instance_extractor: 7,
            PlannerCandidateKind.resource_seed_worker: 7.5,
            PlannerCandidateKind.bola_object_pair_builder: 7.7,
            PlannerCandidateKind.auth_flow_detector: 8,
            PlannerCandidateKind.test_account_materializer: 9,
            PlannerCandidateKind.ssrf_candidate_detector: 10,
            PlannerCandidateKind.ssrf_probe: 10.5,
            PlannerCandidateKind.property_mutation_test: 11,
            PlannerCandidateKind.zap_discovery_passive: 12,
            PlannerCandidateKind.js_endpoint_extractor: 13,
            PlannerCandidateKind.undocumented_endpoint_validator: 14,
            PlannerCandidateKind.scenario_plan_blocked: 15,
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
    def _existing_bola_replay_result(campaign_id: str, object_pair_id: str) -> bool:
        target = str(object_pair_id or "").strip()
        if not target:
            return False
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            try:
                obs = Observation.model_validate(raw)
            except Exception:
                continue
            if obs.type != ObservationType.bola_replay_result:
                continue
            details = obs.details or {}
            if (
                str(details.get("validation_mode") or "").strip() == "bola_replay"
                and str(details.get("object_pair_id") or "").strip() == target
            ):
                return True
        return False

    @staticmethod
    def _bola_replay_results_by_pair(campaign_id: str) -> dict[str, dict[str, Any]]:
        out: dict[str, dict[str, Any]] = {}
        for raw in memory_store.list_observations_by_campaign(campaign_id):
            try:
                obs = Observation.model_validate(raw)
            except Exception:
                continue
            if obs.type != ObservationType.bola_replay_result:
                continue
            details = obs.details or {}
            if str(details.get("validation_mode") or "").strip() != "bola_replay":
                continue
            object_pair_id = str(details.get("object_pair_id") or "").strip()
            if not object_pair_id:
                continue
            out[object_pair_id] = {
                "result": str(details.get("result") or "").strip(),
                "access_granted": bool(details.get("access_granted") is True),
            }
        return out

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


_SSRF_EXACT_FIELD_NAMES = frozenset({
    "url",
    "uri",
    "link",
    "callback",
    "callback_url",
    "webhook",
    "webhook_url",
    "image_url",
    "avatar_url",
    "file_url",
    "report_url",
    "redirect_url",
    "target_url",
    "endpoint",
    "host",
    "hostname",
    "domain",
    "mechanic_api",
})


def _snake_case_name(value: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text)
    return text.strip("_").lower()


def _field_path_for_source(field_name: str, source: str) -> str:
    clean = str(field_name or "").strip()
    if source == "query":
        return f"$.query.{clean}"
    return f"$.{clean}"


def _detect_ssrf_candidate_fields(
    *,
    body_fields: list[str],
    body_field_summaries: list[dict[str, Any]] | None,
    body_required_fields: list[str] | None,
    operation_tags: list[str] | None,
    query_params: list[str],
    operation_id: str,
    path_template: str,
    method: str,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    path_lower = str(path_template or "").lower()
    path_hints = [
        hint for hint in ("report", "mechanic", "image", "webhook", "callback", "import", "fetch", "contact", "connect", "integration", "notify", "request")
        if f"/{hint}" in path_lower or hint in path_lower
    ]
    op_ctx = " ".join([
        str(operation_id or "").lower(),
        path_lower,
        " ".join(str(x or "").lower() for x in (operation_tags or [])),
    ])
    body_summary_by_name: dict[str, dict[str, Any]] = {}
    for row in body_field_summaries or []:
        if not isinstance(row, dict):
            continue
        nm = str(row.get("name") or "").strip()
        if nm and nm not in body_summary_by_name:
            body_summary_by_name[nm] = row
    for source_name, fields in (("body", body_fields), ("query", query_params)):
        for raw_name in fields:
            field_name = str(raw_name or "").strip()
            if not field_name:
                continue
            normalized = _snake_case_name(field_name)
            reason_codes: list[str] = []
            schema_format = ""
            confidence = "medium"
            if normalized in _SSRF_EXACT_FIELD_NAMES:
                reason_codes.append("url_like_field_name")
                if normalized in {"host", "hostname", "domain"}:
                    schema_format = "hostname"
                else:
                    schema_format = "uri"
            elif normalized.endswith(("_url", "_uri", "_link", "_callback", "_callback_url", "_webhook", "_webhook_url", "_redirect_url", "_endpoint")):
                reason_codes.append("url_like_field_name")
                schema_format = "uri"
            elif normalized.endswith(("_host", "_hostname", "_domain")):
                reason_codes.append("url_like_field_name")
                schema_format = "hostname"
            if not reason_codes:
                continue
            if source_name == "body" and "request_body_ref_resolved" not in reason_codes and body_summary_by_name.get(field_name):
                reason_codes.append("request_body_ref_resolved")
            if any(tok in op_ctx for tok in ("contact", "callback", "webhook", "notify", "integration", "connect", "report", "request", "mechanic")):
                reason_codes.append("operation_context_url_sink")
            if schema_format == "uri":
                reason_codes.append("schema_format_uri")
                confidence = "high"
            elif schema_format == "url":
                reason_codes.append("schema_format_url")
                confidence = "high"
            elif schema_format == "hostname":
                reason_codes.append("schema_format_hostname")
            if method in {"POST", "PUT", "PATCH"}:
                reason_codes.append("mutation_method")
            for hint in path_hints[:2]:
                reason_codes.append(f"path_hint_{hint}")
            field_path = _field_path_for_source(field_name, source_name)
            key = (field_name, field_path)
            if key in seen:
                continue
            seen.add(key)
            summary_row = body_summary_by_name.get(field_name) if source_name == "body" else {}
            if not isinstance(summary_row, dict):
                summary_row = {}
            required_fields = [str(x) for x in (body_required_fields or []) if str(x).strip()]
            field_summaries = [
                dict(item)
                for item in (body_field_summaries or [])
                if isinstance(item, dict)
            ]
            out.append({
                "field_name": field_name,
                "field_path": field_path,
                "schema_type": str(summary_row.get("schema_type") or "string"),
                "schema_format": str(summary_row.get("schema_format") or schema_format),
                "confidence": confidence,
                "reason_codes": reason_codes[:6],
                "required_body_fields": required_fields[:25],
                "allowed_body_fields": sorted(list(body_summary_by_name.keys()))[:60],
                "body_field_summaries": field_summaries[:80],
                "schema_summary_source": "api_graph" if field_summaries else "none",
                "ssrf_target_field": {
                    "field_name": field_name,
                    "field_path": field_path,
                },
            })
    # Include nested request-body fields discovered via resolved schema summaries.
    for row in (body_field_summaries or []):
        if not isinstance(row, dict):
            continue
        source_name = "body"
        field_name = str(row.get("name") or "").strip()
        field_path = str(row.get("field_path") or "").strip()
        if not field_name or not field_path:
            continue
        normalized = _snake_case_name(field_name)
        reason_codes: list[str] = []
        if normalized in _SSRF_EXACT_FIELD_NAMES or normalized.endswith(("_url", "_uri", "_endpoint", "_callback", "_webhook")):
            reason_codes.append("url_like_field_name")
        if "api" in normalized and "url_like_field_name" not in reason_codes:
            reason_codes.append("url_like_field_name")
        if not reason_codes:
            continue
        if any(tok in op_ctx for tok in ("contact", "callback", "webhook", "notify", "integration", "connect", "report", "request", "mechanic")):
            reason_codes.append("operation_context_url_sink")
        reason_codes.append("nested_body_field_detected")
        reason_codes.append("request_body_ref_resolved")
        schema_format = str(row.get("schema_format") or "").strip().lower()
        confidence = "high" if schema_format in {"uri", "url"} else "medium"
        if schema_format == "uri":
            reason_codes.append("schema_format_uri")
        elif schema_format == "url":
            reason_codes.append("schema_format_url")
        key = (field_name, field_path)
        if key in seen:
            continue
        seen.add(key)
        required_fields = [str(x) for x in (body_required_fields or []) if str(x).strip()]
        out.append({
            "field_name": field_name,
            "field_path": field_path,
            "schema_type": str(row.get("schema_type") or "string"),
            "schema_format": schema_format,
            "confidence": confidence,
            "reason_codes": reason_codes[:6],
            "required_body_fields": required_fields[:25],
            "allowed_body_fields": sorted(list(body_summary_by_name.keys()))[:60],
            "body_field_summaries": [dict(item) for item in (body_field_summaries or []) if isinstance(item, dict)][:80],
            "schema_summary_source": "api_graph",
            "ssrf_target_field": {"field_name": field_name, "field_path": field_path},
        })
    scored: list[tuple[float, dict[str, Any]]] = []
    for row in out:
        score = _ssrf_detector_field_score(
            method=method,
            path_template=path_template,
            field_name=str(row.get("field_name") or ""),
            field_path=str(row.get("field_path") or ""),
            schema_format=str(row.get("schema_format") or ""),
            confidence=str(row.get("confidence") or ""),
        )
        scored.append((score, row))
    scored.sort(
        key=lambda item: (
            item[0],
            str(item[1].get("field_name") or ""),
            str(item[1].get("field_path") or ""),
        ),
        reverse=True,
    )
    # Keep a richer deterministic pool for downstream planner/probe selection.
    return [row for _score, row in scored[:10]]


def _ssrf_detector_field_score(
    *,
    method: str,
    path_template: str,
    field_name: str,
    field_path: str,
    schema_format: str,
    confidence: str,
) -> float:
    score = 0.0
    m = str(method or "").strip().upper()
    p = str(path_template or "").strip().lower()
    fn = str(field_name or "").strip().lower()
    fp = str(field_path or "").strip().lower()
    sf = str(schema_format or "").strip().lower()
    conf = str(confidence or "").strip().lower()
    if conf == "high":
        score += 4.0
    elif conf == "medium":
        score += 2.0
    if sf in {"uri", "url"}:
        score += 3.0
    if m in {"POST", "PUT", "PATCH"}:
        score += 2.0
    if "{" not in p and "}" not in p:
        score += 2.0
    positive_hints = (
        "api", "endpoint", "callback", "webhook", "url", "uri", "contact", "notify",
        "target", "destination", "service", "request", "report", "mechanic", "integration", "connect",
    )
    if any(h in fn for h in positive_hints) or any(h in fp for h in positive_hints):
        score += 2.5
    if any(h in p for h in positive_hints):
        score += 2.0
    negative_hints = ("product", "image", "video", "file", "upload", "media", "avatar", "logo", "picture")
    if any(h in fn for h in negative_hints) or any(h in fp for h in negative_hints) or any(h in p for h in negative_hints):
        score -= 3.0
    return score


def _aggregate_ssrf_reason_codes(fields: list[dict[str, Any]]) -> list[str]:
    out: list[str] = []
    for item in fields:
        rc = item.get("reason_codes")
        if not isinstance(rc, list):
            continue
        for code in rc:
            text = str(code).strip()
            if text and text not in out:
                out.append(text)
    return out[:10]
