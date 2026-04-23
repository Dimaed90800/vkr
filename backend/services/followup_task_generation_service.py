from __future__ import annotations

import re
from typing import Any

try:
    from backend.models.scheduling import SchedulerState
    from backend.models.testing import TaskModel
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
    from backend.services.task_fingerprint import TaskFingerprintService
    from backend.services.task_tooling_service import DEFAULT_TASK_TOOLING
except ModuleNotFoundError:  # pragma: no cover
    from models.scheduling import SchedulerState
    from models.testing import TaskModel
    from services.diagnostic_logging_service import DiagnosticLoggingService
    from services.task_fingerprint import TaskFingerprintService
    from services.task_tooling_service import DEFAULT_TASK_TOOLING


class FollowupTaskGenerationService:
    MAX_FOLLOWUPS_PER_ROOT = 3
    MAX_ATTEMPTS_PER_ENDPOINT_FAMILY = 4
    MAX_RETRIES_PER_STRATEGY = 2

    HIGH_VALUE_FAMILIES = {
        "privileged_function_access",
        "object_authorization",
        "collection_access_control",
        "invalid_transition",
        "excessive_data_exposure",
        "property_level_authorization",
        "mass_assignment",
    }
    PREPARATION_STRATEGIES = {
        "create_object_then_replay",
        "list_then_select_object_then_replay",
        "prepare_workflow_state_then_retry",
        "baseline_refinement",
        "success_path_exposure_probe",
    }

    def __init__(self) -> None:
        self.fingerprints = TaskFingerprintService()
        self.diagnostics = DiagnosticLoggingService()

    def generate_followups(
        self,
        *,
        active_task: TaskModel,
        verdict: str,
        rework_hint: str | None,
        evidence: dict[str, Any] | None,
        pending_tasks: list[TaskModel],
        state: SchedulerState,
        max_retries: int,
    ) -> list[TaskModel]:
        normalized_verdict = str(verdict or "rejected").lower()
        if active_task.id == "__no_task__":
            self._emit_followup_decision(
                active_task=active_task,
                state=state,
                status="skipped",
                summary="Follow-up generation skipped for noop task.",
                reason={"skip_reason": "noop_task", "source_verdict": normalized_verdict},
            )
            return []

        root_task_id = str(active_task.parent_task_id or active_task.id or "")
        resource_family = self._resource_family(active_task)
        endpoint_family_key = f"{active_task.class_name}:{resource_family}:{self._normalized_endpoint(active_task.endpoint)}"
        if int(state.root_followup_counts.get(root_task_id, 0) or 0) >= self.MAX_FOLLOWUPS_PER_ROOT:
            self._emit_followup_decision(
                active_task=active_task,
                state=state,
                status="skipped",
                summary="Follow-up generation blocked by root task follow-up cap.",
                reason={"skip_reason": "max_followups_per_root_exceeded", "source_verdict": normalized_verdict},
            )
            return []
        if int(state.endpoint_family_attempts.get(endpoint_family_key, 0) or 0) >= self.MAX_ATTEMPTS_PER_ENDPOINT_FAMILY:
            self._emit_followup_decision(
                active_task=active_task,
                state=state,
                status="skipped",
                summary="Follow-up generation blocked by endpoint family attempt cap.",
                reason={"skip_reason": "endpoint_family_attempts_exhausted", "source_verdict": normalized_verdict},
            )
            return []

        evidence = evidence or {}
        response_summary = evidence.get("response_summary") or {}
        indicators = {str(item or "").strip() for item in (evidence.get("indicators") or []) if str(item or "").strip()}
        failure_reason = str(response_summary.get("failure_reason") or "") or self._artifact_failure_reason(evidence)
        suppress_direct_replay = (
            normalized_verdict == "rework"
            and str(active_task.class_name or "").lower() == "authorization"
            and str(active_task.hypothesis_family or "").lower() == "privileged_function_access"
            and self._requires_object_materialization(active_task, evidence=evidence)
        )

        candidates: list[TaskModel] = []
        if normalized_verdict == "rework":
            candidates.extend(self._rework_followups(active_task, response_summary, indicators, rework_hint, max_retries, evidence))
        elif failure_reason in {
            "baseline_invalid_from_spec",
            "semantic_constraints_not_derivable",
            "object_creation_failed",
            "object_harvest_failed",
            "object_id_missing",
            "creator_not_available",
            "list_not_available",
            "materialization_failed",
            "success_path_not_reachable",
            "success_path_not_reached",
            "missing_auth_context",
            "placeholder_object_id",
            "unauthenticated_request_to_auth_required_endpoint",
        } or {
            "preparation_failed",
            "baseline_invalid",
            "invalid_object_id",
            "placeholder_object_id",
            "missing_auth_context",
        }.intersection(indicators):
            candidates.extend(self._preparation_followups(active_task, response_summary, indicators))

        unique: list[TaskModel] = []
        existing_fingerprints = {self.fingerprints.task_fingerprint(task) for task in pending_tasks}
        if suppress_direct_replay:
            self._emit_followup_candidate(
                active_task=active_task,
                state=state,
                candidate=self._clone_task(active_task, "privileged_function_replay", allowed_tools=["auth_test_access"], priority_boost=6),
                status="suppressed",
                reason={"skip_reason": "missing_object_context_for_direct_replay"},
            )
        for candidate in candidates:
            if candidate.retry_count > int(max_retries or 0):
                self._emit_followup_candidate(
                    active_task=active_task,
                    state=state,
                    candidate=candidate,
                    status="suppressed",
                    reason={"skip_reason": "retry_limit_exceeded", "max_retries": max_retries},
                )
                continue
            strategy_key = self._strategy_key(candidate)
            if int(state.strategy_retry_counts.get(strategy_key, 0) or 0) >= self.MAX_RETRIES_PER_STRATEGY:
                self._emit_strategy_budget(active_task=active_task, state=state, candidate=candidate, strategy_key=strategy_key)
                self._emit_followup_candidate(
                    active_task=active_task,
                    state=state,
                    candidate=candidate,
                    status="suppressed",
                    reason={"skip_reason": "strategy_retries_exhausted", "strategy_key": strategy_key},
                )
                continue
            fingerprint = self.fingerprints.task_fingerprint(candidate)
            if fingerprint in existing_fingerprints:
                self._emit_followup_candidate(
                    active_task=active_task,
                    state=state,
                    candidate=candidate,
                    status="suppressed",
                    reason={"skip_reason": "equivalent_followup_already_exists", "task_fingerprint": fingerprint},
                )
                continue
            existing_fingerprints.add(fingerprint)
            self._hydrate_candidate_from_evidence(candidate, evidence)
            unique.append(candidate)
        final_candidates = unique[:2]
        if final_candidates:
            for candidate in final_candidates:
                self._emit_followup_candidate(
                    active_task=active_task,
                    state=state,
                    candidate=candidate,
                    status="generated",
                    reason={"source_verdict": normalized_verdict},
                )
        elif candidates:
            self._emit_followup_decision(
                active_task=active_task,
                state=state,
                status="suppressed",
                summary="Follow-up generation produced only suppressed candidates.",
                reason={"skip_reason": "all_followups_suppressed", "source_verdict": normalized_verdict},
            )
        else:
            self._emit_followup_decision(
                active_task=active_task,
                state=state,
                status="skipped",
                summary="No deterministic follow-up template matched this outcome.",
                reason={"skip_reason": "no_structured_signal", "source_verdict": normalized_verdict},
            )
        return final_candidates

    def record_task_outcome(self, state: SchedulerState, task: TaskModel, *, followup_count: int = 0) -> SchedulerState:
        root_task_id = str(task.parent_task_id or task.id or "")
        resource_family = self._resource_family(task)
        endpoint_family_key = f"{task.class_name}:{resource_family}:{self._normalized_endpoint(task.endpoint)}"
        strategy_key = self._strategy_key(task)
        exploration = int(state.exploration_budget_used or 0)
        deepening = int(state.deepening_budget_used or 0)
        preparation = int(state.preparation_budget_used or 0)
        if self._is_preparation_task(task):
            preparation += 1
        elif int(task.followup_generation or 0) > 0 or str(task.hypothesis_family or "") in self.HIGH_VALUE_FAMILIES:
            deepening += 1
        else:
            exploration += 1

        root_followup_counts = dict(state.root_followup_counts or {})
        if followup_count:
            root_followup_counts[root_task_id] = int(root_followup_counts.get(root_task_id, 0) or 0) + int(followup_count or 0)

        endpoint_family_attempts = dict(state.endpoint_family_attempts or {})
        endpoint_family_attempts[endpoint_family_key] = int(endpoint_family_attempts.get(endpoint_family_key, 0) or 0) + 1

        strategy_retry_counts = dict(state.strategy_retry_counts or {})
        strategy_retry_counts[strategy_key] = int(strategy_retry_counts.get(strategy_key, 0) or 0) + 1

        return state.model_copy(
            update={
                "exploration_budget_used": exploration,
                "deepening_budget_used": deepening,
                "preparation_budget_used": preparation,
                "root_followup_counts": root_followup_counts,
                "endpoint_family_attempts": endpoint_family_attempts,
                "strategy_retry_counts": strategy_retry_counts,
            }
        )

    def _rework_followups(
        self,
        active_task: TaskModel,
        response_summary: dict[str, Any],
        indicators: set[str],
        rework_hint: str | None,
        max_retries: int,
        evidence: dict[str, Any] | None = None,
    ) -> list[TaskModel]:
        class_name = str(active_task.class_name or "").lower()
        if class_name == "injection":
            return self._injection_followups(active_task, response_summary, indicators, rework_hint)
        if class_name == "authorization":
            return self._authorization_followups(active_task, response_summary, indicators, rework_hint, evidence=evidence)
        if class_name == "business_logic":
            return self._business_logic_followups(active_task, response_summary, indicators, rework_hint)
        return []

    def _preparation_followups(
        self,
        active_task: TaskModel,
        response_summary: dict[str, Any],
        indicators: set[str],
    ) -> list[TaskModel]:
        class_name = str(active_task.class_name or "").lower()
        if class_name == "authorization" and (
            self._requires_object_materialization(active_task)
            or {"invalid_object_id", "placeholder_object_id"}.intersection(indicators)
            or str(response_summary.get("failure_reason") or "") in {"placeholder_object_id", "object_creation_failed", "object_harvest_failed", "object_id_missing", "creator_not_available", "list_not_available", "materialization_failed"}
        ):
            return self._object_materialization_followups(active_task)
        if class_name == "authorization" and str(active_task.subtype or "") == "auth_bootstrap":
            if str(response_summary.get("failure_reason") or "") == "missing_auth_context":
                return [self._clone_task(active_task, "reuse_existing_provisioned_roles", allowed_tools=["auth_test_access"], readiness="ready_to_test", priority_boost=9)]
            return [self._clone_task(active_task, "create_object_then_replay", allowed_tools=["create_test_object"], readiness="needs_preparation", priority_boost=12)]
        if class_name == "injection":
            return [self._clone_task(active_task, "baseline_refinement", allowed_tools=["input_shape_probe"], readiness="needs_preparation", priority_boost=8)]
        if class_name == "business_logic":
            if str(response_summary.get("failure_reason") or "") == "unauthenticated_request_to_auth_required_endpoint":
                return [self._clone_task(active_task, "authenticated_workflow_retry", allowed_tools=["logic_test"], readiness="ready_to_test", priority_boost=11)]
            return [self._clone_task(active_task, "prepare_workflow_state_then_retry", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=10)]
        return []

    def _injection_followups(
        self,
        active_task: TaskModel,
        response_summary: dict[str, Any],
        indicators: set[str],
        rework_hint: str | None,
    ) -> list[TaskModel]:
        followups: list[TaskModel] = []
        failed_strategy = str(active_task.test_strategy or active_task.failed_strategy or "")
        if "baseline_invalid" in indicators or str(response_summary.get("preparation_status") or "") == "baseline_invalid":
            followups.append(self._clone_task(active_task, "baseline_refinement", allowed_tools=["input_shape_probe"], readiness="needs_preparation", payload_family="schema_refinement", priority_boost=10))
            return followups
        if "reflection_detected" in indicators and "unescaped_reflection" not in indicators and "reflection_focus_probe" not in failed_strategy:
            followups.append(self._clone_task(active_task, "reflection_focus_probe", allowed_tools=["reflection_probe"], payload_family="reflection_marker", priority_boost=8))
        elif "alternate_payload_family" not in failed_strategy:
            payload_family = self._next_payload_family(active_task.payload_family)
            followups.append(self._clone_task(active_task, "alternate_payload_family", allowed_tools=["injection_test"], payload_family=payload_family, priority_boost=8))
        elif self._looks_path_like(active_task.endpoint) and "path_fuzz_probe" not in failed_strategy:
            followups.append(self._clone_task(active_task, "path_fuzz_probe", allowed_tools=["path_fuzz_probe"], payload_family="path_variant", priority_boost=6))
        return followups

    def _authorization_followups(
        self,
        active_task: TaskModel,
        response_summary: dict[str, Any],
        indicators: set[str],
        rework_hint: str | None,
        evidence: dict[str, Any] | None = None,
    ) -> list[TaskModel]:
        followups: list[TaskModel] = []
        if self._requires_object_materialization(active_task, evidence=evidence):
            followups.extend(self._object_materialization_followups(active_task))
            return followups
        if str(active_task.hypothesis_family or "") == "collection_access_control" and not active_task.params.selected_object_id and self._resource_family(active_task) != "generic_resource":
            candidate = self._clone_task(active_task, "object_specific_auth_probe", allowed_tools=["create_test_object"], readiness="needs_preparation", priority_boost=12)
            candidate.hypothesis_family = "object_authorization"
            candidate.subtype = "bola"
            candidate.params.requires_object_id_enrichment = True
            candidate.prerequisites.requires_object_id = True
            candidate.readiness = "needs_preparation"
            candidate.allowed_tools = ["create_test_object"]
            candidate.preparation_options = ["create_test_object"]
            candidate.preferred_tool = "create_test_object"
            candidate.strategy_family = "object_materialization"
            candidate.recommended_next_step = "create_test_object"
            if getattr(candidate, "tool_preference", None):
                candidate.tool_preference.preferred_tool = "create_test_object"
                candidate.tool_preference.fallback_tools = []
            candidate = DEFAULT_TASK_TOOLING.normalize_task(candidate, explicit_allowed_tools=["create_test_object"])
            candidate.allowed_tools = ["create_test_object"]
            candidate.preparation_options = ["create_test_object"]
            candidate.recommended_next_step = "create_test_object"
            followups.append(candidate)
        elif str(active_task.subtype or "") == "auth_bootstrap":
            followups.append(self._clone_task(active_task, "login_only_bootstrap_retry", allowed_tools=["auto_provision"], readiness="needs_preparation", priority_boost=8))
        elif str(active_task.hypothesis_family or "") == "privileged_function_access":
            followups.append(self._clone_task(active_task, "privileged_function_replay", allowed_tools=["auth_test_access"], priority_boost=6))
        elif str(active_task.hypothesis_family or "") == "property_level_authorization":
            followups.append(self._clone_task(active_task, "verify_persistence_after_mutation", allowed_tools=["property_mutation_test"], priority_boost=8))
        return followups

    def _requires_object_materialization(
        self,
        task: TaskModel,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        if str(task.class_name or "").lower() != "authorization":
            return False
        if not self._is_object_dependent_auth_task(task):
            return False
        return not self._has_usable_object_context(task, evidence=evidence)

    def _is_object_dependent_auth_task(self, task: TaskModel) -> bool:
        if bool(task.params.requires_object_id_enrichment):
            return True
        if str(task.hypothesis_family or "").lower() in {"object_authorization", "privileged_function_access"} and self._resource_family(task) != "generic_resource":
            return True
        endpoint = str(task.endpoint or "")
        return "{" in endpoint and "}" in endpoint

    def _has_usable_object_context(
        self,
        task: TaskModel,
        evidence: dict[str, Any] | None = None,
    ) -> bool:
        if self._real_object_id(task.params.selected_object_id):
            return True
        for item in task.params.object_id_candidates or []:
            if self._real_object_id(item):
                return True
        for item in self._harvested_ids_from_evidence(evidence or {}):
            if self._real_object_id(item):
                return True
        for artifact in (evidence or {}).get("artifacts") or []:
            if not isinstance(artifact, dict):
                continue
            if str(artifact.get("type") or "") not in {"prepared_object", "workflow_context"}:
                continue
            value = artifact.get("value") or {}
            if isinstance(value, dict) and self._real_object_id(value.get("object_id")):
                return True
        return False

    def _real_object_id(self, value: Any) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        if normalized.startswith("{") and normalized.endswith("}"):
            return None
        if normalized.lower() in {
            "id",
            "video_id",
            "order_id",
            "post_id",
            "postid",
            "vehicleid",
            "vehicle_id",
            "report_id",
            "user_id",
            "userid",
        }:
            return None
        return normalized

    def _object_materialization_followups(self, active_task: TaskModel) -> list[TaskModel]:
        return [
            self._materialization_followup(active_task, "create_object_then_replay", priority_boost=12),
            self._materialization_followup(active_task, "list_then_select_object_then_replay", priority_boost=10),
        ]

    def _materialization_followup(
        self,
        active_task: TaskModel,
        strategy: str,
        *,
        priority_boost: int,
    ) -> TaskModel:
        candidate = self._clone_task(
            active_task,
            strategy,
            allowed_tools=["create_test_object"],
            readiness="needs_preparation",
            priority_boost=priority_boost,
        )
        candidate.params.requires_object_id_enrichment = True
        candidate.prerequisites.requires_object_id = True
        candidate.readiness = "needs_preparation"
        candidate.allowed_tools = ["create_test_object"]
        candidate.preparation_options = ["create_test_object"]
        candidate.preferred_tool = "create_test_object"
        if getattr(candidate, "tool_preference", None):
            candidate.tool_preference.preferred_tool = "create_test_object"
            candidate.tool_preference.fallback_tools = []
        candidate.strategy_family = "object_materialization"
        candidate.recommended_next_step = "create_test_object"
        candidate = DEFAULT_TASK_TOOLING.normalize_task(candidate, explicit_allowed_tools=["create_test_object"])
        candidate.allowed_tools = ["create_test_object"]
        candidate.preparation_options = ["create_test_object"]
        candidate.recommended_next_step = "create_test_object"
        return candidate

    def _business_logic_followups(
        self,
        active_task: TaskModel,
        response_summary: dict[str, Any],
        indicators: set[str],
        rework_hint: str | None,
    ) -> list[TaskModel]:
        followups: list[TaskModel] = []
        if str(response_summary.get("preparation_status") or "") == "baseline_invalid":
            followups.append(self._clone_task(active_task, "prepare_workflow_state_then_retry", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=10))
            return followups
        if str(active_task.subtype or "") == "excessive_data_exposure":
            if str(response_summary.get("weak_signal_class") or "") in {"schema_disclosure", "verbose_validation_leak"} or str(response_summary.get("failure_reason") or "") in {"success_path_not_reached", "unauthenticated_request_to_auth_required_endpoint"}:
                followups.append(self._clone_task(active_task, "success_path_exposure_probe", allowed_tools=["data_exposure_test"], priority_boost=8))
        elif str(active_task.subtype or "") in {"property_level_authorization", "mass_assignment"}:
            followups.append(self._clone_task(active_task, "verify_persistence_after_mutation", allowed_tools=["property_mutation_test"], priority_boost=8))
        elif "invariant_violation" not in indicators and "workflow_state_bypass" not in indicators:
            if self._resource_family(active_task) == "order":
                if "return_order" in str(active_task.endpoint or "").lower():
                    followups.append(self._clone_task(active_task, "create_order_then_return_order", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=12))
                    followups.append(self._clone_task(active_task, "list_orders_then_pick_order_then_return_order", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=10))
                else:
                    followups.append(self._clone_task(active_task, "create_order_then_update_order", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=10))
            if not bool((response_summary.get("state_delta_summary") or {}).get("prepared_context")):
                followups.append(self._clone_task(active_task, "prepare_workflow_state_then_retry", allowed_tools=["workflow_probe"], readiness="needs_preparation", priority_boost=10))
            followups.append(self._clone_task(active_task, "cross_role_sequence_probe", allowed_tools=["logic_test"], priority_boost=8))
        return followups

    def _clone_task(
        self,
        task: TaskModel,
        strategy: str,
        *,
        allowed_tools: list[str],
        readiness: str | None = None,
        payload_family: str | None = None,
        priority_boost: int = 0,
    ) -> TaskModel:
        generation = int(task.followup_generation or 0) + 1
        suffix = re.sub(r"[^a-z0-9]+", "_", strategy.lower()).strip("_")[:32]
        new_id = f"{task.id}__{suffix}_{generation}"
        cloned = DEFAULT_TASK_TOOLING.mutable_task_copy(task)
        cloned.id = new_id
        cloned.parent_task_id = str(task.parent_task_id or task.id)
        cloned.origin_reason = "rework_followup"
        cloned.followup_generation = generation
        cloned.failed_strategy = str(task.test_strategy or task.failed_strategy or "")
        cloned.test_strategy = strategy
        cloned.strategy_family = self._strategy_family_for(strategy, cloned.payload_family)
        cloned.allowed_tools = list(allowed_tools)
        prep_tools = {"create_test_object", "workflow_probe", "input_shape_probe", "auto_provision", "auth_probe_entrypoints", "import_har_capture"}
        cloned.readiness = readiness or ("needs_preparation" if any(str(item or "").strip() in prep_tools for item in (allowed_tools or [])) else "ready_to_test")
        cloned.retry_count = int(task.retry_count or 0) + 1
        cloned = DEFAULT_TASK_TOOLING.normalize_task(cloned, explicit_allowed_tools=cloned.allowed_tools)
        if strategy in {"create_object_then_replay", "list_then_select_object_then_replay", "object_specific_auth_probe"}:
            cloned.params.requires_object_id_enrichment = True
            cloned.prerequisites.requires_object_id = True
            cloned.readiness = "needs_preparation"
        cloned.rework_hint = None
        cloned.priority = min(100, int(task.priority or 0) + priority_boost)
        cloned.payload_family = payload_family or task.payload_family
        cloned.resource_family = self._resource_family(task)
        cloned.context_source = cloned.context_source or "followup"
        return cloned

    def _resource_family(self, task: TaskModel) -> str:
        if str(task.resource_family or "").strip():
            return str(task.resource_family or "").strip().lower()
        hints = task.context_hints or {}
        if isinstance(hints, dict) and str(hints.get("resource_family") or "").strip():
            return str(hints.get("resource_family") or "").strip().lower()
        return "generic_resource"

    def _normalized_endpoint(self, endpoint: str) -> str:
        return self.fingerprints._normalize_endpoint(endpoint)

    def _strategy_key(self, task: TaskModel) -> str:
        return "|".join(
            [
                str(task.class_name or "").lower(),
                self._normalized_endpoint(task.endpoint),
                str(task.strategy_family or task.test_strategy or "").lower(),
                str(task.payload_family or "").lower(),
                str(task.auth_context.owner_role or "").lower(),
                str(task.auth_context.other_role or "").lower(),
                str(task.params.selected_object_id or "").lower(),
            ]
        )

    def _strategy_family_for(self, strategy: str | None, payload_family: str | None) -> str:
        normalized = str(strategy or "").strip().lower()
        if normalized in {"baseline_refinement", "shape_probe_then_test"}:
            return "baseline_refinement"
        if normalized in {"alternate_payload_family", "direct_input_probe"}:
            return f"payload_probe:{str(payload_family or '').strip().lower() or 'default'}"
        if normalized in {"reflection_focus_probe", "reflection_probe"}:
            return "reflection_probe"
        if normalized in {"path_fuzz_probe", "path_probe"}:
            return "path_probe"
        if normalized in {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "prepare_object_then_replay",
        }:
            return "object_materialization"
        if normalized in {
            "prepare_workflow_state_then_retry",
            "create_order_then_return_order",
            "create_order_then_update_order",
            "list_orders_then_pick_order_then_return_order",
            "authenticated_workflow_retry",
            "cross_role_sequence_probe",
        }:
            return "workflow_state"
        if normalized in {
            "login_only_bootstrap_retry",
            "register_then_login_retry",
            "reuse_existing_provisioned_roles",
            "use_existing_provisioned_identity",
            "discover_auth_bootstrap_then_provision",
        }:
            return "auth_bootstrap"
        return normalized or "generic_strategy"

    def _hydrate_candidate_from_evidence(self, candidate: TaskModel, evidence: dict[str, Any]) -> None:
        harvested_ids = self._harvested_ids_from_evidence(evidence)
        if not harvested_ids:
            return
        if candidate.params.selected_object_id in (None, ""):
            candidate.params.selected_object_id = harvested_ids[0]
        current = [str(item) for item in (candidate.params.object_id_candidates or []) if str(item or "").strip()]
        for item in harvested_ids:
            if item not in current:
                current.insert(0, item)
        candidate.params.object_id_candidates = current[:10]
        candidate.params.requires_object_id_enrichment = False
        if candidate.readiness == "needs_preparation" and candidate.test_strategy in {"create_object_then_replay", "list_then_select_object_then_replay"}:
            candidate.readiness = "ready_to_test"
            candidate.allowed_tools = ["auth_test_access"] if candidate.class_name == "authorization" else candidate.allowed_tools
            if candidate.class_name == "authorization":
                candidate.test_strategy = "object_specific_auth_probe"
                candidate.strategy_family = "object_materialization"

    def _harvested_ids_from_evidence(self, evidence: dict[str, Any]) -> list[str]:
        values: list[str] = []
        artifacts = evidence.get("artifacts") or []
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            artifact_type = str(item.get("type") or "")
            value = item.get("value")
            if artifact_type == "harvested_object_ids" and isinstance(value, list):
                for candidate in value:
                    normalized = str(candidate or "").strip()
                    if normalized and normalized not in values:
                        values.append(normalized)
            if artifact_type == "prepared_object" and isinstance(value, dict):
                normalized = str(value.get("object_id") or "").strip()
                if normalized and normalized not in values:
                    values.append(normalized)
            if artifact_type == "workflow_context" and isinstance(value, dict):
                normalized = str(value.get("object_id") or "").strip()
                if normalized and normalized not in values:
                    values.append(normalized)
        return values[:10]

    def _emit_strategy_budget(
        self,
        *,
        active_task: TaskModel,
        state: SchedulerState,
        candidate: TaskModel,
        strategy_key: str,
    ) -> None:
        self.diagnostics.emit(
            event_type="strategy_family_budget_applied",
            component="followup",
            status="suppressed",
            summary=f"Strategy family budget blocked follow-up {candidate.id}.",
            run_id=state.run_id,
            trace_context=self.diagnostics.trace_context(run_id=state.run_id, root_trace_id=state.root_trace_id, task=active_task),
            reason={"skip_reason": "strategy_retries_exhausted", "strategy_key": strategy_key},
            artifacts={"candidate_id": candidate.id, "strategy_family": candidate.strategy_family},
        )

    def _artifact_failure_reason(self, evidence: dict[str, Any]) -> str:
        artifacts = evidence.get("artifacts") or []
        for item in artifacts:
            if not isinstance(item, dict):
                continue
            if str(item.get("type") or "") != "creation_evidence":
                continue
            value = item.get("value") or {}
            if isinstance(value, dict):
                return str(value.get("failure_reason") or "")
        return ""

    def _next_payload_family(self, current: str | None) -> str:
        families = ["sqlish", "templateish", "jsonbreaker", "reflection_marker", "pathlike"]
        normalized = str(current or "").strip().lower()
        if normalized not in families:
            return families[0]
        index = (families.index(normalized) + 1) % len(families)
        return families[index]

    def _looks_path_like(self, endpoint: str) -> bool:
        value = str(endpoint or "").lower()
        return any(token in value for token in ("file", "path", "download", "report", "image"))

    def _is_preparation_task(self, task: TaskModel) -> bool:
        return str(task.readiness or "").lower() == "needs_preparation" or str(task.test_strategy or "").lower() in self.PREPARATION_STRATEGIES

    def _emit_followup_decision(
        self,
        *,
        active_task: TaskModel,
        state: SchedulerState,
        status: str,
        summary: str,
        reason: dict[str, Any],
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=state.run_id,
            root_trace_id=state.root_trace_id,
            task=active_task,
        )
        self.diagnostics.emit(
            event_type="followup_generation_attempt",
            component="followup",
            status=status,
            summary=summary,
            run_id=state.run_id,
            trace_context=trace_context,
            reason=reason,
            counters={
                "exploration_budget_used": int(state.exploration_budget_used or 0),
                "deepening_budget_used": int(state.deepening_budget_used or 0),
                "preparation_budget_used": int(state.preparation_budget_used or 0),
            },
        )

    def _emit_followup_candidate(
        self,
        *,
        active_task: TaskModel,
        state: SchedulerState,
        candidate: TaskModel,
        status: str,
        reason: dict[str, Any],
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=state.run_id,
            root_trace_id=state.root_trace_id,
            task=candidate,
            parent_trace_id=self.diagnostics.trace_context(
                run_id=state.run_id,
                root_trace_id=state.root_trace_id,
                task=active_task,
            )["trace_id"],
        )
        self.diagnostics.emit(
            event_type="followup_task_generated" if status == "generated" else "followup_task_suppressed",
            component="followup",
            status=status,
            summary=f"Follow-up {status} for {active_task.id} using strategy {candidate.test_strategy}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason=reason,
            extra={
                "source_task_id": active_task.id,
                "source_strategy": active_task.test_strategy,
                "followup_allowed_tools": list(candidate.allowed_tools or []),
                "readiness": candidate.readiness,
                "payload_family": candidate.payload_family,
                "origin_reason": candidate.origin_reason,
            },
        )
