"""Phase 5.6 — ObservationTriage.

Triages a single Observation: sets security_relevance,
recommended_next_action, and optionally creates a VerificationPlan.

Phase 5.6 rules:
- judge_worthy stays False for ALL observations.
- No EvidencePack, Judge input, or confirmed findings.
- VerificationPlan.commands are lightweight stubs.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

try:
    from backend.models.observation import (
        Observation,
        SecurityRelevance,
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.observation import (
        Observation,
        SecurityRelevance,
        VerificationPlan,
        VerificationPlanCommand,
        VerificationPlanStatus,
    )
    from storage.memory_store import memory_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_plan_id() -> str:
    return f"vplan_{uuid4().hex[:16]}"


_TRIAGE_RULES: dict[str, dict] = {
    "unexpected_500": {
        "security_relevance": "low",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["minimized_request", "reproduced_500"],
    },
    "server_error_candidate": {
        "security_relevance": "low",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["minimized_request", "reproduced_500"],
    },
    "cross_role_access_signal": {
        "security_relevance": "high",
        "recommended_next_action": "prove_ownership",
        "goal": "prove_ownership",
        "worker_class": "access_control",
        "strategy": "prove_ownership",
        "required_evidence": [
            "owner_collection_contains_object",
            "attacker_collection_does_not_contain_object",
        ],
    },
    "validated_security_header_issue": {
        "security_relevance": "medium",
        "recommended_next_action": "prove_security_header_misconfiguration",
        "goal": "prove_security_header_misconfiguration",
        "worker_class": "misconfiguration",
        "strategy": "prove_security_header_misconfiguration",
        "required_evidence": [],
    },
    "zap_alert": {
        "security_relevance": "medium",
        "recommended_next_action": "replay_misconfiguration",
        "goal": "replay_misconfiguration",
        "worker_class": "misconfiguration",
        "strategy": "replay_misconfiguration",
        "required_evidence": ["replayed_response_confirms_alert"],
    },
    "nuclei_match": {
        "security_relevance": "medium",
        "recommended_next_action": "validate_template_match",
        "goal": "validate_template_match",
        "worker_class": "misconfiguration",
        "strategy": "validate_template_match",
        "required_evidence": ["reproduced_match"],
    },
    "discovered_endpoint": {
        "security_relevance": "low",
        "recommended_next_action": "undocumented_endpoint_auth_check",
        "goal": "undocumented_endpoint_auth_check",
        "worker_class": "discovery_inventory",
        "strategy": "undocumented_endpoint_auth_check",
        "required_evidence": ["auth_required_confirmed", "no_auth_access_result"],
    },
    "hidden_parameter": {
        "security_relevance": "low",
        "recommended_next_action": "parameter_replay_validation",
        "goal": "parameter_replay_validation",
        "worker_class": "contract_fuzzing",
        "strategy": "parameter_replay_validation",
        "required_evidence": ["parameter_impact_confirmed"],
    },
    "auth_anomaly": {
        "security_relevance": "medium",
        "recommended_next_action": "auth_replay_validation",
        "goal": "auth_replay_validation",
        "worker_class": "access_control",
        "strategy": "auth_replay_validation",
        "required_evidence": ["auth_bypass_confirmed"],
    },
    "state_changed_after_invalid_payload": {
        "security_relevance": "medium",
        "recommended_next_action": "replay_minimized_payload",
        "goal": "replay_minimized_payload",
        "worker_class": "contract_fuzzing",
        "strategy": "replay_minimized_payload",
        "required_evidence": ["state_change_reproduced"],
    },
}

_STORE_ONLY_TYPES = {
    "timeout_signal",
    "unsupported_tool_signal",
    "tool_error",
    "sensitive_field_seen",
    "js_endpoint_extraction_result",
    "response_field_inventory",
    "data_exposure_probe_result",
    "auth_flow_signal",
    "test_account_materialization_result",
    "resource_instance_inventory",
    "targeted_object_harvest_result",
    "resource_seed_result",
    "bola_object_pair_inventory",
}

_SCHEMA_MISMATCH_STRONG_SIGNALS = {"5xx", "unexpected_2xx", "schema_violation"}

_INJECTION_STRONG_SIGNALS = frozenset({
    "db_error_pattern",
    "server_error_on_payload",
    "reflected_marker",
    "template_evaluation_marker",
    "traversal_marker",
    "nosql_operator_effect",
})

_CORS_STRONG_ISSUES = frozenset({
    "cors_wildcard_with_credentials",
    "cors_origin_reflection_with_credentials",
})

_COOKIE_STRONG_ISSUES = frozenset({
    "missing_httponly",
    "missing_secure",
    "samesite_none_without_secure",
})

class ObservationTriage:

    def triage(self, observation_id: str) -> tuple[Observation | None, VerificationPlan | None, str | None]:
        """Triage a single observation.

        Returns (observation, verification_plan_or_None, error_or_None).
        """
        obs_data = memory_store.get_observation(observation_id)
        if obs_data is None:
            return None, None, "observation_not_found"

        obs = Observation.model_validate(obs_data)
        obs_type = obs.type

        if obs_type in _STORE_ONLY_TYPES:
            obs.recommended_next_action = "store_only"
            obs.security_relevance = SecurityRelevance.informational
            obs.judge_worthy = False
            self._persist_obs(obs)
            return obs, None, None

        if obs_type == "schema_mismatch":
            return self._triage_schema_mismatch(obs)

        if obs_type == "injection_signal":
            return self._triage_injection_signal(obs)
        if obs_type == "mass_assignment_signal":
            return self._triage_mass_assignment_signal(obs)
        if obs_type == "validated_cors_issue":
            return self._triage_validated_cors_issue(obs)
        if obs_type == "validated_cookie_flag_issue":
            return self._triage_validated_cookie_flag_issue(obs)
        if obs_type == "undocumented_endpoint_signal":
            return self._triage_undocumented_endpoint_signal(obs)
        if obs_type == "ssrf_candidate_signal":
            return self._triage_ssrf_candidate_signal(obs)
        if obs_type == "ssrf_probe_result":
            return self._triage_ssrf_probe_result(obs)
        if obs_type == "data_exposure_signal":
            return self._triage_data_exposure_signal(obs)
        if obs_type == "bola_replay_result":
            return self._triage_bola_replay_result(obs)

        rule = _TRIAGE_RULES.get(obs_type)
        if rule is None:
            obs.recommended_next_action = "store_only"
            obs.security_relevance = SecurityRelevance.informational
            obs.judge_worthy = False
            self._persist_obs(obs)
            return obs, None, None

        obs.security_relevance = SecurityRelevance(rule["security_relevance"])
        obs.recommended_next_action = rule["recommended_next_action"]
        obs.judge_worthy = False
        self._persist_obs(obs)

        existing_plan = self._find_existing_active_plan(obs)
        if existing_plan is not None:
            return obs, existing_plan, None

        plan = self._create_plan(obs, rule)
        return obs, plan, None

    def _triage_schema_mismatch(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        signal_types_raw = details.get("signal_types")
        signal_types = (
            [str(x).strip().lower() for x in signal_types_raw if str(x).strip()]
            if isinstance(signal_types_raw, list)
            else []
        )
        has_strong_signal = any(sig in _SCHEMA_MISMATCH_STRONG_SIGNALS for sig in signal_types)
        if has_strong_signal:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "validate_schema_mismatch_impact"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_schema_mismatch_impact",
                worker_class="contract_fuzzing",
                strategy="validate_schema_mismatch_impact",
                required_evidence=[
                    "schemathesis_signal",
                    "operation_context",
                    "impact_classification",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_injection_signal(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        signal_types_raw = details.get("signal_types")
        signal_types = (
            [str(x).strip().lower() for x in signal_types_raw if str(x).strip()]
            if isinstance(signal_types_raw, list)
            else []
        )
        has_strong = any(sig in _INJECTION_STRONG_SIGNALS for sig in signal_types)
        if has_strong:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "validate_injection_impact"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_injection_impact",
                worker_class="contract_fuzzing",
                strategy="validate_injection_impact",
                required_evidence=[
                    "injection_signal",
                    "parameter_context",
                    "baseline_attack_delta",
                    "impact_classification",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_mass_assignment_signal(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        fields_selected_raw = details.get("fields_selected")
        fields_selected = (
            [str(x).strip() for x in fields_selected_raw if str(x).strip()]
            if isinstance(fields_selected_raw, list)
            else []
        )
        seed_present = details.get("seed_request_id_present") is True
        seed_request_id = str(details.get("seed_request_id") or "").strip()
        diagnostic_only = details.get("diagnostic_only") is True
        mutation_policy = str(details.get("mutation_policy") or "").strip().lower()

        strong_enough = (
            bool(fields_selected)
            and seed_present
            and bool(seed_request_id)
            and diagnostic_only
            and mutation_policy == "diagnostic_only"
        )
        if strong_enough:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "validate_mass_assignment_impact"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_mass_assignment_impact",
                worker_class="access_control",
                strategy="validate_mass_assignment_impact",
                required_evidence=[
                    "mass_assignment_signal",
                    "seed_reference",
                    "field_selection_context",
                    "runtime_effect_assessment",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_data_exposure_signal(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        sens = int(details.get("sensitive_field_count") or 0)
        op = str(details.get("operation_id") or obs.operation_id or "").strip()
        path = str(details.get("path") or "").strip()
        if sens > 0 and op and path:
            rec = str(details.get("recommended_next_action") or "").strip()
            if rec:
                obs.recommended_next_action = rec
            sec_raw = str(details.get("security_relevance") or "medium").lower()
            try:
                obs.security_relevance = SecurityRelevance(sec_raw)
            except ValueError:
                obs.security_relevance = (
                    SecurityRelevance.medium
                    if "sensitive" in sec_raw or "exposure" in sec_raw
                    else SecurityRelevance.informational
                )
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="prove_sensitive_property_exposure",
                worker_class="access_control",
                strategy="validate_response_field_exposure",
                required_evidence=[
                    "response_field_inventory",
                    "sensitive_field_names",
                    "operation_context",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_bola_replay_result(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        access_granted = bool(details.get("access_granted"))
        strength = str(details.get("evidence_strength") or "low").strip().lower()
        op_id = str(details.get("target_operation_id") or obs.operation_id or "").strip()
        if access_granted and strength in {"high", "medium"} and op_id:
            obs.security_relevance = SecurityRelevance.high
            obs.recommended_next_action = "validate_bola_replay_impact"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_bola_replay_impact",
                worker_class="access_control",
                strategy="confirm_bola_replay",
                required_evidence=[
                    "bola_replay_request",
                    "attacker_access_result",
                    "operation_context",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_validated_cors_issue(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        issue_codes_raw = details.get("issue_codes")
        issue_codes = (
            [str(x).strip() for x in issue_codes_raw if str(x).strip()]
            if isinstance(issue_codes_raw, list)
            else []
        )
        has_strong = any(code in _CORS_STRONG_ISSUES for code in issue_codes)
        validation_mode = str(details.get("validation_mode") or "").strip()
        has_location = bool(
            str(obs.operation_id or details.get("operation_id") or "").strip()
            or str(details.get("request_url") or details.get("path_template") or "").strip()
        )

        strong_enough = has_strong and bool(validation_mode) and has_location
        if strong_enough:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "prove_cors_misconfiguration"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="prove_cors_misconfiguration",
                worker_class="misconfiguration",
                strategy="prove_cors_misconfiguration",
                required_evidence=[
                    "validated_cors_issue",
                    "cors_policy_state",
                    "origin_probe_context",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_validated_cookie_flag_issue(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        issue_codes_raw = details.get("issue_codes")
        issue_codes = (
            [str(x).strip() for x in issue_codes_raw if str(x).strip()]
            if isinstance(issue_codes_raw, list)
            else []
        )
        has_strong = any(code in _COOKIE_STRONG_ISSUES for code in issue_codes)
        validation_mode = str(details.get("validation_mode") or "").strip()
        cookie_name_hash = str(details.get("cookie_name_hash") or "").strip()
        has_location = bool(
            str(obs.operation_id or details.get("operation_id") or "").strip()
            or str(details.get("request_url") or details.get("path_template") or "").strip()
        )

        strong_enough = has_strong and bool(validation_mode) and bool(cookie_name_hash) and has_location
        if strong_enough:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "prove_cookie_flag_misconfiguration"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="prove_cookie_flag_misconfiguration",
                worker_class="misconfiguration",
                strategy="prove_cookie_flag_misconfiguration",
                required_evidence=[
                    "validated_cookie_flag_issue",
                    "cookie_flag_context",
                    "endpoint_context",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_undocumented_endpoint_signal(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        method = str(details.get("method") or "").strip().upper()
        path = str(details.get("path") or "").strip()
        status_code_raw = details.get("status_code")
        try:
            status_code = int(status_code_raw)
        except (TypeError, ValueError):
            status_code = 0
        openapi_match = details.get("openapi_match") is True
        is_static_asset = details.get("is_static_asset") is True
        strong_enough = (
            bool(method)
            and bool(path)
            and status_code > 0
            and status_code != 404
            and not openapi_match
            and not is_static_asset
        )
        if strong_enough:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "validate_undocumented_endpoint_inventory"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_undocumented_endpoint_inventory",
                worker_class="discovery_inventory",
                strategy="validate_undocumented_endpoint",
                required_evidence=[
                    "discovered_endpoint",
                    "openapi_absence",
                    "runtime_observed_status",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_ssrf_candidate_signal(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        operation_id = str(details.get("operation_id") or obs.operation_id or "").strip()
        field_name = str(details.get("field_name") or "").strip()
        field_path = str(details.get("field_path") or "").strip()
        validation_mode = str(details.get("validation_mode") or "").strip()
        strong_enough = bool(operation_id and field_name and field_path and validation_mode == "ssrf_candidate_detection")
        if strong_enough:
            obs.security_relevance = SecurityRelevance.medium
            obs.recommended_next_action = "validate_ssrf_candidate_safely"
            obs.judge_worthy = False
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_ssrf_candidate_safely",
                worker_class="input_validation",
                strategy="detect_ssrf_candidate_fields",
                required_evidence=[
                    "openapi_schema_url_like_field",
                    "operation_context",
                ],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _triage_ssrf_probe_result(
        self, obs: Observation,
    ) -> tuple[Observation, VerificationPlan | None, None]:
        details = obs.details if isinstance(obs.details, dict) else {}
        validation_mode = str(details.get("validation_mode") or "").strip()
        callback_received = bool(details.get("callback_received"))
        evidence_strength = str(details.get("evidence_strength") or "low").strip().lower()
        if validation_mode == "ssrf_callback_probe" and callback_received and evidence_strength in {"medium", "high"}:
            obs.security_relevance = SecurityRelevance.high
            obs.recommended_next_action = "build_evidence_pack"
            obs.judge_worthy = True
            self._persist_obs(obs)
            existing_plan = self._find_existing_active_plan(obs)
            if existing_plan is not None:
                return obs, existing_plan, None
            plan = VerificationPlan(
                verification_plan_id=_make_plan_id(),
                campaign_id=obs.campaign_id,
                parent_observation_id=obs.observation_id,
                parent_task_id=obs.task_id,
                goal="validate_ssrf_callback_impact",
                worker_class="ssrf_external",
                strategy="callback_ssrf_probe",
                required_evidence=["callback_received", "correlation_id_matched"],
                commands=[],
                status=VerificationPlanStatus.pending,
                created_at=_now_iso(),
            )
            memory_store.store_verification_plan(
                plan.verification_plan_id,
                obs.campaign_id,
                plan.model_dump(mode="json"),
            )
            return obs, plan, None

        obs.security_relevance = SecurityRelevance.informational
        obs.recommended_next_action = "store_only"
        obs.judge_worthy = False
        self._persist_obs(obs)
        return obs, None, None

    def _create_plan(self, obs: Observation, rule: dict) -> VerificationPlan:
        plan = VerificationPlan(
            verification_plan_id=_make_plan_id(),
            campaign_id=obs.campaign_id,
            parent_observation_id=obs.observation_id,
            parent_task_id=obs.task_id,
            goal=rule["goal"],
            worker_class=rule.get("worker_class", ""),
            strategy=rule.get("strategy", ""),
            required_evidence=rule.get("required_evidence", []),
            commands=[
                VerificationPlanCommand(
                    tool_name="custom_request_executor",
                    strategy=rule.get("strategy", ""),
                    inputs={"parent_observation_id": obs.observation_id},
                ),
            ],
            status=VerificationPlanStatus.pending,
            created_at=_now_iso(),
        )
        memory_store.store_verification_plan(
            plan.verification_plan_id, obs.campaign_id,
            plan.model_dump(mode="json"),
        )
        return plan

    def _persist_obs(self, obs: Observation) -> None:
        memory_store.update_observation(obs.observation_id, obs.model_dump(mode="json"))

    def _find_existing_active_plan(self, obs: Observation) -> VerificationPlan | None:
        plans = memory_store.list_verification_plans_by_campaign(obs.campaign_id)
        for raw in plans:
            plan = VerificationPlan.model_validate(raw)
            if plan.parent_observation_id != obs.observation_id:
                continue
            if plan.status in {
                VerificationPlanStatus.pending,
                VerificationPlanStatus.in_progress,
            }:
                return plan
        return None
