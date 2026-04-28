"""Phase 6 — EvidencePackBuilder.

Builds a structured ``EvidencePack`` from already-stored Phase 1-5.6 state:
* ``Observation`` (Phase 5.6) — the signal that triggers evidence assembly.
* ``VerificationPlan`` (Phase 5.6, optional) — declared ``required_evidence``.
* ``RequestCorpusItem`` (Phase 2) — baseline / attack / control HTTP exchanges.
* ``ApiGraph.Operation`` (Phase 3) — endpoint/method/owasp_candidates metadata.
* ``ToolArtifactRef`` (Phase 5) — pointers to stored stdout/stderr/json blobs.

Phase 6 invariants (enforced by this service):

* No ``Judge`` is invoked.
* No ``Finding`` is created.
* No tool is executed.
* No task is enqueued.
* No raw HTTP body is embedded; exchanges are referenced by ``request_id``.
* The legacy ``EvidenceBuilderService.from_wrapper_result`` path stays
  untouched; this builder operates on a separate model and a separate store
  index (``evidence_packs`` / ``evidence_packs_by_*``).
* ``judge_ready=True`` only when ``status == ready_for_judge`` AND
  ``missing_evidence == []``.
* Idempotent for the same ``(observation_id, verification_plan_id)`` pair.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

try:
    from backend.models.api_graph import Operation
    from backend.models.corpus import RequestCorpusItem, StatusClassification
    from backend.models.evidence_pack import (
        EvidenceArtifactRef,
        EvidenceAttack,
        EvidenceBaseline,
        EvidenceControl,
        EvidenceDiff,
        EvidenceHttpExchangeRef,
        EvidenceOwnershipProof,
        EvidencePack,
        EvidencePackStatus,
        EvidenceReplayStep,
        MissingEvidenceItem,
    )
    from backend.models.observation import (
        Observation,
        ObservationType,
        VerificationPlan,
        VerificationPlanStatus,
    )
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
    from models.corpus import RequestCorpusItem, StatusClassification
    from models.evidence_pack import (
        EvidenceArtifactRef,
        EvidenceAttack,
        EvidenceBaseline,
        EvidenceControl,
        EvidenceDiff,
        EvidenceHttpExchangeRef,
        EvidenceOwnershipProof,
        EvidencePack,
        EvidencePackStatus,
        EvidenceReplayStep,
        MissingEvidenceItem,
    )
    from models.observation import (
        Observation,
        ObservationType,
        VerificationPlan,
        VerificationPlanStatus,
    )
    from services.api_graph_service import ApiGraphService
    from services.request_corpus_service import RequestCorpusService
    from storage.memory_store import memory_store


_HARD_CODED_OWASP_BY_OBS_TYPE: dict[str, str] = {
    ObservationType.cross_role_access_signal.value: "API1_BOLA",
    ObservationType.auth_anomaly.value: "API2_AUTH",
    ObservationType.validated_security_header_issue.value: "API8_SECURITY_MISCONFIGURATION",
    ObservationType.zap_alert.value: "API8_SECURITY_MISCONFIGURATION",
    ObservationType.nuclei_match.value: "API8_SECURITY_MISCONFIGURATION",
    ObservationType.discovered_endpoint.value: "API9_IMPROPER_INVENTORY_MANAGEMENT",
    ObservationType.undocumented_endpoint_signal.value: "API9_IMPROPER_INVENTORY_MANAGEMENT",
    ObservationType.ssrf_candidate_signal.value: "API7_SERVER_SIDE_REQUEST_FORGERY",
    ObservationType.auth_flow_signal.value: "API2_AUTH",
    ObservationType.validated_cors_issue.value: "API8_SECURITY_MISCONFIGURATION",
    ObservationType.validated_cookie_flag_issue.value: "API8_SECURITY_MISCONFIGURATION",
    ObservationType.data_exposure_signal.value: "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
    ObservationType.resource_instance_inventory.value: "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
    ObservationType.resource_seed_result.value: "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
    ObservationType.bola_object_pair_inventory.value: "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
    ObservationType.bola_replay_result.value: "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
}


_NOT_JUDGE_READY_TYPES: set[str] = {
    ObservationType.timeout_signal.value,
    ObservationType.unsupported_tool_signal.value,
    ObservationType.tool_error.value,
    ObservationType.sensitive_field_seen.value,
    ObservationType.auth_flow_signal.value,
    ObservationType.resource_instance_inventory.value,
    ObservationType.resource_seed_result.value,
    ObservationType.bola_object_pair_inventory.value,
}

_INJECTION_STRONG_SIGNALS: frozenset[str] = frozenset({
    "db_error_pattern",
    "server_error_on_payload",
    "reflected_marker",
    "template_evaluation_marker",
    "traversal_marker",
    "nosql_operator_effect",
})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_evidence_id() -> str:
    return f"evp_{uuid4().hex[:16]}"


class EvidencePackBuildError:
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message


class EvidencePackBuilder:
    """Backend-owned builder.

    The class is stateless aside from helper services. All state lives in
    ``memory_store``. The builder never mutates Observation/VerificationPlan
    state and never creates Findings.
    """

    def __init__(self) -> None:
        self._corpus = RequestCorpusService()
        self._graph = ApiGraphService()

    # ------------------------------------------------------------------
    # Public entry points
    # ------------------------------------------------------------------
    def build_from_observation(
        self, observation_id: str
    ) -> tuple[EvidencePack | None, EvidencePackBuildError | None, bool]:
        obs_data = memory_store.get_observation(observation_id)
        if obs_data is None:
            return None, EvidencePackBuildError(
                "observation_not_found",
                f"Observation '{observation_id}' not found.",
            ), False

        obs = Observation.model_validate(obs_data)
        if memory_store.get_campaign(obs.campaign_id) is None:
            return None, EvidencePackBuildError(
                "campaign_not_found",
                f"Campaign '{obs.campaign_id}' not found.",
            ), False
        boundary_error = self._validate_tool_run_campaign_boundary(obs)
        if boundary_error is not None:
            return None, boundary_error, False
        plan = self._find_active_plan(obs)
        return self._build(obs, plan)

    def build_from_verification_plan(
        self, verification_plan_id: str
    ) -> tuple[EvidencePack | None, EvidencePackBuildError | None, bool]:
        plan_data = memory_store.get_verification_plan(verification_plan_id)
        if plan_data is None:
            return None, EvidencePackBuildError(
                "verification_plan_not_found",
                f"VerificationPlan '{verification_plan_id}' not found.",
            ), False

        plan = VerificationPlan.model_validate(plan_data)
        if memory_store.get_campaign(plan.campaign_id) is None:
            return None, EvidencePackBuildError(
                "campaign_not_found",
                f"Campaign '{plan.campaign_id}' not found.",
            ), False
        if not plan.parent_observation_id:
            return None, EvidencePackBuildError(
                "verification_plan_without_parent_observation",
                f"VerificationPlan '{verification_plan_id}' has no parent observation.",
            ), False

        obs_data = memory_store.get_observation(plan.parent_observation_id)
        if obs_data is None:
            return None, EvidencePackBuildError(
                "parent_observation_not_found",
                f"Parent observation '{plan.parent_observation_id}' not found.",
            ), False

        obs = Observation.model_validate(obs_data)
        if obs.campaign_id != plan.campaign_id:
            return None, EvidencePackBuildError(
                "parent_observation_campaign_mismatch",
                (
                    "VerificationPlan campaign_id does not match its parent "
                    f"Observation campaign_id ('{plan.campaign_id}' != '{obs.campaign_id}')."
                ),
            ), False
        boundary_error = self._validate_tool_run_campaign_boundary(obs)
        if boundary_error is not None:
            return None, boundary_error, False
        return self._build(obs, plan)

    # ------------------------------------------------------------------
    # Core builder
    # ------------------------------------------------------------------
    def _build(
        self, obs: Observation, plan: VerificationPlan | None
    ) -> tuple[EvidencePack, None, bool]:
        plan_id = plan.verification_plan_id if plan else ""
        existing = self._find_existing(obs.observation_id, plan_id)
        if existing is not None:
            return existing, None, True

        obs_type = obs.type.value if hasattr(obs.type, "value") else str(obs.type)

        pack = self._init_pack(obs, plan)

        if obs_type in _NOT_JUDGE_READY_TYPES:
            self._fill_not_judge_ready(pack, obs)
            self._persist(pack, obs, plan)
            return pack, None, False

        if obs_type == ObservationType.cross_role_access_signal.value:
            self._fill_cross_role(pack, obs, plan)
        elif obs_type == ObservationType.bola_replay_result.value:
            self._fill_bola_replay_result(pack, obs, plan)
        elif obs_type in (
            ObservationType.unexpected_500.value,
            ObservationType.server_error_candidate.value,
        ):
            self._fill_unexpected_500(pack, obs, plan)
        elif obs_type == ObservationType.auth_anomaly.value:
            self._fill_auth_anomaly(pack, obs, plan)
        elif obs_type == ObservationType.validated_security_header_issue.value:
            self._fill_validated_security_header_issue(pack, obs, plan)
        elif obs_type in (
            ObservationType.zap_alert.value,
            ObservationType.nuclei_match.value,
        ):
            self._fill_zap_or_nuclei(pack, obs, plan)
        elif obs_type == ObservationType.discovered_endpoint.value:
            self._fill_discovered_endpoint(pack, obs, plan)
        elif obs_type == ObservationType.undocumented_endpoint_signal.value:
            self._fill_undocumented_endpoint_signal(pack, obs, plan)
        elif obs_type == ObservationType.ssrf_candidate_signal.value:
            self._fill_ssrf_candidate_signal(pack, obs, plan)
        elif obs_type == ObservationType.schema_mismatch.value:
            self._fill_schema_mismatch(pack, obs, plan)
        elif obs_type == ObservationType.injection_signal.value:
            self._fill_injection_signal(pack, obs, plan)
        elif obs_type == ObservationType.mass_assignment_signal.value:
            self._fill_mass_assignment_signal(pack, obs, plan)
        elif obs_type == ObservationType.data_exposure_signal.value:
            self._fill_data_exposure_signal(pack, obs, plan)
        elif obs_type == ObservationType.validated_cors_issue.value:
            self._fill_validated_cors_issue_cors(pack, obs, plan)
        elif obs_type == ObservationType.validated_cookie_flag_issue.value:
            self._fill_validated_cookie_flag_issue(pack, obs, plan)
        else:
            self._fill_not_judge_ready(pack, obs, code="unsupported_observation_type")

        self._finalize_status(pack, plan)
        self._persist(pack, obs, plan)
        return pack, None, False

    # ------------------------------------------------------------------
    # Init / finalize helpers
    # ------------------------------------------------------------------
    def _init_pack(self, obs: Observation, plan: VerificationPlan | None) -> EvidencePack:
        operation = self._lookup_operation(obs.campaign_id, obs.operation_id)
        owasp = self._derive_owasp_category(obs, operation)

        pack = EvidencePack(
            evidence_id=_make_evidence_id(),
            campaign_id=obs.campaign_id,
            task_id=obs.task_id,
            observation_id=obs.observation_id,
            verification_plan_id=plan.verification_plan_id if plan else "",
            tool_run_ids=[obs.tool_run_id] if obs.tool_run_id else [],
            owasp_category=owasp,
            vulnerability_class=self._vulnerability_class(obs),
            operation_id=obs.operation_id,
            endpoint=operation.path_template if operation else "",
            method=(operation.method if operation else "").upper(),
            hypothesis="",
            confidence=float(obs.confidence or 0.0),
            status=EvidencePackStatus.incomplete,
            judge_ready=False,
            created_at=_now_iso(),
        )
        for ref in self._collect_artifact_refs(
            obs.campaign_id, obs.tool_run_id, obs.artifact_refs
        ):
            pack.artifact_refs.append(ref)
        return pack

    def _finalize_status(self, pack: EvidencePack, plan: VerificationPlan | None) -> None:
        if pack.status == EvidencePackStatus.not_judge_ready:
            pack.judge_ready = False
            return

        if plan is not None:
            self._merge_required_evidence(pack, plan)

        if pack.missing_evidence:
            pack.status = EvidencePackStatus.incomplete
            pack.judge_ready = False
            return

        pack.status = EvidencePackStatus.ready_for_judge
        pack.judge_ready = True

    def _merge_required_evidence(
        self, pack: EvidencePack, plan: VerificationPlan
    ) -> None:
        already_codes = {item.code for item in pack.missing_evidence}
        for code in plan.required_evidence:
            if self._is_required_code_satisfied(code, pack):
                continue
            if code in already_codes:
                continue
            pack.missing_evidence.append(
                MissingEvidenceItem(
                    code=code,
                    description=f"VerificationPlan '{plan.verification_plan_id}' requires '{code}'.",
                    required_for=plan.goal or pack.vulnerability_class,
                )
            )

    @staticmethod
    def _is_required_code_satisfied(code: str, pack: EvidencePack) -> bool:
        """Map a VerificationPlan ``required_evidence`` code to pack structure.

        We avoid free-text matching where possible; structural checks are
        preferred. Only a few description-based checks remain (replay /
        impact validation) because Phase 6 keeps replay step descriptions as
        short labels rather than typed enums.
        """
        if code == "minimized_request":
            return any(c.name == "minimized_request" for c in pack.controls)
        if code == "reproduced_500":
            for step in pack.replay_steps:
                ref = step.request_ref
                if ref is None:
                    continue
                if 500 <= ref.status_code < 600 and "reproduce" in (step.description or "").lower():
                    return True
            return False
        if code == "owner_collection_contains_object":
            return (
                pack.ownership_proof is not None
                and pack.ownership_proof.owner_collection_request_ref is not None
            )
        if code == "attacker_collection_does_not_contain_object":
            return (
                pack.ownership_proof is not None
                and pack.ownership_proof.attacker_collection_request_ref is not None
            )
        if code == "auth_required_confirmed":
            return any(c.name == "auth_required_confirmed" for c in pack.controls)
        if code == "no_auth_access_result":
            return any(c.name == "no_auth_access_result" for c in pack.controls)
        if code == "replayed_response_confirms_alert":
            return any(
                "confirms" in (s.description or "").lower()
                or "alert" in (s.description or "").lower()
                for s in pack.replay_steps
            )
        if code == "reproduced_match":
            return any(
                "match" in (s.description or "").lower()
                or "reproduction" in (s.description or "").lower()
                for s in pack.replay_steps
            )
        if code == "impact_confirmed":
            return any(
                "impact" in (s.description or "").lower() for s in pack.replay_steps
            )
        if code == "schemathesis_signal":
            return any(
                s.startswith("signal:") for s in (pack.derived_signals or [])
            )
        if code == "operation_context":
            return bool((pack.operation_id or "").strip())
        if code == "impact_classification":
            strong = {"5xx", "schema_violation", "unexpected_2xx"}
            seen = {
                str(s).split("signal:", 1)[1]
                for s in (pack.derived_signals or [])
                if str(s).startswith("signal:")
            }
            if bool(seen & strong):
                return True
            der_inj = pack.derived_signals or []
            return any(str(s).startswith("strong_signal:") for s in der_inj)
        if code == "injection_signal":
            der = pack.derived_signals or []
            if "injection_signal" not in der:
                return False
            return any(str(s).startswith("signal:") for s in der)
        if code == "parameter_context":
            der = pack.derived_signals or []
            prefixes = (
                "parameter_name:",
                "parameter_location:",
                "payload_family:",
                "payload_label:",
            )
            for pref in prefixes:
                match = next((str(s) for s in der if str(s).startswith(pref)), "")
                rest = match.split(":", 1)[-1].strip() if match else ""
                if not rest:
                    return False
            return True
        if code == "baseline_attack_delta":
            der = pack.derived_signals or []
            return any(str(s).startswith("baseline_status:") for s in der) and any(
                str(s).startswith("attack_status:") for s in der
            )
        if code.startswith("operation_id:"):
            # Legacy VerificationPlan rows mistakenly used operation_id:<op> as a code.
            expected = code[len("operation_id:") :].strip()
            if not expected:
                return False
            if (pack.operation_id or "").strip() == expected:
                return True
            return any(
                str(s) == f"operation_id:{expected}"
                for s in (pack.derived_signals or [])
            )
        if code == "auth_bypass_confirmed":
            return (
                pack.attack is not None
                and pack.attack.request_ref is not None
                and pack.baseline is not None
                and pack.baseline.request_ref is not None
            )
        if code == "mass_assignment_signal":
            return "mass_assignment_signal" in (pack.derived_signals or [])
        if code == "response_field_inventory":
            return any(
                str(s).startswith("response_field_inventory:")
                for s in (pack.derived_signals or [])
            )
        if code == "sensitive_field_names":
            return any(
                str(s).startswith("sensitive_field_name:")
                for s in (pack.derived_signals or [])
            )
        if code == "seed_reference":
            return (
                pack.attack is not None
                and pack.attack.request_ref is not None
                and bool((pack.attack.request_ref.request_id or "").strip())
            )
        if code == "field_selection_context":
            return any(str(s).startswith("fields_selected_count:") for s in (pack.derived_signals or []))
        if code == "runtime_effect_assessment":
            return any(str(s).startswith("runtime_effect_proven:") for s in (pack.derived_signals or []))
        if code == "validated_cors_issue":
            return "validated_cors_issue" in (pack.derived_signals or [])
        if code == "cors_policy_state":
            return any(str(s).startswith("acao_state:") for s in (pack.derived_signals or []))
        if code == "origin_probe_context":
            return any(str(s).startswith("origin_probe_label:") for s in (pack.derived_signals or []))
        if code == "validated_cookie_flag_issue":
            return "validated_cookie_flag_issue" in (pack.derived_signals or [])
        if code == "cookie_flag_context":
            return any(str(s).startswith("cookie_name_hash:") for s in (pack.derived_signals or []))
        if code == "discovered_endpoint":
            return "undocumented_endpoint_signal" in (pack.derived_signals or [])
        if code == "openapi_absence":
            return "openapi_match:false" in (pack.derived_signals or [])
        if code == "runtime_observed_status":
            return any(str(s).startswith("status_code:") for s in (pack.derived_signals or []))
        if code == "endpoint_context":
            return bool((pack.endpoint or "").strip())
        return False

    # ------------------------------------------------------------------
    # OWASP / class derivation
    # ------------------------------------------------------------------
    def _derive_owasp_category(
        self, obs: Observation, operation: Operation | None
    ) -> str:
        obs_type = obs.type.value if hasattr(obs.type, "value") else str(obs.type)

        if operation is not None and operation.owasp_candidates:
            return operation.owasp_candidates[0]

        if obs_type == ObservationType.schema_mismatch.value:
            return "API8_SECURITY_MISCONFIGURATION"

        if obs_type == ObservationType.injection_signal.value:
            return "API8_SECURITY_MISCONFIGURATION"

        if obs_type in (
            ObservationType.unexpected_500.value,
            ObservationType.server_error_candidate.value,
        ):
            impact = str(obs.details.get("impact", "")).lower()
            if any(needle in impact for needle in ("rate", "consumption", "resource_abuse")):
                return "API4_UNRESTRICTED_RESOURCE_CONSUMPTION"
            return ""

        return _HARD_CODED_OWASP_BY_OBS_TYPE.get(obs_type, "")

    @staticmethod
    def _vulnerability_class(obs: Observation) -> str:
        obs_type = obs.type.value if hasattr(obs.type, "value") else str(obs.type)
        if obs_type == ObservationType.schema_mismatch.value:
            return "api_schema_contract_violation"
        if obs_type == ObservationType.validated_security_header_issue.value:
            return "security_header_misconfiguration"
        if obs_type == ObservationType.injection_signal.value:
            return "potential_injection"
        if obs_type == ObservationType.validated_cors_issue.value:
            return "cors_misconfiguration"
        if obs_type == ObservationType.validated_cookie_flag_issue.value:
            return "cookie_flag_misconfiguration"
        if obs_type == ObservationType.undocumented_endpoint_signal.value:
            return "undocumented_api_endpoint"
        if obs_type == ObservationType.ssrf_candidate_signal.value:
            return "ssrf_candidate"
        if obs_type == ObservationType.data_exposure_signal.value:
            return "sensitive_property_exposure"
        if obs_type == ObservationType.auth_flow_signal.value:
            return "auth_flow_diagnostic"
        if obs_type == ObservationType.bola_replay_result.value:
            return "bola"
        return obs_type

    # ------------------------------------------------------------------
    # Per-observation-type fillers
    # ------------------------------------------------------------------
    def _fill_cross_role(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        object_id = str(obs.details.get("object_id", "") or "")
        attacker_role = str(obs.details.get("attacker_role", "") or "")
        owner_role = str(obs.details.get("owner_role", "") or "")
        operation_id = obs.operation_id

        pack.hypothesis = self._build_cross_role_hypothesis(
            attacker_role, owner_role, object_id, operation_id
        )

        baseline_ref, attack_ref = self._find_cross_role_refs(
            obs.campaign_id, operation_id, owner_role, attacker_role, object_id
        )

        if baseline_ref is not None:
            pack.baseline = EvidenceBaseline(
                role=baseline_ref.role,
                request_ref=baseline_ref,
                description=f"Owner '{baseline_ref.role}' legitimately accesses object",
            )
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attack_ref.role,
                request_ref=attack_ref,
                description=f"Attacker '{attack_ref.role}' accesses owner's object",
            )

        ownership_proof = self._build_ownership_proof(
            obs.campaign_id,
            object_id,
            owner_role,
            attacker_role,
            operation_id,
            obs.details,
        )
        if ownership_proof is not None:
            pack.ownership_proof = ownership_proof

        negative = self._find_negative_control(
            obs.campaign_id, attacker_role, operation_id, object_id
        )
        if negative is not None:
            pack.controls.append(negative)

        if baseline_ref is not None and attack_ref is not None:
            pack.diff = self._compute_diff(baseline_ref, attack_ref)

        pack.replay_steps = self._build_replay_steps(
            [
                ("baseline", baseline_ref),
                ("attack", attack_ref),
            ]
        )

        missing: list[MissingEvidenceItem] = []
        if baseline_ref is None:
            missing.append(MissingEvidenceItem(
                code="baseline_owner_access_missing",
                description="Owner-role corpus seed for the contested object not found.",
                required_for="cross_role_access_signal",
            ))
        if attack_ref is None:
            missing.append(MissingEvidenceItem(
                code="attack_request_missing",
                description="Attacker-role corpus seed against the contested object not found.",
                required_for="cross_role_access_signal",
            ))
        if ownership_proof is None:
            missing.append(MissingEvidenceItem(
                code="ownership_proof_missing",
                description="Could not find owner_collection_contains_object + "
                            "attacker_collection_does_not_contain_object proof pair.",
                required_for="cross_role_access_signal",
            ))
        if not pack.controls:
            missing.append(MissingEvidenceItem(
                code="negative_control_missing",
                description="Attacker accessing their own resource of the same type was not observed.",
                required_for="cross_role_access_signal",
            ))
        if pack.diff is None:
            missing.append(MissingEvidenceItem(
                code="diff_missing",
                description="No baseline + attack pair available to compute diff.",
                required_for="cross_role_access_signal",
            ))
        if not pack.replay_steps:
            missing.append(MissingEvidenceItem(
                code="replay_steps_missing",
                description="Need ordered baseline + attack replay steps.",
                required_for="cross_role_access_signal",
            ))

        pack.missing_evidence = missing
        pack.derived_signals = self._cross_role_derived_signals(
            obs, baseline_ref, attack_ref, ownership_proof
        )

    def _fill_bola_replay_result(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(details.get("target_operation_id") or obs.operation_id or "").strip()
        path = str(details.get("target_path_template") or "").strip()
        method = str(details.get("target_method") or "GET").strip().upper() or "GET"
        status_code = int(details.get("status_code") or 0)
        access_granted = bool(details.get("access_granted"))
        evidence_strength = str(details.get("evidence_strength") or "low").strip().lower()
        owner_baseline_valid = bool(details.get("owner_baseline_valid"))
        result_label = str(details.get("result") or "").strip()
        request_id = str(details.get("request_id") or obs.request_id or "").strip()
        attacker_auth_profile_id = str(details.get("attacker_auth_profile_id") or "").strip()

        pack.owasp_category = "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"
        pack.vulnerability_class = "bola"
        if op_id:
            pack.operation_id = op_id
        if path:
            pack.endpoint = EvidencePackBuilder._strip_path_query(path)
        if method:
            pack.method = method
        pack.hypothesis = "Attacker-authenticated replay against an owner-linked object returned an accessible response."
        attack_ref = self._sanitize_bola_request_ref(
            self._resolve_request_ref(obs.campaign_id, request_id),
            safe_path_template=pack.endpoint or path,
        )
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attacker_auth_profile_id,
                request_ref=attack_ref,
                description="Attacker-authenticated replay against prepared object pair.",
            )
        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role=attacker_auth_profile_id,
                method=pack.method or "",
                path_template=pack.endpoint or "",
                url="",
                request_ref=attack_ref,
                description="Replay prepared object pair with attacker auth profile.",
            ),
        ]
        pack.derived_signals = [
            "bola_replay_result",
            f"object_pair_id:{str(details.get('object_pair_id') or '')}",
            f"status_code:{status_code}",
            f"result:{result_label}",
            f"access_granted:{str(access_granted).lower()}",
            f"evidence_strength:{evidence_strength or 'low'}",
        ]
        if not owner_baseline_valid:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="owner_baseline_invalid",
                description="Owner baseline request did not succeed (2xx); object pair is not valid evidence for BOLA replay.",
                required_for="bola",
            ))
        if result_label != "attacker_access_granted":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="bola_replay_not_granted",
                description="Replay did not show attacker access granted for the owner-linked object pair.",
                required_for="bola",
            ))
        if not access_granted:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="attacker_access_not_granted",
                description="Replay did not show attacker access to the prepared object pair.",
                required_for="bola",
            ))
        if evidence_strength not in {"high", "medium"}:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="evidence_strength_low",
                description="BOLA replay evidence_strength must be high or medium for judge-ready evidence.",
                required_for="bola",
            ))
        if not op_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="target_operation_id is required for BOLA replay evidence.",
                required_for="bola",
            ))
        if not path:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="endpoint_context_missing",
                description="target_path_template is required for BOLA replay evidence.",
                required_for="bola",
            ))
        if attack_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="attack_request_missing",
                description="Replay request_id is required in corpus for BOLA replay evidence.",
                required_for="bola",
            ))

    @staticmethod
    def _sanitize_bola_request_ref(
        ref: EvidenceHttpExchangeRef | None,
        *,
        safe_path_template: str,
    ) -> EvidenceHttpExchangeRef | None:
        if ref is None:
            return None
        return EvidenceHttpExchangeRef(
            request_id=ref.request_id,
            role=ref.role,
            method=ref.method,
            path_template=safe_path_template,
            url="",
            status_code=ref.status_code,
            classification=ref.classification,
            operation_id=ref.operation_id,
        )

    def _fill_unexpected_500(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        pack.hypothesis = (
            "Server returned an unexpected 5xx; potential resource consumption "
            "or input-handling defect."
        )

        attack_ref = self._resolve_request_ref(obs.campaign_id, obs.request_id)
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attack_ref.role,
                request_ref=attack_ref,
                description="Original 5xx response observed",
            )

        repeated_ref = self._find_repeated_500(
            obs.campaign_id, obs.operation_id, obs.request_id
        )
        if repeated_ref is None:
            explicit = obs.details.get("reproduced_500_request_id")
            repeated_ref = self._resolve_request_ref(obs.campaign_id, str(explicit) if explicit else "")

        minimized_ref = None
        explicit_min = obs.details.get("minimized_request_id")
        if explicit_min:
            minimized_ref = self._resolve_request_ref(obs.campaign_id, str(explicit_min))

        replay: list[tuple[str, EvidenceHttpExchangeRef | None]] = [("attack", attack_ref)]
        if repeated_ref is not None:
            replay.append(("reproduce_500", repeated_ref))
        if minimized_ref is not None:
            replay.append(("minimized", minimized_ref))
        pack.replay_steps = self._build_replay_steps(replay)

        if minimized_ref is not None:
            pack.controls.append(EvidenceControl(
                name="minimized_request",
                role=minimized_ref.role,
                request_ref=minimized_ref,
                description="Minimized payload that still triggers the 5xx.",
            ))

        if attack_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="attack_request_missing",
                description="Original 5xx request not found in corpus.",
                required_for="unexpected_500",
            ))
        if repeated_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="reproduced_500",
                description="A single 5xx is insufficient; need an additional reproduction.",
                required_for="unexpected_500",
            ))
        if minimized_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="minimized_request",
                description="Minimized payload that triggers the 5xx is required.",
                required_for="unexpected_500",
            ))

    def _fill_auth_anomaly(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        pack.hypothesis = "Authentication contract violation observed."

        baseline_ref = None
        if obs.operation_id:
            seeds = self._corpus.find_successful_by_operation(obs.campaign_id, obs.operation_id)
            if seeds:
                baseline_ref = self._item_to_ref(seeds[0])
        explicit_baseline = obs.details.get("baseline_request_id")
        if baseline_ref is None and explicit_baseline:
            baseline_ref = self._resolve_request_ref(obs.campaign_id, str(explicit_baseline))

        attack_ref = self._resolve_request_ref(obs.campaign_id, obs.request_id)

        if baseline_ref is not None:
            pack.baseline = EvidenceBaseline(
                role=baseline_ref.role,
                request_ref=baseline_ref,
                description="Valid auth establishes legitimate access",
            )
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attack_ref.role,
                request_ref=attack_ref,
                description="Bad / missing auth produced the anomaly",
            )

        if baseline_ref is not None and attack_ref is not None:
            pack.diff = self._compute_diff(baseline_ref, attack_ref)

        pack.replay_steps = self._build_replay_steps(
            [("baseline", baseline_ref), ("attack", attack_ref)]
        )

        if baseline_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="baseline_with_valid_auth",
                description="Need a successful corpus seed for this operation with valid auth.",
                required_for="auth_anomaly",
            ))
        if attack_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="attack_with_bad_auth",
                description="Need the corpus seed of the bad/missing-auth attack.",
                required_for="auth_anomaly",
            ))

    def _fill_validated_security_header_issue(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details or {}
        header_name = str(details.get("header_name") or "").strip()
        alert_name = str(details.get("alert_name") or "").strip()
        actual_state = str(details.get("actual_state") or "").strip()
        actual_value_redacted = str(details.get("actual_value_redacted") or "").strip()
        validation_mode = str(details.get("validation_mode") or "").strip()
        source_observation_id = str(details.get("source_observation_id") or "").strip()
        url = str(details.get("url") or "").strip()
        path = str(details.get("path") or "").strip()
        target_location = url or path

        if not pack.method:
            pack.method = "GET"
        if not pack.endpoint:
            pack.endpoint = path or (urlparse(url).path if url else "")

        state_label = actual_state or "unknown_state"
        header_label = header_name or "security header"
        pack.hypothesis = (
            f"Validated {header_label} misconfiguration observed with state '{state_label}'."
        )
        pack.derived_signals = [
            "validated_security_header_issue",
            f"header_name:{header_name}" if header_name else "header_name:",
            f"actual_state:{actual_state}" if actual_state else "actual_state:",
            f"validation_mode:{validation_mode}" if validation_mode else "validation_mode:",
        ]
        pack.replay_steps.append(EvidenceReplayStep(
            order=1,
            role="",
            method="GET",
            path_template=path,
            url=target_location,
            request_ref=None,
            description="Validated security header misconfiguration",
        ))

        if not header_name:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="header_name_missing",
                description="Validated security header issue is missing header_name.",
                required_for="validated_security_header_issue",
            ))
        if not alert_name:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="alert_name_missing",
                description="Validated security header issue is missing alert_name.",
                required_for="validated_security_header_issue",
            ))
        if not actual_state:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="actual_state_missing",
                description="Validated security header issue is missing actual_state.",
                required_for="validated_security_header_issue",
            ))
        if not validation_mode:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="validation_mode_missing",
                description="Validated security header issue is missing validation_mode.",
                required_for="validated_security_header_issue",
            ))
        if not source_observation_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="source_observation_id_missing",
                description="Validated security header issue is missing source_observation_id.",
                required_for="validated_security_header_issue",
            ))
        if not target_location:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="target_location_missing",
                description="Validated security header issue is missing url or path.",
                required_for="validated_security_header_issue",
            ))
        if actual_state == "unsafe_value" and not actual_value_redacted:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="actual_value_missing_for_unsafe_value",
                description="unsafe_value findings must include actual_value_redacted.",
                required_for="validated_security_header_issue",
            ))

    def _fill_zap_or_nuclei(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        is_zap = obs.type.value == ObservationType.zap_alert.value
        pack.hypothesis = (
            "ZAP alert flagged a misconfiguration; needs replay validation."
            if is_zap
            else "Nuclei template matched; needs reproduction."
        )

        attack_ref = self._resolve_request_ref(obs.campaign_id, obs.request_id)
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attack_ref.role,
                request_ref=attack_ref,
                description="Original alert/match request",
            )

        replay_id = (
            obs.details.get("replay_request_id")
            or obs.details.get("reproduced_match_request_id")
            or obs.details.get("replayed_response_request_id")
        )
        replay_ref = self._resolve_request_ref(obs.campaign_id, str(replay_id) if replay_id else "")
        if replay_ref is not None:
            pack.replay_steps.append(EvidenceReplayStep(
                order=1,
                role=replay_ref.role,
                method=replay_ref.method,
                path_template=replay_ref.path_template,
                url=replay_ref.url,
                request_ref=replay_ref,
                description=(
                    "Replay confirms ZAP alert" if is_zap else "Reproduction confirms nuclei match"
                ),
            ))

        if attack_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="original_signal_request_missing",
                description="Original ZAP/nuclei request not found in corpus.",
                required_for=obs.type.value,
            ))
        if replay_ref is None:
            if is_zap:
                pack.missing_evidence.append(MissingEvidenceItem(
                    code="replay_validation_missing",
                    description="Replay request that confirms the alert is required.",
                    required_for="zap_alert",
                ))
            else:
                pack.missing_evidence.append(MissingEvidenceItem(
                    code="reproduction_missing",
                    description="Reproduction request that confirms the match is required.",
                    required_for="nuclei_match",
                ))

    def _fill_discovered_endpoint(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        pack.hypothesis = "Undocumented endpoint discovered; verify auth requirements."

        attack_ref = self._resolve_request_ref(obs.campaign_id, obs.request_id)
        if attack_ref is not None:
            pack.attack = EvidenceAttack(
                role=attack_ref.role,
                request_ref=attack_ref,
                description="Original discovery request",
            )

        auth_required_id = (
            obs.details.get("auth_required_request_id")
            or obs.details.get("authenticated_access_request_id")
        )
        no_auth_id = (
            obs.details.get("no_auth_access_request_id")
            or obs.details.get("unauthenticated_access_request_id")
        )

        auth_required_ref = self._resolve_request_ref(
            obs.campaign_id, str(auth_required_id) if auth_required_id else ""
        )
        no_auth_ref = self._resolve_request_ref(
            obs.campaign_id, str(no_auth_id) if no_auth_id else ""
        )

        if auth_required_ref is not None:
            pack.controls.append(EvidenceControl(
                name="auth_required_confirmed",
                role=auth_required_ref.role,
                request_ref=auth_required_ref,
                description="Endpoint behavior with valid auth.",
            ))
        if no_auth_ref is not None:
            pack.controls.append(EvidenceControl(
                name="no_auth_access_result",
                role=no_auth_ref.role,
                request_ref=no_auth_ref,
                description="Endpoint behavior without auth.",
            ))

        if auth_required_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="auth_required_confirmed",
                description="Authenticated access result for the discovered endpoint is missing.",
                required_for="discovered_endpoint",
            ))
        if no_auth_ref is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="no_auth_access_result",
                description="Unauthenticated access result for the discovered endpoint is missing.",
                required_for="discovered_endpoint",
            ))

    def _fill_undocumented_endpoint_signal(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None,
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        method = str(details.get("method") or "").strip().upper()
        path = str(details.get("path") or "").strip()
        url_sanitized = str(details.get("url_sanitized") or "").strip()
        source = str(details.get("source") or obs.source or "").strip()
        matched_operation_id = str(details.get("matched_operation_id") or "").strip()
        openapi_match = details.get("openapi_match") is True
        is_static_asset = details.get("is_static_asset") is True
        status_code_raw = details.get("status_code")
        try:
            status_code = int(status_code_raw)
        except (TypeError, ValueError):
            status_code = 0

        pack.hypothesis = (
            "Runtime discovery observed an endpoint that is not represented in the OpenAPI inventory."
        )
        pack.method = method
        pack.endpoint = path

        pack.derived_signals.extend([
            "undocumented_endpoint_signal",
            f"method:{method or 'unknown'}",
            f"path:{path or 'unknown'}",
            f"status_code:{status_code if status_code else 'unknown'}",
            f"openapi_match:{str(openapi_match).lower()}",
            f"source:{source or 'unknown'}",
        ])
        if url_sanitized:
            pack.derived_signals.append(f"url_sanitized:{url_sanitized}")
        if matched_operation_id:
            pack.derived_signals.append(f"matched_operation_id:{matched_operation_id}")
        if is_static_asset:
            pack.derived_signals.append("is_static_asset:true")

        if not method:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="method_missing",
                description="undocumented_endpoint_signal evidence requires method.",
                required_for="undocumented_endpoint_signal",
            ))
        if not path:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="path_missing",
                description="undocumented_endpoint_signal evidence requires path.",
                required_for="undocumented_endpoint_signal",
            ))
        if status_code <= 0:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="runtime_status_missing",
                description="undocumented_endpoint_signal evidence requires runtime-observed status_code.",
                required_for="undocumented_endpoint_signal",
            ))
        if status_code == 404:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="runtime_status_not_found",
                description="undocumented_endpoint_signal cannot be judge-ready when runtime validation returned 404.",
                required_for="undocumented_endpoint_signal",
            ))
        if openapi_match:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="openapi_absence_not_proven",
                description="undocumented_endpoint_signal requires absence from the OpenAPI graph.",
                required_for="undocumented_endpoint_signal",
            ))
        if is_static_asset:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="static_asset_ignored",
                description="Static/service assets are not treated as undocumented API endpoints.",
                required_for="undocumented_endpoint_signal",
            ))

    def _fill_ssrf_candidate_signal(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None,
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        operation_id = str(details.get("operation_id") or obs.operation_id or "").strip()
        method = str(details.get("method") or "").strip().upper()
        path = str(details.get("path") or "").strip()
        field_name = str(details.get("field_name") or "").strip()
        field_path = str(details.get("field_path") or "").strip()
        schema_type = str(details.get("schema_type") or "string").strip() or "string"
        schema_format = str(details.get("schema_format") or "").strip()
        validation_mode = str(details.get("validation_mode") or "").strip()
        confidence = str(details.get("confidence") or "").strip()
        reason_codes = details.get("reason_codes") if isinstance(details.get("reason_codes"), list) else []

        pack.owasp_category = "API7_SERVER_SIDE_REQUEST_FORGERY"
        pack.vulnerability_class = "ssrf_candidate"
        if operation_id:
            pack.operation_id = operation_id
        if method:
            pack.method = method
        if path:
            pack.endpoint = path
        pack.hypothesis = (
            "OpenAPI schema analysis found URL-like request fields that may be SSRF-relevant and require safe follow-up validation."
        )
        pack.derived_signals.extend([
            "ssrf_candidate_signal",
            f"operation_id:{operation_id}",
            f"method:{method or 'unknown'}",
            f"path:{path or 'unknown'}",
            f"field_name:{field_name}",
            f"field_path:{field_path}",
            f"schema_type:{schema_type}",
            f"schema_format:{schema_format or 'unknown'}",
            f"validation_mode:{validation_mode or 'unknown'}",
        ])
        if confidence:
            pack.derived_signals.append(f"confidence:{confidence}")
        for code in reason_codes[:6]:
            text = str(code).strip()
            if text:
                pack.derived_signals.append(f"reason_code:{text}")
        pack.status = EvidencePackStatus.not_judge_ready
        pack.judge_ready = False
        pack.missing_evidence.append(MissingEvidenceItem(
            code="runtime_ssrf_proof_missing",
            description="ssrf_candidate is diagnostic-only in this phase and requires explicit safe runtime proof before Judge.",
            required_for="ssrf_candidate_signal",
        ))
        if not field_name:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="field_name_missing",
                description="ssrf_candidate_signal evidence requires field_name.",
                required_for="ssrf_candidate_signal",
            ))
        if not field_path:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="field_path_missing",
                description="ssrf_candidate_signal evidence requires field_path.",
                required_for="ssrf_candidate_signal",
            ))
        if not operation_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="ssrf_candidate_signal evidence requires operation_id.",
                required_for="ssrf_candidate_signal",
            ))
        if not validation_mode:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="validation_mode_missing",
                description="ssrf_candidate_signal evidence requires validation_mode.",
                required_for="ssrf_candidate_signal",
            ))

    @staticmethod
    def _schema_mismatch_signal_count(
        details: Mapping[str, object], signal_types: list[str]
    ) -> int:
        """Parse ``signal_count`` from observation details; never raise on garbage input."""
        raw = details.get("signal_count")
        fallback = len(signal_types)
        if raw is None:
            return fallback
        if isinstance(raw, str) and not raw.strip():
            return fallback
        if isinstance(raw, bool):
            return fallback
        if isinstance(raw, int):
            return raw
        if isinstance(raw, float):
            if raw != int(raw):
                return fallback
            return int(raw)
        try:
            return int(raw)  # type: ignore[arg-type]
        except (TypeError, ValueError):
            return fallback

    @staticmethod
    def _schema_mismatch_impact_summary_text(signal_types: list[str]) -> str:
        st = set(signal_types)
        p5 = "5xx" in st
        pu = "unexpected_2xx" in st
        ps = "schema_violation" in st
        parts: list[str] = []
        if p5:
            parts.append(
                "Negative schema testing triggered server error responses, "
                "indicating robustness/security impact."
            )
        if pu:
            parts.append(
                "Invalid or negative contract inputs were accepted successfully, "
                "indicating insufficient input validation."
            )
        if ps:
            if not p5 and not pu:
                parts.append(
                    "Response behavior deviated from the declared API schema contract "
                    "and requires impact judgment."
                )
            elif p5 or pu:
                parts.append("Declared API response schema contract was also violated.")
        return " ".join(parts).strip()

    @staticmethod
    def _schema_mismatch_signal_interpretations(signal_types: list[str]) -> list[str]:
        out: list[str] = []
        st = set(signal_types)
        if "5xx" in st:
            out.append("signal_interpretation:server_error_on_negative_contract_test")
        if "unexpected_2xx" in st:
            out.append("signal_interpretation:unexpected_success_on_invalid_input")
        if "schema_violation" in st:
            out.append("signal_interpretation:response_schema_contract_violation")
        return out

    @staticmethod
    def _strip_path_query(path_template: str) -> str:
        return (path_template or "").split("?", 1)[0]

    def _append_schema_mismatch_graph_signals(
        self, derived: list[str], campaign_id: str, op_id: str
    ) -> None:
        if not op_id:
            return
        op = self._lookup_operation(campaign_id, op_id)
        if op is None:
            return
        derived.append(f"method:{(op.method or '').upper()}")
        derived.append(
            f"path_template:{EvidencePackBuilder._strip_path_query(op.path_template or '')}"
        )
        derived.append(f"auth_required:{str(bool(op.auth_required)).lower()}")
        rt = (op.resource_type or "").strip()
        if rt:
            derived.append(f"resource_type:{rt}")
        for hint in (op.risk_hints or [])[:3]:
            h = str(hint).strip()
            if h:
                derived.append(f"risk_hint:{h[:120]}")
        for cand in (op.owasp_candidates or [])[:3]:
            c = str(cand).strip()
            if c:
                derived.append(f"owasp_candidate:{c[:120]}")

    def _fill_schema_mismatch(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details or {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        tool_name = str(details.get("tool_name") or "").strip()
        raw_signal_types = details.get("signal_types")
        signal_types = (
            [str(s).strip().lower() for s in raw_signal_types if str(s).strip()]
            if isinstance(raw_signal_types, list)
            else []
        )
        strong_signals = {"5xx", "schema_violation", "unexpected_2xx"}
        has_strong_signal = any(s in strong_signals for s in signal_types)
        strong_signal_count = sum(1 for s in signal_types if s in strong_signals)
        signal_count = EvidencePackBuilder._schema_mismatch_signal_count(
            details, signal_types
        )
        exit_code = details.get("exit_code")

        pack.owasp_category = "API8_SECURITY_MISCONFIGURATION"
        pack.vulnerability_class = "api_schema_contract_violation"
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op_id:
            pack.operation_id = op_id
            if op is not None:
                if not pack.method:
                    pack.method = (op.method or "").upper()
                if not pack.endpoint:
                    pack.endpoint = EvidencePackBuilder._strip_path_query(
                        op.path_template or ""
                    )
        pack.hypothesis = (
            "Schemathesis negative testing produced schema/contract mismatch "
            f"signals for operation {op_id or 'unknown_operation'}."
        )

        pack.derived_signals = [
            "schema_mismatch",
            f"tool_name:{tool_name or 'unknown'}",
            f"operation_id:{op_id or ''}",
            f"signal_count:{signal_count}",
        ]
        if exit_code is not None and str(exit_code) != "":
            pack.derived_signals.append(f"exit_code:{exit_code}")
        for sig in signal_types:
            pack.derived_signals.append(f"signal:{sig}")
        pack.derived_signals.append(f"strong_signal_count:{strong_signal_count}")
        pack.derived_signals.extend(
            EvidencePackBuilder._schema_mismatch_signal_interpretations(signal_types)
        )
        pack.derived_signals.append(
            "impact_summary:"
            + EvidencePackBuilder._schema_mismatch_impact_summary_text(signal_types)
        )
        self._append_schema_mismatch_graph_signals(
            pack.derived_signals, obs.campaign_id, op_id
        )

        if pack.endpoint:
            pack.endpoint = EvidencePackBuilder._strip_path_query(pack.endpoint)

        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=pack.method or "",
                path_template=pack.endpoint or "",
                url="",
                request_ref=None,
                description="Schemathesis negative testing produced schema/contract mismatch signals",
            )
        ]

        if plan is None or (plan.goal or "") != "validate_schema_mismatch_impact":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="verification_goal_mismatch",
                description=(
                    "Schema mismatch evidence requires VerificationPlan goal "
                    "'validate_schema_mismatch_impact'."
                ),
                required_for="schema_mismatch",
            ))
        if not op_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="operation_id is required for schema_mismatch evidence.",
                required_for="schema_mismatch",
            ))
        if tool_name != "schemathesis_negative_test":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description=(
                    "schema_mismatch evidence must come from tool_name "
                    "'schemathesis_negative_test'."
                ),
                required_for="schema_mismatch",
            ))
        if not signal_types:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="schemathesis_signal_missing",
                description="signal_types must be a non-empty list for schema_mismatch evidence.",
                required_for="schema_mismatch",
            ))
        if signal_types and not has_strong_signal:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="impact_classification_missing",
                description=(
                    "signal_types must include at least one strong signal "
                    "(5xx, schema_violation, unexpected_2xx)."
                ),
                required_for="schema_mismatch",
            ))

    def _fill_injection_signal(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        tool_name = str(details.get("tool_name") or "").strip()

        raw_signal_types = details.get("signal_types")
        signal_types = (
            [str(s).strip().lower() for s in raw_signal_types if str(s).strip()]
            if isinstance(raw_signal_types, list)
            else []
        )
        has_strong = any(s in _INJECTION_STRONG_SIGNALS for s in signal_types)

        pack.owasp_category = "API8_SECURITY_MISCONFIGURATION"
        pack.vulnerability_class = "potential_injection"

        pname = str(details.get("parameter_name") or "").strip()
        ploc = str(details.get("parameter_location") or "").strip()
        pfam = str(details.get("payload_family") or "").strip()
        plab = str(details.get("payload_label") or "").strip()
        bline = details.get("baseline_status")
        aline = details.get("attack_status")
        rsp_delta = str(details.get("response_delta_class") or "").strip()
        marker_raw = details.get("marker_reflected")
        err_cls = str(details.get("error_pattern_class") or "").strip()

        op_disp = op_id or "unknown"
        p_disp = pname or "unknown"
        loc_disp = ploc or "unknown"
        pack.hypothesis = (
            "Injection probe reported strong signals for operation "
            f"{op_disp} parameter {p_disp} ({loc_disp})."
        )

        if op_id:
            pack.operation_id = op_id
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op is not None:
            if not pack.method:
                pack.method = (op.method or "").upper()
            if not pack.endpoint:
                pack.endpoint = EvidencePackBuilder._strip_path_query(op.path_template or "")

        def _fmt_status(v: object) -> str:
            if v is None:
                return ""
            if isinstance(v, bool):
                return str(v).lower()
            if isinstance(v, (int, float)):
                return str(int(v))
            return str(v).strip()

        derived: list[str] = [
            "injection_signal",
            f"tool_name:{tool_name}",
            f"operation_id:{op_id}",
        ]
        for sig in signal_types:
            derived.append(f"signal:{sig}")
        for sig in signal_types:
            if sig in _INJECTION_STRONG_SIGNALS:
                derived.append(f"strong_signal:{sig}")
        derived.extend([
            f"parameter_name:{pname}",
            f"parameter_location:{ploc}",
            f"payload_family:{pfam}",
            f"payload_label:{plab}",
            f"baseline_status:{_fmt_status(bline)}",
            f"attack_status:{_fmt_status(aline)}",
            f"response_delta_class:{rsp_delta}",
            f"marker_reflected:{str(bool(marker_raw)).lower()}",
            f"error_pattern_class:{err_cls}",
        ])
        pack.derived_signals = derived

        method = (pack.method or "GET").upper()
        path_t = pack.endpoint or ""
        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=method,
                path_template=path_t,
                url="",
                request_ref=None,
                description="Injection probe compared baseline and labeled attack metadata",
            ),
        ]

        if plan is None or (plan.goal or "") != "validate_injection_impact":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="verification_goal_mismatch",
                description=(
                    "Injection evidence requires VerificationPlan goal "
                    "'validate_injection_impact'."
                ),
                required_for="potential_injection",
            ))
        if not op_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="operation_id is required for injection evidence.",
                required_for="potential_injection",
            ))
        if tool_name != "injection_test":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description=(
                    "injection_signal evidence must come from tool_name 'injection_test'."
                ),
                required_for="potential_injection",
            ))
        if not signal_types:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="injection_signal_missing",
                description="signal_types must be a non-empty list for injection evidence.",
                required_for="potential_injection",
            ))
        if not (pname and ploc and pfam and plab):
            pack.missing_evidence.append(MissingEvidenceItem(
                code="injection_parameter_context_missing",
                description=(
                    "parameter_name, parameter_location, payload_family, and payload_label "
                    "are required."
                ),
                required_for="potential_injection",
            ))
        if bline is None or aline is None:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="baseline_attack_delta_missing",
                description="baseline_status and attack_status are required.",
                required_for="potential_injection",
            ))
        if signal_types and not has_strong:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="impact_classification_missing",
                description=(
                    "signal_types must include at least one strong injection signal."
                ),
                required_for="potential_injection",
            ))

    def _fill_mass_assignment_signal(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        tool_name = str(details.get("tool_name") or "").strip()
        mutation_policy = str(details.get("mutation_policy") or "").strip().lower()
        diagnostic_only = details.get("diagnostic_only") is True
        runtime_effect_proven = details.get("runtime_effect_proven") is True
        seed_request_id = str(details.get("seed_request_id") or "").strip()
        seed_present = details.get("seed_request_id_present") is True

        fields_selected_raw = details.get("fields_selected")
        fields_selected = (
            [str(x).strip() for x in fields_selected_raw if str(x).strip()]
            if isinstance(fields_selected_raw, list)
            else []
        )
        fields_considered_count = int(details.get("fields_considered_count") or 0)
        fields_skipped_count = int(details.get("fields_skipped_count") or 0)

        pack.owasp_category = "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
        pack.vulnerability_class = "potential_mass_assignment"
        if op_id:
            pack.operation_id = op_id
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op is not None:
            if not pack.method:
                pack.method = (op.method or "").upper()
            if not pack.endpoint:
                pack.endpoint = EvidencePackBuilder._strip_path_query(op.path_template or "")
        pack.hypothesis = (
            "Diagnostic signal suggests sensitive writable fields may be mass-assignable; "
            "runtime effect is not proven."
        )
        pack.derived_signals = [
            "mass_assignment_signal",
            f"tool_name:{tool_name or 'property_mutation_test'}",
            f"operation_id:{op_id}",
            f"mutation_policy:{mutation_policy or 'diagnostic_only'}",
            f"diagnostic_only:{str(bool(diagnostic_only)).lower()}",
            f"runtime_effect_proven:{str(bool(runtime_effect_proven)).lower()}",
            f"fields_selected_count:{len(fields_selected)}",
            f"fields_considered_count:{max(0, fields_considered_count)}",
            f"fields_skipped_count:{max(0, fields_skipped_count)}",
            f"proof_scope:{str(details.get('proof_scope') or 'diagnostic_signal_only')}",
        ]
        for field_name in fields_selected[:20]:
            pack.derived_signals.append(f"field_selected:{field_name}")

        if seed_present and seed_request_id:
            seed_ref = self._resolve_request_ref(obs.campaign_id, seed_request_id)
            if seed_ref is not None:
                pack.attack = EvidenceAttack(
                    role=seed_ref.role,
                    request_ref=seed_ref,
                    description="Seed request reference for diagnostic mass-assignment signal.",
                )

        if not op_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="operation_id is required for mass_assignment_signal evidence.",
                required_for="potential_mass_assignment",
            ))
        if tool_name and tool_name != "property_mutation_test":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description="mass_assignment_signal must come from property_mutation_test.",
                required_for="potential_mass_assignment",
            ))
        if mutation_policy != "diagnostic_only" or not diagnostic_only:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="diagnostic_mode_required",
                description="mass_assignment_signal evidence in Phase 18C must stay diagnostic_only.",
                required_for="potential_mass_assignment",
            ))
        if not fields_selected:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="field_selection_context_missing",
                description="fields_selected must contain at least one candidate field name.",
                required_for="potential_mass_assignment",
            ))
        if not (seed_present and seed_request_id):
            pack.missing_evidence.append(MissingEvidenceItem(
                code="seed_reference_missing",
                description="seed_request_id context is required for mass_assignment diagnostic evidence.",
                required_for="potential_mass_assignment",
            ))

        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=pack.method or "",
                path_template=pack.endpoint or "",
                url="",
                request_ref=pack.attack.request_ref if pack.attack is not None else None,
                description="Property mutation diagnostic signal context captured",
            ),
        ]

    def _fill_data_exposure_signal(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        path = str(details.get("path") or "").strip()
        method = str(details.get("method") or "GET").strip().upper() or "GET"
        status_code = int(details.get("status_code") or 0)
        sens_count = int(details.get("sensitive_field_count") or 0)
        tool_name = str(details.get("tool_name") or "").strip()

        pack.owasp_category = "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
        pack.vulnerability_class = "sensitive_property_exposure"
        if op_id:
            pack.operation_id = op_id
        if path:
            pack.endpoint = EvidencePackBuilder._strip_path_query(path)
        if method:
            pack.method = method
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op is not None and not pack.endpoint:
            pack.endpoint = EvidencePackBuilder._strip_path_query(op.path_template or "")
        if op is not None and not pack.method:
            pack.method = (op.method or "GET").upper()

        pack.hypothesis = (
            "JSON response exposes field names that match sensitive categories; "
            "review authorization and response minimization (field names only in evidence)."
        )
        cats_raw = details.get("sensitive_categories")
        cats = (
            [str(x).strip() for x in cats_raw if str(x).strip()]
            if isinstance(cats_raw, list)
            else []
        )
        sens_fields = details.get("sensitive_fields")
        rows: list[dict[str, Any]] = []
        if isinstance(sens_fields, list):
            for item in sens_fields:
                if isinstance(item, dict):
                    rows.append(item)
        derived: list[str] = [
            "data_exposure_signal",
            "response_field_inventory:true",
            f"sensitive_field_count:{max(0, sens_count)}",
            f"status_code:{status_code}",
            f"operation_id:{op_id}",
            f"method:{method}",
        ]
        for c in cats[:20]:
            derived.append(f"sensitive_category:{c}")
        for row in rows[:40]:
            fn = str(row.get("field_name") or "").strip()
            if fn:
                derived.append(f"sensitive_field_name:{fn}")
        pack.derived_signals = derived

        if tool_name and tool_name != "data_exposure_validator":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description="data_exposure_signal must come from data_exposure_validator.",
                required_for="sensitive_property_exposure",
            ))
        if sens_count <= 0:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="sensitive_field_count_missing",
                description="sensitive_field_count must be > 0 for judge-ready exposure evidence.",
                required_for="sensitive_property_exposure",
            ))
        if not op_id:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="operation_context_missing",
                description="operation_id is required for data_exposure_signal evidence.",
                required_for="sensitive_property_exposure",
            ))
        if not path:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="endpoint_context_missing",
                description="path is required for data_exposure_signal evidence.",
                required_for="sensitive_property_exposure",
            ))

        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=pack.method or "",
                path_template=pack.endpoint or "",
                url="",
                request_ref=None,
                description="Safe GET response field inventory (names only)",
            ),
        ]

    def _fill_validated_cors_issue_cors(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        tool_name = str(details.get("tool_name") or "").strip()
        validation_mode = str(details.get("validation_mode") or "").strip()
        request_url = str(details.get("request_url") or "").strip()
        path_template = str(details.get("path_template") or "").strip()
        issue_codes_raw = details.get("issue_codes")
        issue_codes = (
            [str(x).strip() for x in issue_codes_raw if str(x).strip()]
            if isinstance(issue_codes_raw, list)
            else []
        )
        strong_codes = {
            "cors_wildcard_with_credentials",
            "cors_origin_reflection_with_credentials",
        }
        has_strong = any(code in strong_codes for code in issue_codes)
        acao_state = str(details.get("acao_state") or "").strip()
        acac_present = details.get("acac_present") is True
        vary_origin_present = details.get("vary_origin_present") is True
        origin_reflection_detected = details.get("origin_reflection_detected") is True
        origin_probe_label = str(details.get("origin_probe_label") or "").strip()

        pack.owasp_category = "API8_SECURITY_MISCONFIGURATION"
        pack.vulnerability_class = "cors_misconfiguration"
        if op_id:
            pack.operation_id = op_id
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op is not None:
            if not pack.method:
                pack.method = (op.method or "").upper()
            if not pack.endpoint:
                pack.endpoint = EvidencePackBuilder._strip_path_query(op.path_template or "")
        if not pack.endpoint:
            pack.endpoint = EvidencePackBuilder._strip_path_query(path_template or "")
        pack.hypothesis = (
            "Validated CORS policy appears overly permissive for a cross-origin probe."
        )

        derived = [
            "validated_cors_issue",
            f"tool_name:{tool_name or 'cors_validator'}",
            f"acao_state:{acao_state}",
            f"acac_present:{str(bool(acac_present)).lower()}",
            f"origin_reflection_detected:{str(bool(origin_reflection_detected)).lower()}",
            f"vary_origin_present:{str(bool(vary_origin_present)).lower()}",
            f"validation_mode:{validation_mode or 'single_replay_cors_check'}",
            f"origin_probe_label:{origin_probe_label or 'evil_example_invalid'}",
        ]
        for code in issue_codes[:10]:
            derived.append(f"issue_code:{code}")
        pack.derived_signals = derived

        location = request_url or path_template or pack.endpoint
        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=(pack.method or "GET").upper(),
                path_template=pack.endpoint or "",
                url=location,
                request_ref=None,
                description="Validated CORS policy replay against fixed cross-origin probe",
            ),
        ]

        if not has_strong:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="strong_cors_issue_missing",
                description="validated_cors_issue requires a strong CORS issue code in MVP.",
                required_for="cors_misconfiguration",
            ))
        if not validation_mode:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="validation_mode_missing",
                description="validated_cors_issue evidence requires validation_mode.",
                required_for="cors_misconfiguration",
            ))
        if not (op_id or request_url or path_template):
            pack.missing_evidence.append(MissingEvidenceItem(
                code="target_location_missing",
                description="validated_cors_issue evidence requires operation_id or target location.",
                required_for="cors_misconfiguration",
            ))
        if not acao_state:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="cors_policy_state_missing",
                description="validated_cors_issue evidence requires acao_state.",
                required_for="cors_misconfiguration",
            ))
        if tool_name and tool_name != "cors_validator":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description="validated_cors_issue must come from cors_validator.",
                required_for="cors_misconfiguration",
            ))

    def _fill_validated_cookie_flag_issue(
        self, pack: EvidencePack, obs: Observation, plan: VerificationPlan | None
    ) -> None:
        details = obs.details if isinstance(obs.details, dict) else {}
        op_id = str(obs.operation_id or details.get("operation_id") or "").strip()
        tool_name = str(details.get("tool_name") or "").strip()
        validation_mode = str(details.get("validation_mode") or "").strip()
        request_url = str(details.get("request_url") or "").strip()
        path_template = str(details.get("path_template") or "").strip()
        cookie_name_hash = str(details.get("cookie_name_hash") or "").strip()
        issue_codes_raw = details.get("issue_codes")
        issue_codes = (
            [str(x).strip() for x in issue_codes_raw if str(x).strip()]
            if isinstance(issue_codes_raw, list)
            else []
        )
        strong_codes = {
            "missing_httponly",
            "missing_secure",
            "samesite_none_without_secure",
        }
        has_strong = any(code in strong_codes for code in issue_codes)
        has_httponly = details.get("has_httponly") is True
        has_secure = details.get("has_secure") is True
        is_https = details.get("is_https") is True
        samesite_state = str(details.get("samesite_state") or "missing").strip().lower() or "missing"

        pack.owasp_category = "API8_SECURITY_MISCONFIGURATION"
        pack.vulnerability_class = "cookie_flag_misconfiguration"
        if op_id:
            pack.operation_id = op_id
        op = self._lookup_operation(obs.campaign_id, op_id) if op_id else None
        if op is not None:
            if not pack.method:
                pack.method = (op.method or "").upper()
            if not pack.endpoint:
                pack.endpoint = EvidencePackBuilder._strip_path_query(op.path_template or "")
        if not pack.endpoint:
            pack.endpoint = EvidencePackBuilder._strip_path_query(path_template or "")
        pack.hypothesis = "Validated cookie flag misconfiguration observed during safe replay."

        derived = [
            "validated_cookie_flag_issue",
            f"tool_name:{tool_name or 'cookie_flag_validator'}",
            f"cookie_name_hash:{cookie_name_hash}",
            f"has_httponly:{str(bool(has_httponly)).lower()}",
            f"has_secure:{str(bool(has_secure)).lower()}",
            f"samesite_state:{samesite_state}",
            f"is_https:{str(bool(is_https)).lower()}",
            f"validation_mode:{validation_mode or 'baseline_cookie_flag_check'}",
        ]
        for code in issue_codes[:10]:
            derived.append(f"issue_code:{code}")
        pack.derived_signals = derived

        location = request_url or path_template or pack.endpoint
        pack.replay_steps = [
            EvidenceReplayStep(
                order=1,
                role="",
                method=(pack.method or "GET").upper(),
                path_template=pack.endpoint or "",
                url=location,
                request_ref=None,
                description="Validated cookie flag replay against safe baseline endpoint",
            ),
        ]

        if not has_strong:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="strong_cookie_issue_missing",
                description="validated_cookie_flag_issue requires a strong cookie issue code in MVP.",
                required_for="cookie_flag_misconfiguration",
            ))
        if not validation_mode:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="validation_mode_missing",
                description="validated_cookie_flag_issue evidence requires validation_mode.",
                required_for="cookie_flag_misconfiguration",
            ))
        if not (op_id or request_url or path_template):
            pack.missing_evidence.append(MissingEvidenceItem(
                code="target_location_missing",
                description="validated_cookie_flag_issue evidence requires operation_id or target location.",
                required_for="cookie_flag_misconfiguration",
            ))
        if not cookie_name_hash:
            pack.missing_evidence.append(MissingEvidenceItem(
                code="cookie_name_hash_missing",
                description="validated_cookie_flag_issue evidence requires cookie_name_hash.",
                required_for="cookie_flag_misconfiguration",
            ))
        if tool_name and tool_name != "cookie_flag_validator":
            pack.missing_evidence.append(MissingEvidenceItem(
                code="tool_name_mismatch",
                description="validated_cookie_flag_issue must come from cookie_flag_validator.",
                required_for="cookie_flag_misconfiguration",
            ))

    def _fill_not_judge_ready(
        self, pack: EvidencePack, obs: Observation, code: str | None = None
    ) -> None:
        pack.status = EvidencePackStatus.not_judge_ready
        pack.judge_ready = False
        reason_code = code or f"{obs.type.value}_not_judge_ready"
        pack.missing_evidence.append(MissingEvidenceItem(
            code=reason_code,
            description=(
                f"Observation type '{obs.type.value}' is store-only and never "
                "becomes judge-ready by itself."
            ),
            required_for=obs.type.value,
        ))
        pack.hypothesis = pack.hypothesis or (
            f"{obs.type.value} is informational; no confirmed-finding hypothesis."
        )

    # ------------------------------------------------------------------
    # Cross-role helpers
    # ------------------------------------------------------------------
    def _build_cross_role_hypothesis(
        self,
        attacker_role: str,
        owner_role: str,
        object_id: str,
        operation_id: str,
    ) -> str:
        attacker = attacker_role or "attacker"
        owner = owner_role or "owner"
        if object_id:
            obj = object_id
        else:
            obj = "an object"
        op = f" via operation '{operation_id}'" if operation_id else ""
        return (
            f"Role '{attacker}' may be able to access {obj} owned by "
            f"role '{owner}'{op} — potential BOLA."
        )

    def _find_cross_role_refs(
        self,
        campaign_id: str,
        operation_id: str,
        owner_role: str,
        attacker_role: str,
        object_id: str,
    ) -> tuple[EvidenceHttpExchangeRef | None, EvidenceHttpExchangeRef | None]:
        try:
            candidates = self._corpus.find_cross_role_candidates(campaign_id)
        except Exception:  # pragma: no cover - defensive
            candidates = []

        chosen_a: str = ""
        chosen_b: str = ""
        for cand in candidates:
            cand_key = str(cand.get("operation_key", "") or "")
            if operation_id and cand_key != operation_id:
                continue
            if object_id and object_id not in cand.get("overlapping_ids", []):
                continue
            role_a = cand.get("role_a", "")
            role_b = cand.get("role_b", "")
            if owner_role and attacker_role:
                if role_a == owner_role and role_b == attacker_role:
                    chosen_a = cand.get("sample_request_a", "")
                    chosen_b = cand.get("sample_request_b", "")
                    break
                if role_b == owner_role and role_a == attacker_role:
                    chosen_a = cand.get("sample_request_b", "")
                    chosen_b = cand.get("sample_request_a", "")
                    break
            else:
                chosen_a = cand.get("sample_request_a", "")
                chosen_b = cand.get("sample_request_b", "")
                break

        baseline_ref = self._resolve_request_ref(campaign_id, chosen_a) if chosen_a else None
        attack_ref = self._resolve_request_ref(campaign_id, chosen_b) if chosen_b else None

        if baseline_ref is None and owner_role and operation_id:
            for item in self._corpus.find_successful_by_operation(campaign_id, operation_id):
                if item.auth_profile == owner_role:
                    baseline_ref = self._item_to_ref(item)
                    break
        if attack_ref is None and attacker_role and operation_id:
            for item in self._corpus.list_by_campaign(campaign_id):
                if (
                    item.operation_id == operation_id
                    and item.auth_profile == attacker_role
                ):
                    attack_ref = self._item_to_ref(item)
                    break

        return baseline_ref, attack_ref

    def _build_ownership_proof(
        self,
        campaign_id: str,
        object_id: str,
        owner_role: str,
        attacker_role: str,
        operation_id: str,
        observation_details: Mapping[str, object] | None = None,
    ) -> EvidenceOwnershipProof | None:
        if not (object_id and owner_role and attacker_role):
            return None

        owner_collection_ref: EvidenceHttpExchangeRef | None = None
        attacker_collection_ref: EvidenceHttpExchangeRef | None = None

        details = observation_details or {}
        owner_collection_request_id = str(details.get("owner_collection_request_id", "") or "")
        attacker_collection_request_id = str(details.get("attacker_collection_request_id", "") or "")

        if owner_collection_request_id:
            owner_collection_ref = self._resolve_request_ref(campaign_id, owner_collection_request_id)
            if not self._ref_matches_collection_proof(
                owner_collection_ref, owner_role, object_id, must_contain=True
            ):
                owner_collection_ref = None

        if attacker_collection_request_id:
            attacker_collection_ref = self._resolve_request_ref(
                campaign_id, attacker_collection_request_id
            )
            if not self._ref_matches_collection_proof(
                attacker_collection_ref, attacker_role, object_id, must_contain=False
            ):
                attacker_collection_ref = None

        for item in self._corpus.list_by_campaign(campaign_id):
            if item.classification != StatusClassification.successful_seed:
                continue
            if not item.auth_profile:
                continue
            # Ownership proof is a *separate* collection observation,
            # not a re-statement of the contested cross-role pair.
            if operation_id and item.operation_id == operation_id:
                continue
            ids_in_item = self._all_ids_in_item(item)

            if (
                owner_collection_ref is None
                and item.auth_profile == owner_role
                and object_id in ids_in_item
            ):
                owner_collection_ref = self._item_to_ref(item)
            if (
                attacker_collection_ref is None
                and item.auth_profile == attacker_role
                and object_id not in ids_in_item
            ):
                attacker_collection_ref = self._item_to_ref(item)

        if owner_collection_ref is None or attacker_collection_ref is None:
            return None

        return EvidenceOwnershipProof(
            object_id=object_id,
            owner_role=owner_role,
            owner_collection_request_ref=owner_collection_ref,
            attacker_collection_request_ref=attacker_collection_ref,
            proof=(
                f"Object '{object_id}' is observed in '{owner_role}' collection "
                f"and absent from '{attacker_role}' collection."
            ),
        )

    @staticmethod
    def _all_ids_in_item(item: RequestCorpusItem) -> set[str]:
        ids: set[str] = set()
        for vals in item.extracted_ids.values():
            for val in vals:
                ids.add(str(val))
        body = item.response_body_redacted
        if body is not None:
            for val in EvidencePackBuilder._all_scalar_values_recursive(body):
                ids.add(val)
        return ids

    @staticmethod
    def _all_scalar_values_recursive(data: object) -> set[str]:
        out: set[str] = set()
        if isinstance(data, Mapping):
            for value in data.values():
                out.update(EvidencePackBuilder._all_scalar_values_recursive(value))
            return out
        if isinstance(data, list):
            for value in data:
                out.update(EvidencePackBuilder._all_scalar_values_recursive(value))
            return out
        if isinstance(data, (str, int, float)) and not isinstance(data, bool):
            str_val = str(data)
            if str_val:
                out.add(str_val)
        return out

    def _ref_matches_collection_proof(
        self,
        ref: EvidenceHttpExchangeRef | None,
        expected_role: str,
        object_id: str,
        *,
        must_contain: bool,
    ) -> bool:
        if ref is None:
            return False
        if expected_role and ref.role != expected_role:
            return False
        if ref.classification != StatusClassification.successful_seed.value:
            return False
        item = self._corpus.get_request(ref.request_id)
        if item is None:
            return False
        ids_in_item = self._all_ids_in_item(item)
        contains = object_id in ids_in_item
        return contains if must_contain else not contains

    def _find_negative_control(
        self,
        campaign_id: str,
        attacker_role: str,
        operation_id: str,
        contested_object_id: str = "",
    ) -> EvidenceControl | None:
        if not (attacker_role and operation_id):
            return None
        for item in self._corpus.list_by_campaign(campaign_id):
            if item.operation_id != operation_id:
                continue
            if item.auth_profile != attacker_role:
                continue
            if item.classification != StatusClassification.successful_seed:
                continue
            if contested_object_id:
                ids_in_item = self._all_ids_in_item(item)
                if contested_object_id in ids_in_item:
                    continue
            return EvidenceControl(
                name="attacker_self_access",
                role=attacker_role,
                request_ref=self._item_to_ref(item),
                description=(
                    f"Attacker '{attacker_role}' is allowed to access their own "
                    "resource of the same type."
                ),
            )
        return None

    @staticmethod
    def _cross_role_derived_signals(
        obs: Observation,
        baseline_ref: EvidenceHttpExchangeRef | None,
        attack_ref: EvidenceHttpExchangeRef | None,
        ownership_proof: EvidenceOwnershipProof | None,
    ) -> list[str]:
        signals: list[str] = []
        if baseline_ref and attack_ref:
            signals.append("cross_role_pair_present")
        if ownership_proof is not None:
            signals.append("ownership_proof_present")
        if obs.confidence and obs.confidence >= 0.8:
            signals.append("high_signal_confidence")
        return signals

    # ------------------------------------------------------------------
    # 500 helpers
    # ------------------------------------------------------------------
    def _find_repeated_500(
        self, campaign_id: str, operation_id: str, original_request_id: str
    ) -> EvidenceHttpExchangeRef | None:
        if not operation_id:
            return None
        for item in self._corpus.list_by_campaign(campaign_id):
            if item.operation_id != operation_id:
                continue
            if not (500 <= item.status_code < 600):
                continue
            if item.request_id == original_request_id:
                continue
            return self._item_to_ref(item)
        return None

    # ------------------------------------------------------------------
    # Diff / replay helpers
    # ------------------------------------------------------------------
    def _compute_diff(
        self,
        baseline: EvidenceHttpExchangeRef,
        attack: EvidenceHttpExchangeRef,
    ) -> EvidenceDiff:
        diff = EvidenceDiff(
            status_code_baseline=baseline.status_code,
            status_code_attack=attack.status_code,
        )
        baseline_item = memory_store.get_corpus_item(baseline.request_id)
        attack_item = memory_store.get_corpus_item(attack.request_id)

        baseline_fields = self._response_top_level_fields(baseline_item)
        attack_fields = self._response_top_level_fields(attack_item)

        diff.fields_present_in_attack = sorted(
            attack_fields.intersection(baseline_fields)
        )
        diff.fields_missing_in_attack = sorted(
            baseline_fields.difference(attack_fields)
        )
        if baseline.status_code != attack.status_code:
            diff.notes.append("status_code_changed")
        return diff

    @staticmethod
    def _response_top_level_fields(item: dict | None) -> set[str]:
        if not item:
            return set()
        body = item.get("response_body_redacted")
        if isinstance(body, Mapping):
            return {str(k) for k in body.keys()}
        return set()

    def _build_replay_steps(
        self, refs: list[tuple[str, EvidenceHttpExchangeRef | None]]
    ) -> list[EvidenceReplayStep]:
        out: list[EvidenceReplayStep] = []
        order = 1
        for label, ref in refs:
            if ref is None:
                continue
            out.append(EvidenceReplayStep(
                order=order,
                role=ref.role,
                method=ref.method,
                path_template=ref.path_template,
                url=ref.url,
                request_ref=ref,
                description=label,
            ))
            order += 1
        return out

    # ------------------------------------------------------------------
    # Corpus / artifact helpers
    # ------------------------------------------------------------------
    def _resolve_request_ref(
        self, campaign_id: str, request_id: str
    ) -> EvidenceHttpExchangeRef | None:
        if not request_id:
            return None
        item = self._corpus.get_request(request_id)
        if item is None:
            return None
        if item.campaign_id != campaign_id:
            return None
        return self._item_to_ref(item)

    @staticmethod
    def _item_to_ref(item: RequestCorpusItem) -> EvidenceHttpExchangeRef:
        return EvidenceHttpExchangeRef(
            request_id=item.request_id,
            role=item.auth_profile,
            method=item.method,
            path_template=item.path_template,
            url=item.url,
            status_code=item.status_code,
            classification=item.classification.value
            if hasattr(item.classification, "value")
            else str(item.classification),
            operation_id=item.operation_id,
        )

    def _collect_artifact_refs(
        self,
        campaign_id: str,
        tool_run_id: str,
        observation_artifact_refs: list[str],
    ) -> list[EvidenceArtifactRef]:
        refs: list[EvidenceArtifactRef] = []
        seen: set[str] = set()
        if tool_run_id:
            for raw in memory_store.list_artifacts_by_run(tool_run_id):
                artifact_campaign = str(raw.get("campaign_id", "") or "")
                if artifact_campaign and artifact_campaign != campaign_id:
                    continue
                aid = str(raw.get("artifact_id", "") or "")
                if not aid or aid in seen:
                    continue
                refs.append(EvidenceArtifactRef(
                    artifact_id=aid,
                    artifact_type=str(raw.get("artifact_type", "") or ""),
                    path=str(raw.get("path", "") or ""),
                    size_bytes=int(raw.get("size_bytes", 0) or 0),
                ))
                seen.add(aid)
        for aid in observation_artifact_refs or []:
            if not aid or aid in seen:
                continue
            raw = memory_store.get_artifact(aid)
            if raw is None:
                refs.append(EvidenceArtifactRef(artifact_id=aid))
            else:
                artifact_campaign = str(raw.get("campaign_id", "") or "")
                if artifact_campaign and artifact_campaign != campaign_id:
                    continue
                refs.append(EvidenceArtifactRef(
                    artifact_id=aid,
                    artifact_type=str(raw.get("artifact_type", "") or ""),
                    path=str(raw.get("path", "") or ""),
                    size_bytes=int(raw.get("size_bytes", 0) or 0),
                ))
            seen.add(aid)
        return refs

    def _lookup_operation(
        self, campaign_id: str, operation_id: str
    ) -> Operation | None:
        if not operation_id:
            return None
        try:
            graph = self._graph.get_graph(campaign_id)
        except Exception:  # pragma: no cover - defensive
            return None
        if graph is None:
            return None
        for op in graph.operations:
            if op.operation_id == operation_id:
                return op
        return None

    # ------------------------------------------------------------------
    # Idempotency / persistence
    # ------------------------------------------------------------------
    def _find_active_plan(self, obs: Observation) -> VerificationPlan | None:
        plans = memory_store.list_verification_plans_by_campaign(obs.campaign_id)
        for raw in plans:
            try:
                plan = VerificationPlan.model_validate(raw)
            except Exception:  # pragma: no cover - defensive
                continue
            if plan.parent_observation_id != obs.observation_id:
                continue
            if plan.status not in {
                VerificationPlanStatus.pending,
                VerificationPlanStatus.in_progress,
            }:
                continue
            return plan
        return None

    def _validate_tool_run_campaign_boundary(
        self, obs: Observation
    ) -> EvidencePackBuildError | None:
        if not obs.tool_run_id:
            return None
        run_data = memory_store.get_tool_run(obs.tool_run_id)
        if run_data is None:
            return None
        run_campaign = str(run_data.get("campaign_id", "") or "")
        if run_campaign and run_campaign != obs.campaign_id:
            return EvidencePackBuildError(
                "tool_run_campaign_mismatch",
                (
                    f"ToolRun '{obs.tool_run_id}' belongs to campaign "
                    f"'{run_campaign}', expected '{obs.campaign_id}'."
                ),
            )
        return None

    def _find_existing(
        self, observation_id: str, verification_plan_id: str
    ) -> EvidencePack | None:
        existing_packs = memory_store.list_evidence_packs_by_observation(observation_id)
        for raw in existing_packs:
            try:
                pack = EvidencePack.model_validate(raw)
            except Exception:  # pragma: no cover - defensive
                continue
            if pack.verification_plan_id == verification_plan_id:
                return pack
        return None

    def _persist(
        self,
        pack: EvidencePack,
        obs: Observation,
        plan: VerificationPlan | None,
    ) -> None:
        memory_store.store_evidence_pack(
            evidence_id=pack.evidence_id,
            campaign_id=pack.campaign_id,
            observation_id=obs.observation_id,
            verification_plan_id=plan.verification_plan_id if plan else "",
            data=pack.model_dump(mode="json"),
        )
