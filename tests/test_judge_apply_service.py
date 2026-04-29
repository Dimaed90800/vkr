"""Phase 7 - JudgeApply service tests."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.evidence_pack import (
    EvidenceAttack,
    EvidenceBaseline,
    EvidenceHttpExchangeRef,
    EvidenceOwnershipProof,
    EvidencePack,
    EvidencePackStatus,
    MissingEvidenceItem,
)
from backend.models.judge import (
    FindingCandidatePayload,
    JudgeApplyRequest,
    JudgeVerdictKind,
    JudgeVerdictPayload,
)
from backend.models.observation import VerificationPlan, VerificationPlanStatus
from backend.services.auto_judge_service import apply_judge_for_ready_evidence_in_campaign
from backend.services.judge_apply_service import JudgeApplyError, JudgeApplyService
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "corpus_items", "corpus_by_campaign", "resource_instances", "resources_by_campaign",
        "graphs_by_campaign", "commands", "commands_by_campaign", "command_fingerprints",
        "tool_runs", "tool_runs_by_campaign", "tool_results", "artifacts", "artifacts_by_run",
        "observations", "observations_by_campaign", "observations_by_tool_run",
        "verification_plans", "verification_plans_by_campaign",
        "evidence_packs", "evidence_packs_by_campaign", "evidence_packs_by_observation",
        "evidence_packs_by_verification_plan", "judge_decisions",
        "judge_decisions_by_campaign", "judge_decisions_by_evidence",
        "confirmed_findings", "confirmed_findings_by_campaign", "findings_by_fingerprint",
        "evidence_pack_apply_meta", "observation_apply_meta",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _create_campaign(campaign_id: str = "cmp_judge1") -> None:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))


def _pack(
    *,
    evidence_id: str = "evp_ready",
    campaign_id: str = "cmp_judge1",
    status: EvidencePackStatus = EvidencePackStatus.ready_for_judge,
    judge_ready: bool = True,
    missing: list[str] | None = None,
    owasp: str = "API1_BOLA",
    vulnerability_class: str = "cross_role_access_signal",
    observation_id: str = "obs_judge1",
    verification_plan_id: str = "vplan_judge1",
    task_id: str = "task_judge1",
    operation_id: str = "op_GET_/api/users/{id}",
    endpoint: str = "/api/users/{id}",
    method: str = "GET",
    object_id: str = "",
    baseline_role: str = "",
    attack_role: str = "attacker",
    owner_role: str = "",
    derived_signals: list[str] | None = None,
) -> EvidencePack:
    pack = EvidencePack(
        evidence_id=evidence_id,
        campaign_id=campaign_id,
        task_id=task_id,
        observation_id=observation_id,
        verification_plan_id=verification_plan_id,
        tool_run_ids=["toolrun_judge1"],
        owasp_category=owasp,
        vulnerability_class=vulnerability_class,
        operation_id=operation_id,
        endpoint=endpoint,
        method=method,
        hypothesis="Potential issue",
        baseline=EvidenceBaseline(
            role=baseline_role,
            request_ref=EvidenceHttpExchangeRef(
                request_id="req_baseline",
                role=baseline_role,
                method=method,
                path_template=endpoint,
                url=f"http://testapp.local{endpoint}",
                status_code=200,
            ),
        ) if baseline_role else None,
        attack=EvidenceAttack(
            role=attack_role,
            request_ref=EvidenceHttpExchangeRef(
                request_id="req_attack",
                role=attack_role,
                method=method,
                path_template=endpoint,
                url=f"http://testapp.local{endpoint}",
                status_code=200,
            ),
        ),
        ownership_proof=EvidenceOwnershipProof(
            object_id=object_id,
            owner_role=owner_role,
        ) if object_id or owner_role else None,
        missing_evidence=[
            MissingEvidenceItem(code=code, description=code, required_for=vulnerability_class)
            for code in (missing or [])
        ],
        confidence=0.8,
        derived_signals=derived_signals or [],
        status=status,
        judge_ready=judge_ready,
        created_at="2026-04-25T00:00:00+00:00",
    )
    memory_store.store_evidence_pack(
        pack.evidence_id,
        pack.campaign_id,
        pack.observation_id,
        pack.verification_plan_id,
        pack.model_dump(mode="json"),
    )
    return pack


def _verdict(
    kind: JudgeVerdictKind,
    *,
    severity: str = "",
    confidence: float = 0.91,
    reason: str = "judge reason",
    candidate: FindingCandidatePayload | None = None,
    duplicate_of: str = "",
) -> JudgeVerdictPayload:
    return JudgeVerdictPayload(
        verdict=kind,
        confidence=confidence,
        severity=severity,
        reason=reason,
        finding_candidate=candidate or FindingCandidatePayload(),
        duplicate_of_finding_id=duplicate_of,
        judge_source="unit",
        judge_model="test-model",
    )


def _request(
    kind: JudgeVerdictKind,
    *,
    evidence_id: str = "evp_ready",
    campaign_id: str = "cmp_judge1",
    candidate: FindingCandidatePayload | None = None,
    duplicate_of: str = "",
    max_rework_depth: int = 2,
    create_rework_on_inconclusive: bool = False,
) -> JudgeApplyRequest:
    return JudgeApplyRequest(
        campaign_id=campaign_id,
        evidence_id=evidence_id,
        task_id="task_request",
        verdict=_verdict(kind, candidate=candidate, duplicate_of=duplicate_of),
        rework_hint="collect_more_evidence",
        max_rework_depth=max_rework_depth,
        create_rework_on_inconclusive=create_rework_on_inconclusive,
    )


def _apply(req: JudgeApplyRequest):
    result, error = JudgeApplyService().apply(req)
    assert error is None
    assert result is not None
    return result


def test_confirmed_creates_finding_when_pack_judge_ready():
    _reset_store(); _create_campaign(); _pack()
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert result.finding_id
    assert result.finding is not None
    assert len(memory_store.confirmed_findings) == 1


def test_confirmed_api7_ssrf_with_callback_proof_creates_finding() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        owasp="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
        operation_id="op_POST_/api/contact",
        endpoint="/api/contact",
        method="POST",
        derived_signals=[
            "ssrf_probe_result",
            "callback_received_effective:true",
            "controlled_callback_received",
            "callback_correlation_matched",
        ],
    )
    candidate = FindingCandidatePayload(vulnerability_class="server_side_request_forgery")
    result = _apply(_request(JudgeVerdictKind.confirmed, candidate=candidate))
    assert result.finding is not None
    assert result.finding.owasp_category == "API7_SERVER_SIDE_REQUEST_FORGERY"
    assert result.finding.vulnerability_class == "server_side_request_forgery"


def test_apply_judge_for_ready_api7_ssrf_evidence_creates_confirmed_finding() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_api7_1",
        owasp="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
        operation_id="op_POST_/api/contact",
        endpoint="/api/contact",
        method="POST",
        derived_signals=[
            "ssrf_probe_result",
            "callback_received_effective:true",
            "callback_store_received:true",
            "controlled_callback_received",
            "callback_correlation_matched",
            "evidence_strength:high",
        ],
    )
    summary = apply_judge_for_ready_evidence_in_campaign(
        "cmp_judge1",
        owasp_category="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
    )
    assert summary["applied_count"] == 1
    assert summary["confirmed_count"] == 1
    findings = memory_store.list_confirmed_findings_by_campaign("cmp_judge1")
    assert len(findings) == 1
    assert findings[0]["owasp_category"] == "API7_SERVER_SIDE_REQUEST_FORGERY"
    assert findings[0]["vulnerability_class"] == "server_side_request_forgery"


def test_auto_judge_idempotent_for_same_evidence() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_api7_idem",
        owasp="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
        derived_signals=[
            "callback_received_effective:true",
            "callback_store_received:true",
            "controlled_callback_received",
            "callback_correlation_matched",
            "evidence_strength:high",
        ],
    )
    first = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    second = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    assert first["confirmed_count"] == 1
    assert second["confirmed_count"] == 0
    assert len(memory_store.list_judge_decisions_by_campaign("cmp_judge1")) == 1
    assert len(memory_store.list_confirmed_findings_by_campaign("cmp_judge1")) == 1


def test_auto_judge_does_not_confirm_without_callback_store_received() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_api7_no_store",
        owasp="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
        derived_signals=[
            "callback_received_effective:true",
            "controlled_callback_received",
            "callback_correlation_matched",
            "evidence_strength:high",
        ],
    )
    summary = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    assert summary["confirmed_count"] == 0
    assert len(memory_store.list_confirmed_findings_by_campaign("cmp_judge1")) == 0


def test_auto_judge_confirms_ready_bola_evidence() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_bola_1",
        owasp="API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        vulnerability_class="broken_object_level_authorization",
        operation_id="op_GET_/identity/api/v2/vehicle/{vehicleId}/location",
        endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        derived_signals=[
            "bola_replay_result",
            "object_pair_id:objpair_auto_1",
            "owner_baseline_valid:true",
            "result:attacker_access_granted",
            "access_granted:true",
            "replay_classification:possible_bola",
            "owner_status_code:200",
            "attacker_status_code:200",
            "evidence_strength:high",
            "semantic_id_kind:vehicle_id",
        ],
    )
    summary = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    assert summary["applied_count"] == 1
    assert summary["confirmed_count"] == 1
    findings = memory_store.list_confirmed_findings_by_campaign("cmp_judge1")
    assert len(findings) == 1
    assert findings[0]["owasp_category"] == "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"
    assert findings[0]["endpoint"] == "/identity/api/v2/vehicle/{vehicleId}/location"


def test_auto_judge_idempotent_for_bola() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_bola_idem",
        owasp="API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        vulnerability_class="broken_object_level_authorization",
        derived_signals=[
            "object_pair_id:objpair_auto_idem",
            "owner_baseline_valid:true",
            "result:attacker_access_granted",
            "access_granted:true",
            "replay_classification:possible_bola",
            "owner_status_code:200",
            "attacker_status_code:200",
            "evidence_strength:high",
        ],
    )
    first = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    second = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    assert first["confirmed_count"] == 1
    assert second["confirmed_count"] == 0
    assert len(memory_store.list_judge_decisions_by_campaign("cmp_judge1")) == 1
    assert len(memory_store.list_confirmed_findings_by_campaign("cmp_judge1")) == 1


def test_auto_judge_does_not_confirm_bola_without_strict_callback_equivalent_proof() -> None:
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_auto_bola_no_proof",
        owasp="API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        vulnerability_class="broken_object_level_authorization",
        derived_signals=[
            "object_pair_id:objpair_auto_no_proof",
            "owner_baseline_valid:true",
            "result:attacker_access_granted",
            "access_granted:true",
            "replay_classification:possible_bola",
            "owner_status_code:200",
            "attacker_status_code:403",
            "evidence_strength:high",
        ],
    )
    summary = apply_judge_for_ready_evidence_in_campaign("cmp_judge1")
    assert summary["confirmed_count"] == 0
    assert len(memory_store.list_confirmed_findings_by_campaign("cmp_judge1")) == 0


def test_confirmed_links_evidence_id_observation_id_decision_id():
    _reset_store(); _create_campaign(); pack = _pack()
    result = _apply(_request(JudgeVerdictKind.confirmed))
    finding = result.finding
    assert finding.evidence_id == pack.evidence_id
    assert finding.observation_id == pack.observation_id
    assert finding.decision_id == result.decision_id


def test_confirmed_marks_evidence_and_observation_applied():
    _reset_store(); _create_campaign(); pack = _pack()
    result = _apply(_request(JudgeVerdictKind.confirmed))
    ev_meta = memory_store.evidence_pack_apply_meta[pack.evidence_id]
    obs_meta = memory_store.observation_apply_meta[pack.observation_id]
    assert ev_meta["decision_id"] == result.decision_id
    assert obs_meta["finding_id"] == result.finding_id


def test_confirmed_uses_verdict_finding_candidate_overrides():
    _reset_store(); _create_campaign(); _pack()
    candidate = FindingCandidatePayload(
        title="Custom title",
        severity="critical",
        vulnerability_class="custom_class",
        summary="Custom summary",
        extras={"x": 1},
    )
    result = _apply(_request(JudgeVerdictKind.confirmed, candidate=candidate))
    assert result.finding.title == "Custom title"
    assert result.finding.severity == "critical"
    assert result.finding.vulnerability_class == "custom_class"
    assert result.finding.summary == "Custom summary"
    assert result.finding.candidate_extras == {"x": 1}


def test_confirmed_falls_back_to_evidence_pack_fields_when_candidate_missing():
    _reset_store(); _create_campaign(); _pack()
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert result.finding.vulnerability_class == "cross_role_access_signal"
    assert result.finding.endpoint == "/api/users/{id}"
    assert result.finding.summary == "Potential issue"


def test_confirmed_repeated_apply_does_not_duplicate_finding():
    _reset_store(); _create_campaign(); _pack()
    first = _apply(_request(JudgeVerdictKind.confirmed))
    second = _apply(_request(JudgeVerdictKind.confirmed))
    assert first.finding_id == second.finding_id
    assert len(memory_store.confirmed_findings) == 1


def test_confirmed_with_existing_fingerprint_links_existing_finding():
    _reset_store(); _create_campaign(); _pack()
    first = _apply(_request(JudgeVerdictKind.confirmed))
    second = _apply(_request(JudgeVerdictKind.confirmed))
    assert second.duplicate_of_finding_id == first.finding_id


def test_bola_fingerprint_distinguishes_different_object_or_roles():
    _reset_store(); _create_campaign()
    _pack(
        evidence_id="evp_obj_123",
        observation_id="obs_obj_123",
        verification_plan_id="vplan_obj_123",
        object_id="123",
        baseline_role="owner",
        attack_role="attacker",
        owner_role="owner",
    )
    _pack(
        evidence_id="evp_obj_456",
        observation_id="obs_obj_456",
        verification_plan_id="vplan_obj_456",
        object_id="456",
        baseline_role="owner",
        attack_role="attacker",
        owner_role="owner",
    )

    first = _apply(_request(JudgeVerdictKind.confirmed, evidence_id="evp_obj_123"))
    second = _apply(_request(JudgeVerdictKind.confirmed, evidence_id="evp_obj_456"))

    assert first.finding_id != second.finding_id
    assert first.finding.fingerprint != second.finding.fingerprint
    assert len(memory_store.confirmed_findings) == 2


def test_confirmed_severity_default_heuristic_by_owasp_category():
    expectations = {
        "API1_BOLA": "high",
        "API2_AUTH": "high",
        "API5_BFLA": "high",
        "API3_BOPLA": "medium",
        "API4_UNRESTRICTED_RESOURCE_CONSUMPTION": "medium",
        "API8_SECURITY_MISCONFIGURATION": "low",
        "API9_IMPROPER_INVENTORY_MANAGEMENT": "low",
        "OTHER": "info",
    }
    for idx, (owasp, severity) in enumerate(expectations.items()):
        _reset_store(); _create_campaign(); _pack(evidence_id=f"evp_{idx}", owasp=owasp)
        result = _apply(_request(JudgeVerdictKind.confirmed, evidence_id=f"evp_{idx}"))
        assert result.finding.severity == severity


def test_confirmed_on_incomplete_pack_downgrades_to_rework():
    _reset_store(); _create_campaign()
    _pack(status=EvidencePackStatus.incomplete, judge_ready=False, missing=["ownership_proof"])
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert result.decision.verdict == JudgeVerdictKind.rework
    assert result.decision.applied_status == "applied_with_downgrade"
    assert result.finding is None
    assert result.followup_verification_plan_id


def test_confirmed_on_not_judge_ready_pack_downgrades_to_inconclusive():
    _reset_store(); _create_campaign()
    _pack(status=EvidencePackStatus.not_judge_ready, judge_ready=False)
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert result.decision.verdict == JudgeVerdictKind.inconclusive
    assert "evidence_not_judge_ready" in result.readiness_issues
    assert result.finding is None


def test_confirmed_with_missing_evidence_does_not_create_finding():
    _reset_store(); _create_campaign()
    _pack(status=EvidencePackStatus.incomplete, judge_ready=False, missing=["negative_control"])
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert result.finding is None
    assert memory_store.confirmed_findings == {}


def test_confirmed_mass_assignment_without_runtime_effect_downgrades_and_no_finding():
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_mass_assignment",
        vulnerability_class="potential_mass_assignment",
        owasp="API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        derived_signals=["mass_assignment_signal", "runtime_effect_proven:false"],
    )
    result = _apply(_request(JudgeVerdictKind.confirmed, evidence_id="evp_mass_assignment"))
    assert result.finding is None
    assert result.decision.verdict == JudgeVerdictKind.rework
    assert result.decision.applied_status == "applied_with_downgrade"
    assert "mass_assignment_runtime_effect_not_proven" in result.readiness_issues
    assert memory_store.confirmed_findings == {}


def test_confirmed_mass_assignment_with_runtime_effect_true_can_create_finding():
    _reset_store()
    _create_campaign()
    _pack(
        evidence_id="evp_mass_assignment_rt",
        vulnerability_class="potential_mass_assignment",
        owasp="API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        derived_signals=["mass_assignment_signal", "runtime_effect_proven:true"],
    )
    result = _apply(_request(JudgeVerdictKind.confirmed, evidence_id="evp_mass_assignment_rt"))
    assert result.finding is not None
    assert result.decision.verdict == JudgeVerdictKind.confirmed


def test_downgrade_records_readiness_issues_in_decision():
    _reset_store(); _create_campaign()
    _pack(status=EvidencePackStatus.incomplete, judge_ready=False, missing=["diff_missing"])
    result = _apply(_request(JudgeVerdictKind.confirmed))
    assert "evidence_incomplete" in result.decision.readiness_issues
    assert "diff_missing" in result.decision.readiness_issues


def test_rework_creates_followup_verification_plan():
    _reset_store(); _create_campaign()
    _pack(status=EvidencePackStatus.incomplete, judge_ready=False, missing=["x"])
    result = _apply(_request(JudgeVerdictKind.rework))
    assert result.followup_verification_plan_id
    assert result.followup_verification_plan.status == VerificationPlanStatus.pending


def test_rework_preserves_parent_observation_id_and_task_id():
    _reset_store(); _create_campaign(); pack = _pack(missing=["x"], judge_ready=False, status=EvidencePackStatus.incomplete)
    result = _apply(_request(JudgeVerdictKind.rework))
    plan = result.followup_verification_plan
    assert plan.parent_observation_id == pack.observation_id
    assert plan.parent_task_id == pack.task_id


def test_rework_required_evidence_copies_missing_evidence_codes():
    _reset_store(); _create_campaign()
    _pack(missing=["a", "b"], judge_ready=False, status=EvidencePackStatus.incomplete)
    result = _apply(_request(JudgeVerdictKind.rework))
    assert result.followup_verification_plan.required_evidence == ["a", "b"]


def test_rework_repeated_apply_reuses_pending_plan():
    _reset_store(); _create_campaign()
    _pack(missing=["a"], judge_ready=False, status=EvidencePackStatus.incomplete)
    first = _apply(_request(JudgeVerdictKind.rework))
    second = _apply(_request(JudgeVerdictKind.rework))
    assert first.followup_verification_plan_id == second.followup_verification_plan_id


def test_rework_reuses_existing_active_plan_when_depth_exhausted():
    _reset_store(); _create_campaign()
    pack = _pack(missing=["a"], judge_ready=False, status=EvidencePackStatus.incomplete)
    existing = VerificationPlan(
        verification_plan_id="vplan_existing_active",
        campaign_id=pack.campaign_id,
        parent_observation_id=pack.observation_id,
        parent_task_id=pack.task_id,
        goal="collect_more_evidence",
        strategy="collect_more_evidence",
        required_evidence=["a"],
        status=VerificationPlanStatus.pending,
    )
    memory_store.store_verification_plan(
        existing.verification_plan_id,
        existing.campaign_id,
        existing.model_dump(mode="json"),
    )

    result = _apply(_request(JudgeVerdictKind.rework, max_rework_depth=0))

    assert result.followup_verification_plan_id == existing.verification_plan_id
    assert len(memory_store.verification_plans) == 1


def test_rework_depth_exhaustion_creates_no_plan():
    _reset_store(); _create_campaign()
    _pack(missing=["a"], judge_ready=False, status=EvidencePackStatus.incomplete)
    result = _apply(_request(JudgeVerdictKind.rework, max_rework_depth=0))
    assert result.followup_verification_plan_id == ""
    assert len(memory_store.verification_plans) == 0


def test_rework_does_not_create_finding():
    _reset_store(); _create_campaign()
    _pack(missing=["a"], judge_ready=False, status=EvidencePackStatus.incomplete)
    _apply(_request(JudgeVerdictKind.rework))
    assert memory_store.confirmed_findings == {}


def test_rework_does_not_call_legacy_task_scheduler(monkeypatch):
    _reset_store(); _create_campaign()
    _pack(missing=["a"], judge_ready=False, status=EvidencePackStatus.incomplete)
    called = {"value": False}

    def mark_called(*args, **kwargs):
        called["value"] = True

    monkeypatch.setattr(memory_store, "store_command", mark_called)
    _apply(_request(JudgeVerdictKind.rework))
    assert called["value"] is False


def test_rejected_does_not_create_finding():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.rejected))
    assert memory_store.confirmed_findings == {}


def test_rejected_marks_evidence_applied_with_rejected_status():
    _reset_store(); _create_campaign(); pack = _pack()
    result = _apply(_request(JudgeVerdictKind.rejected))
    meta = memory_store.evidence_pack_apply_meta[pack.evidence_id]
    assert meta["verdict"] == "rejected"
    assert meta["decision_id"] == result.decision_id


def test_out_of_scope_does_not_create_finding_or_plan():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.out_of_scope))
    assert memory_store.confirmed_findings == {}
    assert memory_store.verification_plans == {}


def test_duplicate_with_target_links_existing_finding():
    _reset_store(); _create_campaign(); _pack()
    confirmed = _apply(_request(JudgeVerdictKind.confirmed))
    duplicate = _apply(_request(JudgeVerdictKind.duplicate, duplicate_of=confirmed.finding_id))
    assert duplicate.duplicate_of_finding_id == confirmed.finding_id
    stored = memory_store.get_confirmed_finding(confirmed.finding_id)
    assert duplicate.decision_id in stored["duplicates"]


def test_duplicate_via_fingerprint_links_existing_finding():
    _reset_store(); _create_campaign(); _pack()
    confirmed = _apply(_request(JudgeVerdictKind.confirmed))
    duplicate = _apply(_request(JudgeVerdictKind.duplicate))
    assert duplicate.duplicate_of_finding_id == confirmed.finding_id


def test_duplicate_without_target_or_fingerprint_returns_422():
    _reset_store(); _create_campaign(); _pack()
    result, error = JudgeApplyService().apply(_request(JudgeVerdictKind.duplicate))
    assert result is None
    assert isinstance(error, JudgeApplyError)
    assert error.code == "duplicate_target_required"
    assert error.status_code == 422


def test_duplicate_target_in_other_campaign_returns_409():
    _reset_store(); _create_campaign("cmp_a"); _create_campaign("cmp_b")
    _pack(campaign_id="cmp_b", evidence_id="evp_b")
    existing = _apply(_request(JudgeVerdictKind.confirmed, campaign_id="cmp_b", evidence_id="evp_b"))
    _pack(campaign_id="cmp_a", evidence_id="evp_a")
    result, error = JudgeApplyService().apply(
        _request(JudgeVerdictKind.duplicate, campaign_id="cmp_a", evidence_id="evp_a", duplicate_of=existing.finding_id)
    )
    assert result is None
    assert error.code == "duplicate_target_other_campaign"
    assert error.status_code == 409


def test_duplicate_does_not_create_new_finding():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.confirmed))
    _apply(_request(JudgeVerdictKind.duplicate))
    assert len(memory_store.confirmed_findings) == 1


def test_inconclusive_does_not_create_finding():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.inconclusive))
    assert memory_store.confirmed_findings == {}


def test_inconclusive_with_missing_evidence_creates_followup_plan_when_flag_set():
    _reset_store(); _create_campaign()
    _pack(missing=["x"], judge_ready=False, status=EvidencePackStatus.incomplete)
    result = _apply(_request(JudgeVerdictKind.inconclusive, create_rework_on_inconclusive=True))
    assert result.followup_verification_plan_id


def test_inconclusive_without_flag_does_not_create_plan():
    _reset_store(); _create_campaign()
    _pack(missing=["x"], judge_ready=False, status=EvidencePackStatus.incomplete)
    result = _apply(_request(JudgeVerdictKind.inconclusive))
    assert result.followup_verification_plan_id == ""


def test_unknown_evidence_id_returns_404():
    _reset_store(); _create_campaign()
    result, error = JudgeApplyService().apply(_request(JudgeVerdictKind.rejected, evidence_id="missing"))
    assert result is None
    assert error.code == "evidence_pack_not_found"
    assert error.status_code == 404


def test_evidence_campaign_mismatch_returns_409():
    _reset_store(); _create_campaign("cmp_a"); _create_campaign("cmp_b")
    _pack(campaign_id="cmp_a")
    result, error = JudgeApplyService().apply(
        _request(JudgeVerdictKind.rejected, campaign_id="cmp_b")
    )
    assert result is None
    assert error.code == "campaign_mismatch"
    assert error.status_code == 409


def test_decision_record_persisted_for_every_verdict():
    for kind in [
        JudgeVerdictKind.confirmed,
        JudgeVerdictKind.rework,
        JudgeVerdictKind.rejected,
        JudgeVerdictKind.out_of_scope,
        JudgeVerdictKind.inconclusive,
    ]:
        _reset_store(); _create_campaign()
        _pack(missing=["x"] if kind == JudgeVerdictKind.rework else None,
              judge_ready=kind != JudgeVerdictKind.rework,
              status=EvidencePackStatus.incomplete if kind == JudgeVerdictKind.rework else EvidencePackStatus.ready_for_judge)
        _apply(_request(kind))
        assert len(memory_store.judge_decisions) == 1


def test_decisions_listed_by_campaign():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.rejected))
    assert len(memory_store.list_judge_decisions_by_campaign("cmp_judge1")) == 1


def test_decisions_listed_by_evidence():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.rejected))
    assert len(memory_store.list_judge_decisions_by_evidence("evp_ready")) == 1


def test_findings_listed_by_campaign():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.confirmed))
    assert len(memory_store.list_confirmed_findings_by_campaign("cmp_judge1")) == 1


def _client():
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


def test_findings_get_item_returns_finding():
    _reset_store(); _create_campaign(); _pack()
    result = _apply(_request(JudgeVerdictKind.confirmed))
    resp = _client().get(f"/v1/findings/confirmed/item/{result.finding_id}")
    assert resp.status_code == 200
    assert resp.json()["finding_id"] == result.finding_id


def test_findings_get_item_404():
    _reset_store()
    resp = _client().get("/v1/findings/confirmed/item/finding_missing")
    assert resp.status_code == 404


def test_no_legacy_finding_written_via_judge_apply():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.confirmed))
    assert memory_store.findings == []
    assert dict(memory_store.findings_by_session) == {}


def test_no_legacy_evidence_record_written_via_judge_apply():
    _reset_store(); _create_campaign(); _pack()
    _apply(_request(JudgeVerdictKind.confirmed))
    assert memory_store.evidence_records == []
    assert dict(memory_store.evidence_by_session) == {}


def test_legacy_judge_ready_evidence_flow_still_works():
    _reset_store()
    from backend.models.tool_wrappers import ToolWrapperResult
    from backend.services.evidence_builder_service import EvidenceBuilderService

    evidence = EvidenceBuilderService().from_wrapper_result(
        task=None,
        worker_role="access_control",
        tool_result=ToolWrapperResult(tool_name="custom_request_executor", source_task_id="t"),
        run_id="run_1",
    )
    assert evidence.schema_version == "judge-ready-evidence/v1"
    assert memory_store.confirmed_findings == {}


def test_judge_apply_does_not_invoke_tool_executor(monkeypatch):
    _reset_store(); _create_campaign(); _pack()
    import backend.services.tool_executor as tool_executor

    def fail(*args, **kwargs):
        raise AssertionError("ToolExecutor should not be invoked")

    monkeypatch.setattr(tool_executor.ToolExecutor, "execute_sync", fail)
    _apply(_request(JudgeVerdictKind.confirmed))


def test_judge_apply_does_not_invoke_evidence_pack_builder(monkeypatch):
    _reset_store(); _create_campaign(); _pack()
    import backend.services.evidence_pack_builder as evidence_pack_builder

    def fail(*args, **kwargs):
        raise AssertionError("EvidencePackBuilder should not be invoked")

    monkeypatch.setattr(evidence_pack_builder.EvidencePackBuilder, "build_from_observation", fail)
    _apply(_request(JudgeVerdictKind.confirmed))


def test_apply_route_and_list_routes_work():
    _reset_store(); _create_campaign(); _pack()
    payload = _request(JudgeVerdictKind.confirmed).model_dump(mode="json")
    client = _client()
    resp = client.post("/v1/judge/apply", json=payload)
    assert resp.status_code == 200
    finding_id = resp.json()["finding_id"]
    assert client.get("/v1/judge/decisions/cmp_judge1").status_code == 200
    findings = client.get("/v1/findings/confirmed/cmp_judge1")
    assert findings.status_code == 200
    assert findings.json()[0]["finding_id"] == finding_id
