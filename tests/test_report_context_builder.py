from __future__ import annotations

import json

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.evidence_pack import EvidencePack, EvidencePackStatus
from backend.models.judge import ConfirmedFinding, JudgeDecisionRecord, JudgeVerdictKind
from backend.models.observation import Observation, ObservationType, VerificationPlan, VerificationPlanStatus
from backend.services.report_context_builder import ReportContextBuilder
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
        "evidence_packs_by_verification_plan", "judge_decisions", "judge_decisions_by_campaign",
        "judge_decisions_by_evidence", "confirmed_findings", "confirmed_findings_by_campaign",
        "findings_by_fingerprint", "evidence_pack_apply_meta", "observation_apply_meta",
    ]:
        getattr(memory_store, name).clear()


def _create_campaign(campaign_id: str = "cmp_report") -> None:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://target.local",
        openapi_url="http://target.local/openapi.json",
        allowed_hosts=["target.local"],
        profile="safe",
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
        created_at="2026-04-27T00:00:00+00:00",
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))


def _store_sample_finding(campaign_id: str = "cmp_report", evidence_id: str = "evp_1") -> None:
    finding = ConfirmedFinding(
        finding_id="finding_1",
        campaign_id=campaign_id,
        evidence_id=evidence_id,
        decision_id="jdec_1",
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="security_header_misconfiguration",
        endpoint="/api/v1/me",
        method="GET",
        title="Missing Security Header",
        severity="low",
        summary="Header validation confirms a missing policy.",
        reproduction_pointer={"evidence_id": evidence_id, "replay_steps_count": 1},
    )
    memory_store.store_confirmed_finding(
        finding.finding_id,
        finding.campaign_id,
        "fp_1",
        finding.model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id=evidence_id,
        campaign_id=campaign_id,
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="security_header_misconfiguration",
        hypothesis="Validated security header issue.",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["validated_security_header_issue"],
    )
    memory_store.store_evidence_pack(
        evidence_id=evidence_id,
        campaign_id=campaign_id,
        observation_id="obs_1",
        verification_plan_id="",
        data=evidence.model_dump(mode="json"),
    )
    decision = JudgeDecisionRecord(
        decision_id="jdec_1",
        campaign_id=campaign_id,
        evidence_id=evidence_id,
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(
        decision.decision_id,
        campaign_id,
        evidence_id,
        decision.model_dump(mode="json"),
    )


def test_report_context_empty_campaign() -> None:
    _reset_store()
    _create_campaign()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    assert ctx["schema_version"] == "report-context/v1"
    assert ctx["campaign"]["campaign_id"] == "cmp_report"
    assert ctx["executive_summary"]["confirmed_findings_count"] == 0
    assert "runtime_state_snapshot" in ctx["data_quality"]["missing_sections"]
    assert any("No destructive tests were performed." in row for row in ctx["limitations"])


def test_report_context_confirmed_finding_and_api8_grouping() -> None:
    _reset_store()
    _create_campaign()
    _store_sample_finding()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    assert len(ctx["confirmed_findings"]) == 1
    finding = ctx["confirmed_findings"][0]
    assert finding["finding_id"] == "finding_1"
    assert finding["evidence_id"] == "evp_1"
    assert finding["owasp_category"] == "API8_SECURITY_MISCONFIGURATION"
    assert finding["judge_verdict"] == "confirmed"
    assert finding["detection_chain"]["worker_kind"] == "security_header_validator"
    assert finding["detection_chain"]["observation_type"] == "validated_security_header_issue"
    assert finding["detection_chain"]["evidence_id"] == "evp_1"
    assert finding["detection_chain"]["judge_verdict"] == "confirmed"
    assert finding["detection_chain"]["vulnerability_class"] == "security_header_misconfiguration"
    assert isinstance(finding["safe_reproduction_steps"], list) and len(finding["safe_reproduction_steps"]) >= 1
    assert finding["safe_reproduction_steps"][0]["method"] == "GET"
    assert finding["safe_reproduction_steps"][0]["endpoint"] == "/api/v1/me"
    assert finding["safe_reproduction_steps"][0]["evidence_id"] == "evp_1"
    assert "В рамках разрешённой тестовой среды" in finding["safe_reproduction_steps"][0]["check"]
    assert "авторизованный запрос" not in finding["safe_reproduction_steps"][0]["check"].lower()
    assert finding["exploitation_summary"]
    assert finding["impact_summary"]
    assert finding["remediation_hint"]
    assert ctx["owasp_coverage"]["API8_SECURITY_MISCONFIGURATION"]["confirmed_findings_count"] == 1
    assert "finding_groups" in ctx


def test_report_context_api9_and_api3_diagnostics_with_runtime_snapshot() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_schema",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_schema",
            campaign_id="cmp_report",
            type=ObservationType.schema_mismatch,
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_mass",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_mass",
            campaign_id="cmp_report",
            type=ObservationType.mass_assignment_signal,
        ).model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id="evp_mass",
        campaign_id="cmp_report",
        vulnerability_class="potential_mass_assignment",
        derived_signals=["runtime_effect_proven:true"],
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
    )
    memory_store.store_evidence_pack("evp_mass", "cmp_report", "obs_mass", "", evidence.model_dump(mode="json"))

    runtime = {
        "iterations_run": 4,
        "max_iterations": 6,
        "stopped_reason": "max_iterations_reached",
        "executed_by_kind": {
            "schemathesis_negative_test": 2,
            "property_mutation_test": 1,
            "security_header_validator": 1,
            "cookie_flag_validator": 1,
            "cors_validator": 1,
        },
        "ready_candidates_by_kind_count": {
            "property_mutation_test": 3,
        },
        "blocked_candidates_by_kind_count": {
            "property_mutation_test": 2,
        },
        "blocked_candidates_sample": [
            {
                "kind": "property_mutation_test",
                "mass_assignment_candidate_result": "blocked_no_sensitive_fields",
                "reason_codes": ["blocked_no_sensitive_fields"],
            },
            {
                "kind": "property_mutation_test",
                "mass_assignment_candidate_result": "blocked_missing_seed_context",
                "reason_codes": ["blocked_missing_seed_context"],
            },
        ],
        "ready_candidates_sample": [
            {"kind": "cors_validator", "tool_name": "cors_validator", "validation_mode": "single_replay_cors_check"},
        ],
        "tool_failures_count": 1,
        "failed_by_kind": {"security_header_validator": 1},
        "tool_failure_summaries": [{"candidate_kind": "security_header_validator", "tool_error_safe_message": "response too large"}],
        "iteration_summaries": [
            {"candidate_kind": "cors_validator", "outcome": "no_observations"},
            {"candidate_kind": "property_mutation_test", "outcome": "pending_verification"},
            {"candidate_kind": "security_header_validator", "outcome": "tool_failed"},
        ],
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    assert ctx is not None
    assert ctx["data_quality"]["runtime_state_attached"] is True
    assert ctx["owasp_coverage"]["API9_IMPROPER_INVENTORY_MANAGEMENT"]["schema_mismatch_count"] == 1
    assert ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]["blocked_no_sensitive_fields_count"] >= 1
    assert ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]["blocked_missing_seed_context_count"] >= 1
    assert ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]["runtime_effect_proven_count"] == 1
    assert ctx["worker_execution_summary"]["executed_by_kind"]["schemathesis_negative_test"] == 2


def test_report_context_pending_and_runtime_absence_defaults() -> None:
    _reset_store()
    _create_campaign()
    plan = VerificationPlan(
        verification_plan_id="vplan_1",
        campaign_id="cmp_report",
        goal="prove_cors_misconfiguration",
        status=VerificationPlanStatus.pending,
    )
    memory_store.store_verification_plan("vplan_1", "cmp_report", plan.model_dump(mode="json"))
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    assert ctx["executive_summary"]["iterations_run"] == "not_available"
    assert len(ctx["pending_verification"]) >= 1
    assert ctx["worker_execution_summary"]["status"] == "not_available"


def test_report_context_sanitizer_no_raw_leakage_but_safe_cookie_fields_allowed() -> None:
    _reset_store()
    _create_campaign()
    runtime = {
        "ready_candidates_sample": [{
            "kind": "cookie_flag_validator",
            "cookie_name_hash": "abc123",
            "cookie_candidate_source": "baseline",
            "safe_note": "Authorization: Bearer secret",
            "raw_headers": {"Authorization": "Bearer X"},
            "payload": {"token": "123"},
        }],
        "blocked_candidates_sample": [],
        "executed_by_kind": {"cookie_flag_validator": 1},
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    assert ctx is not None
    blob = json.dumps(ctx, ensure_ascii=False)
    for bad in ("Authorization", "Set-Cookie:", "Bearer ", "token=", "request_body", "response_body", "raw_body", "raw_headers"):
        assert bad not in blob
    assert "cookie_flag_validator" in blob
    assert "cookie_name_hash" in blob


def test_report_context_confirmed_finding_safe_fields_have_no_raw_leakage() -> None:
    _reset_store()
    _create_campaign()
    _store_sample_finding()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    finding = ctx["confirmed_findings"][0]
    blob = json.dumps(finding, ensure_ascii=False)
    for bad in ("Authorization", "Cookie", "Set-Cookie", "request_body", "response_body", "token=", "Bearer "):
        assert bad not in blob


def test_schema_contract_violation_normalized_to_api9() -> None:
    _reset_store()
    _create_campaign()
    finding = ConfirmedFinding(
        finding_id="finding_schema_1",
        campaign_id="cmp_report",
        evidence_id="evp_schema_1",
        decision_id="jdec_schema_1",
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="api_schema_contract_violation",
        endpoint="/api/v1/orders",
        method="POST",
        title="Schema behavior mismatch",
        severity="medium",
        summary="schema mismatch",
    )
    memory_store.store_confirmed_finding(
        finding.finding_id,
        finding.campaign_id,
        "fp_schema_1",
        finding.model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id="evp_schema_1",
        campaign_id="cmp_report",
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="api_schema_contract_violation",
        hypothesis="Schema mismatch from bounded contract check",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["schema_mismatch"],
    )
    memory_store.store_evidence_pack("evp_schema_1", "cmp_report", "obs_schema_1", "", evidence.model_dump(mode="json"))
    decision = JudgeDecisionRecord(
        decision_id="jdec_schema_1",
        campaign_id="cmp_report",
        evidence_id="evp_schema_1",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(
        decision.decision_id,
        "cmp_report",
        "evp_schema_1",
        decision.model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    row = ctx["confirmed_findings"][0]
    assert row["owasp_category"] == "API9_IMPROPER_INVENTORY_MANAGEMENT"
    assert row["source_owasp_category"] == "API8_SECURITY_MISCONFIGURATION"
    assert row["category_normalized"] is True
    assert ctx["owasp_coverage"]["API9_IMPROPER_INVENTORY_MANAGEMENT"]["confirmed_findings_count"] == 1
    assert ctx["owasp_coverage"]["API8_SECURITY_MISCONFIGURATION"]["confirmed_findings_count"] == 0


def test_confirmed_finding_contains_traceability_fields() -> None:
    _reset_store()
    _create_campaign()
    _store_sample_finding()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    row = ctx["confirmed_findings"][0]
    assert row["finding_id"] == "finding_1"
    assert row["evidence_id"] == "evp_1"
    assert row["judge_verdict"] == "confirmed"
    assert isinstance(row["detection_chain"], dict)
    assert row["detection_chain"]["worker_kind"] == "security_header_validator"
    assert row["detection_chain"]["observation_type"] == "validated_security_header_issue"
    assert row["detection_chain"]["evidence_id"] == "evp_1"
    assert isinstance(row["safe_reproduction_steps"], list) and row["safe_reproduction_steps"]


def test_api3_diagnostics_counts_from_blocked_snapshot() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_mass_diag",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_mass_diag",
            campaign_id="cmp_report",
            type=ObservationType.mass_assignment_signal,
        ).model_dump(mode="json"),
    )
    ev = EvidencePack(
        evidence_id="evp_mass_diag",
        campaign_id="cmp_report",
        vulnerability_class="potential_mass_assignment",
        derived_signals=["runtime_effect_proven:true"],
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
    )
    memory_store.store_evidence_pack("evp_mass_diag", "cmp_report", "obs_mass_diag", "", ev.model_dump(mode="json"))
    runtime = {
        "executed_by_kind": {"property_mutation_test": 1},
        "ready_candidates_by_kind_count": {"property_mutation_test": 2},
        "blocked_candidates_by_kind_count": {"property_mutation_test": 3},
        "blocked_candidates_sample": [
            {"kind": "property_mutation_test", "mass_assignment_candidate_result": "blocked_no_sensitive_fields", "reason_codes": ["blocked_no_sensitive_fields"]},
            {"kind": "property_mutation_test", "mass_assignment_candidate_result": "blocked_missing_seed_context", "reason_codes": ["blocked_missing_seed_context"]},
        ],
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["blocked_no_sensitive_fields_count"] >= 1
    assert api3["blocked_missing_seed_context_count"] >= 1
    assert api3["mass_assignment_signal_count"] >= 1
    assert api3["runtime_effect_proven_count"] >= 1
    assert api3["confirmed_findings_count"] == 0
    assert api3["candidates_considered"] == 6


def test_api3_coverage_present_even_when_no_findings() -> None:
    _reset_store()
    _create_campaign()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    assert "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION" in ctx["owasp_coverage"]
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert "confirmed_findings_count" in api3
    assert api3["confirmed_findings_count"] == 0


def test_static_asset_context_and_security_header_grouping_fields() -> None:
    _reset_store()
    _create_campaign()
    for idx, endpoint in enumerate(("/static/css/app.css", "/images/favicon.ico"), start=1):
        finding = ConfirmedFinding(
            finding_id=f"finding_static_{idx}",
            campaign_id="cmp_report",
            evidence_id=f"evp_static_{idx}",
            decision_id=f"jdec_static_{idx}",
            owasp_category="API8_SECURITY_MISCONFIGURATION",
            vulnerability_class="security_header_misconfiguration",
            endpoint=endpoint,
            method="GET",
            title="Missing X-Frame-Options",
            severity="low",
            summary="header missing",
        )
        memory_store.store_confirmed_finding(
            finding.finding_id,
            finding.campaign_id,
            f"fp_static_{idx}",
            finding.model_dump(mode="json"),
        )
        evidence = EvidencePack(
            evidence_id=f"evp_static_{idx}",
            campaign_id="cmp_report",
            owasp_category="API8_SECURITY_MISCONFIGURATION",
            vulnerability_class="security_header_misconfiguration",
            hypothesis="Validated security header issue.",
            status=EvidencePackStatus.ready_for_judge,
            judge_ready=True,
            derived_signals=["validated_security_header_issue", "header_name:X-Frame-Options"],
        )
        memory_store.store_evidence_pack(
            f"evp_static_{idx}",
            "cmp_report",
            f"obs_static_{idx}",
            "",
            evidence.model_dump(mode="json"),
        )
        decision = JudgeDecisionRecord(
            decision_id=f"jdec_static_{idx}",
            campaign_id="cmp_report",
            evidence_id=f"evp_static_{idx}",
            verdict=JudgeVerdictKind.confirmed,
            reason="confirmed",
        )
        memory_store.store_judge_decision(
            decision.decision_id,
            "cmp_report",
            f"evp_static_{idx}",
            decision.model_dump(mode="json"),
        )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    rows = ctx["confirmed_findings"]
    assert len(rows) == 2
    for row in rows:
        assert row["resource_context"]["is_static_asset"] is True
        assert row["resource_context"]["resource_type"] == "static_asset"
        assert "статическому или служебному ресурсу" in row["resource_context"]["impact_note"]
        assert row["finding_group_key"].startswith("security_header_misconfiguration:")
        assert row["similar_findings_count"] == 2
        assert len(row["similar_affected_endpoints"]) == 2
    groups = ctx["finding_groups"]
    assert len(groups) == 1
    assert groups[0]["count"] == 2
    assert len(groups[0]["affected_endpoints"]) == 2
    assert len(groups[0]["finding_ids"]) == 2


def test_robots_txt_is_static_asset_with_service_note() -> None:
    _reset_store()
    _create_campaign()
    finding = ConfirmedFinding(
        finding_id="finding_robots",
        campaign_id="cmp_report",
        evidence_id="evp_robots",
        decision_id="jdec_robots",
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="security_header_misconfiguration",
        endpoint="/robots.txt",
        method="GET",
        title="Missing X-Content-Type-Options",
        severity="low",
        summary="header missing",
    )
    memory_store.store_confirmed_finding(finding.finding_id, finding.campaign_id, "fp_robots", finding.model_dump(mode="json"))
    evidence = EvidencePack(
        evidence_id="evp_robots",
        campaign_id="cmp_report",
        vulnerability_class="security_header_misconfiguration",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["validated_security_header_issue"],
    )
    memory_store.store_evidence_pack("evp_robots", "cmp_report", "obs_robots", "", evidence.model_dump(mode="json"))
    decision = JudgeDecisionRecord(
        decision_id="jdec_robots",
        campaign_id="cmp_report",
        evidence_id="evp_robots",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(decision.decision_id, "cmp_report", "evp_robots", decision.model_dump(mode="json"))
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    row = ctx["confirmed_findings"][0]
    assert row["resource_context"]["is_static_asset"] is True
    assert "статическому или служебному ресурсу" in row["resource_context"]["impact_note"]


def test_safe_reproduction_steps_are_russian() -> None:
    _reset_store()
    _create_campaign()
    finding = ConfirmedFinding(
        finding_id="finding_schema_ru",
        campaign_id="cmp_report",
        evidence_id="evp_schema_ru",
        decision_id="jdec_schema_ru",
        owasp_category="API9_IMPROPER_INVENTORY_MANAGEMENT",
        vulnerability_class="api_schema_contract_violation",
        endpoint="/api/v1/orders",
        method="POST",
        title="Schema mismatch",
        severity="medium",
        summary="schema mismatch",
    )
    memory_store.store_confirmed_finding(finding.finding_id, finding.campaign_id, "fp_schema_ru", finding.model_dump(mode="json"))
    evidence = EvidencePack(
        evidence_id="evp_schema_ru",
        campaign_id="cmp_report",
        vulnerability_class="api_schema_contract_violation",
        hypothesis="schema check",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["schema_mismatch"],
    )
    memory_store.store_evidence_pack("evp_schema_ru", "cmp_report", "obs_schema_ru", "", evidence.model_dump(mode="json"))
    decision = JudgeDecisionRecord(
        decision_id="jdec_schema_ru",
        campaign_id="cmp_report",
        evidence_id="evp_schema_ru",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(decision.decision_id, "cmp_report", "evp_schema_ru", decision.model_dump(mode="json"))
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    steps_blob = json.dumps(ctx["confirmed_findings"][0]["safe_reproduction_steps"], ensure_ascii=False)
    assert "ограниченную проверку контракта по OpenAPI" in steps_blob
    assert "bounded contract check against OpenAPI" not in steps_blob


def test_security_header_endpoint_fallback() -> None:
    _reset_store()
    _create_campaign()
    finding = ConfirmedFinding(
        finding_id="finding_hdr_fallback",
        campaign_id="cmp_report",
        evidence_id="evp_hdr_fallback",
        decision_id="jdec_hdr_fallback",
        owasp_category="API8_SECURITY_MISCONFIGURATION",
        vulnerability_class="security_header_misconfiguration",
        endpoint="",
        method="GET",
        title="Missing CSP",
        severity="low",
        summary="header issue",
    )
    memory_store.store_confirmed_finding(finding.finding_id, finding.campaign_id, "fp_hdr_fallback", finding.model_dump(mode="json"))
    evidence = EvidencePack(
        evidence_id="evp_hdr_fallback",
        campaign_id="cmp_report",
        vulnerability_class="security_header_misconfiguration",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        attack={"request_ref": {"path_template": "/static/app.js"}},
        derived_signals=["validated_security_header_issue", "header_name:Content-Security-Policy"],
    )
    memory_store.store_evidence_pack("evp_hdr_fallback", "cmp_report", "obs_hdr_fallback", "", evidence.model_dump(mode="json"))
    decision = JudgeDecisionRecord(
        decision_id="jdec_hdr_fallback",
        campaign_id="cmp_report",
        evidence_id="evp_hdr_fallback",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(decision.decision_id, "cmp_report", "evp_hdr_fallback", decision.model_dump(mode="json"))
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    row = ctx["confirmed_findings"][0]
    assert row["endpoint"] == "/static/app.js"
