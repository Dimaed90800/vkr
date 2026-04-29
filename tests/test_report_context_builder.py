from __future__ import annotations

import hashlib
import json

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.evidence_pack import EvidencePack, EvidencePackStatus
from backend.models.judge import ConfirmedFinding, JudgeDecisionRecord, JudgeVerdictKind
from backend.models.observation import Observation, ObservationType, VerificationPlan, VerificationPlanStatus
from backend.services.report_context_builder import ReportContextBuilder
from backend.services.auth_profile_store import AuthProfileStore
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
        "auth_profiles", "auth_profiles_by_campaign", "runtime_token_secrets", "runtime_credential_secrets",
        "runtime_response_json_secrets", "runtime_object_id_secrets",
        "runtime_resource_instances", "runtime_resource_instances_by_campaign",
        "runtime_bola_object_pairs", "runtime_bola_object_pairs_by_campaign",
        "runtime_ssrf_callbacks", "runtime_ssrf_callbacks_by_campaign",
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


def test_report_context_api9_includes_js_extraction_counters_and_safe_samples() -> None:
    _reset_store()
    _create_campaign()
    sanitized = "http://target.local/static/app.js"
    ref = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()[:16]
    obs = Observation(
        observation_id="obs_js_ex",
        campaign_id="cmp_report",
        type=ObservationType.js_endpoint_extraction_result,
        confidence=0.0,
        details={
            "source": "js_endpoint_extractor",
            "js_url_sanitized": sanitized,
            "source_js_ref": ref,
            "source_observation_id": "obs_src",
            "result": "route_fragments_found",
            "absolute_paths_count": 0,
            "route_fragments_count": 3,
            "route_fragments_matched_count": 0,
            "endpoints_extracted_count": 0,
            "endpoints_emitted_count": 0,
            "filtered_count": 1,
            "multi_match_skipped": 0,
            "fragment_no_graph_match": 3,
            "reason_codes": ["fragment_no_graph_match", "filtered_route_fragments"],
        },
    )
    memory_store.store_observation("obs_js_ex", "cmp_report", "", obs.model_dump(mode="json"))
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    api9 = ctx["owasp_coverage"]["API9_IMPROPER_INVENTORY_MANAGEMENT"]
    assert api9["js_endpoint_extraction_count"] == 1
    assert api9["js_route_fragments_count"] == 3
    assert api9["js_route_fragments_matched_count"] == 0
    assert api9["js_endpoints_emitted_count"] == 0
    assert len(api9["js_extraction_results"]) == 1
    sample = api9["js_extraction_results"][0]
    assert sample["js_url_sanitized"] == sanitized
    assert sample["source_js_ref"] == ref
    assert sample["result"] == "route_fragments_found"
    blob = json.dumps(sample, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "bearer ", "token=abc", "headers", "request_body", "response_body"):
        assert bad not in blob


def test_report_context_tool_failures_maps_error_type_message_and_stays_safe() -> None:
    _reset_store()
    _create_campaign()
    runtime = {
        "tool_failure_summaries": [
            {
                "iteration_index": 3,
                "candidate_kind": "undocumented_endpoint_validator",
                "tool_name": "undocumented_endpoint_validator",
                "tool_run_id": "toolrun_undoc_1",
                "status": "failed",
                "error_type": "response_too_large",
                "message": "HTTP response exceeded max_response_bytes.",
            }
        ],
        "executed_by_kind": {"undocumented_endpoint_validator": 2},
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    assert ctx is not None
    failures = ctx.get("tool_failures") or []
    assert len(failures) == 1
    row = failures[0]
    assert row.get("candidate_kind") == "undocumented_endpoint_validator"
    assert row.get("tool_run_id") == "toolrun_undoc_1"
    assert row.get("status") == "failed"
    assert row.get("iteration_index") == 3
    assert row.get("error_type") == "response_too_large"
    assert row.get("safe_message") == "HTTP response exceeded max_response_bytes."
    blob = json.dumps(row, ensure_ascii=False)
    for bad in ("Authorization", "Cookie", "Set-Cookie", "Bearer ", "token=", "request_body", "response_body", "raw_headers"):
        assert bad not in blob


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
    assert ctx["adaptive_planner_diagnostics"]["status"] == "not_available"
    assert ctx["adaptive_planner_diagnostics"]["reason"] == "planner_diagnostics_not_persisted"


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


def test_report_context_compact_attempt_summary_keeps_safe_ssrf_and_bola_attempts() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_attempt",
        "cmp_report",
        "toolrun_ssrf_1",
        Observation(
            observation_id="obs_ssrf_attempt",
            campaign_id="cmp_report",
            tool_run_id="toolrun_ssrf_1",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/hooks",
                "field_path": "$.callback_url",
                "auth_mode": "authenticated",
                "result": "no_callback",
                "target_status_code": 202,
                "callback_received": False,
                "evidence_strength": "low",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_bola_attempt",
        "cmp_report",
        "toolrun_bola_1",
        Observation(
            observation_id="obs_bola_attempt",
            campaign_id="cmp_report",
            tool_run_id="toolrun_bola_1",
            type=ObservationType.bola_replay_result,
            details={
                "validation_mode": "bola_replay",
                "target_operation_id": "op_GET_/vehicles/{vehicleId}",
                "object_pair_id": "objpair_1",
                "attacker_auth_profile_id": "authprof_attacker_1",
                "result": "invalid_object_pair",
                "status_code": 404,
                "access_granted": False,
                "owner_baseline_valid": True,
                "evidence_strength": "low",
            },
        ).model_dump(mode="json"),
    )

    runtime = {
        "iteration_summaries": [
            {"tool_run_id": "toolrun_ssrf_1", "candidate_kind": "ssrf_probe", "finding_id": ""},
            {"tool_run_id": "toolrun_bola_1", "candidate_kind": "bola_replay_probe", "finding_id": ""},
        ]
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    assert ctx is not None
    attempts = ctx["compact_attempt_summary"]
    assert len(attempts) >= 2
    ssrf = next(row for row in attempts if row["kind"] == "ssrf_probe")
    assert ssrf["operation_id"] == "op_POST_/hooks"
    assert ssrf["field_path"] == "$.callback_url"
    assert ssrf["result"] == "no_callback"
    assert ssrf["status_code"] == 202
    assert ssrf["callback_received"] is False
    bola = next(row for row in attempts if row["kind"] == "bola_replay_probe")
    assert bola["operation_id"] == "op_GET_/vehicles/{vehicleId}"
    assert bola["object_pair_id"] == "objpair_1"
    assert bola["result"] == "invalid_object_pair"
    assert bola["owner_baseline_valid"] is True
    blob = json.dumps({"attempts": attempts, "last": ctx["last_observation_summary"]}, ensure_ascii=False)
    for bad in ("Authorization", "Cookie", "request_body", "response_body", "raw_headers", "password", "object_id"):
        assert bad not in blob


def test_report_context_adaptive_planner_diagnostics_populated_safe_shape() -> None:
    _reset_store()
    _create_campaign()
    runtime = {
        "llm_planner_used": True,
        "llm_planner_fallback": "selected_kind",
        "llm_selected_candidate_id": "pcand_123",
        "llm_selected_kind": "ssrf_probe",
        "llm_selection_reason": "Prefer callback/contact endpoint after media candidate failed.",
        "iteration_summaries": [
            {
                "candidate_kind": "ssrf_probe",
                "selection_outcome": "llm_selected_kind",
                "selected_candidate_id": "pcand_123",
                "selection_reason": "safe reason",
            }
        ],
    }
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None
    assert ctx is not None
    diag = ctx["adaptive_planner_diagnostics"]
    assert diag["status"] == "available"
    assert diag["llm_planner_used_count"] >= 1
    assert diag["llm_planner_fallback_count"] >= 1
    assert diag["last_selected_candidate_id"] == "pcand_123"
    assert diag["last_selected_kind"] == "ssrf_probe"
    assert isinstance(diag["recent_selected_candidates"], list)
    assert diag["recent_selected_candidates"]
    row = diag["recent_selected_candidates"][0]
    assert set(row.keys()) == {"selected_candidate_id", "selected_kind", "decision", "fallback_used", "reason"}
    blob = json.dumps(diag, ensure_ascii=False)
    for bad in ("Authorization", "Cookie", "request_body", "response_body", "raw_headers", "password", "token="):
        assert bad not in blob


def test_report_context_includes_ssrf_payload_synthesis_diagnostics() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_diag",
        "cmp_report",
        "toolrun_ssrf_diag",
        Observation(
            observation_id="obs_ssrf_diag",
            campaign_id="cmp_report",
            tool_run_id="toolrun_ssrf_diag",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/api/contact",
                "method": "POST",
                "path": "/api/contact",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "request_composer": "deterministic",
                "request_draft_validated": False,
                "payload_synthesis_result": "schema_synthesized",
                "filled_required_fields_count": 3,
                "missing_required_fields_count": 1,
                "rejected_fields_count": 0,
                "synthesized_field_count": 4,
                "schema_summary_source": "api_graph",
                "reason_codes": ["required_secret_like_field_not_synthesized"],
                "target_status_code": 200,
                "callback_received": False,
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    sample = api7["ssrf_probe_results"][0]
    assert sample["payload_synthesis_result"] == "schema_synthesized"
    assert sample["filled_required_fields_count"] == 3
    assert sample["missing_required_fields_count"] == 1
    assert sample["synthesized_field_count"] == 4
    blob = json.dumps(sample, ensure_ascii=False).lower()
    for bad in ("body_json", "authorization", "cookie", "token", "password", "raw_body", "raw_headers"):
        assert bad not in blob


def test_report_context_includes_ssrf_probe_synthesis_counts() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_counts",
        "cmp_report",
        "toolrun_ssrf_counts",
        Observation(
            observation_id="obs_ssrf_counts",
            campaign_id="cmp_report",
            tool_run_id="toolrun_ssrf_counts",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/api/hooks",
                "field_path": "$.callback_url",
                "result": "target_4xx",
                "target_status_code": 400,
                "callback_received": False,
                "request_composer": "llm",
                "payload_synthesis_result": "llm_composed",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    assert api7["ssrf_probe_result_count"] >= 1
    assert api7["ssrf_probe_target_non_2xx_count"] >= 1
    assert api7["ssrf_probe_llm_composed_count"] >= 1


def test_report_context_includes_api7_planning_diagnostics() -> None:
    _reset_store()
    _create_campaign()
    runtime = {
        "stopped_reason": "no_ready_candidate",
        "ready_candidates_sample": [],
        "blocked_candidates_sample": [
            {
                "kind": "ssrf_probe",
                "operation_id": "op_PUT_/api/videos/{id}",
                "field_path": "$.video_url",
                "reason": "Path parameters require a corpus seed before SSRF callback probe.",
            }
        ],
    }
    memory_store.store_observation(
        "obs_ssrf_signal_diag",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_signal_diag",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "operation_id": "op_PUT_/api/videos/{id}",
                "method": "PUT",
                "path": "/api/videos/{id}",
                "field_name": "video_url",
                "field_path": "$.video_url",
                "confidence": "high",
                "schema_format": "uri",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None and ctx is not None
    diag = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]["api7_planning_diagnostics"]
    assert diag["ssrf_candidate_signal_count"] >= 1
    assert diag["ssrf_probe_ready_count"] == 0
    assert diag["ssrf_probe_blocked_count"] >= 1
    assert "reason" in diag


def test_report_context_includes_api7_ssrf_pipeline_trace() -> None:
    _reset_store()
    _create_campaign()
    runtime = {
        "stopped_reason": "no_ready_candidate",
        "ready_candidates_sample": [
            {
                "kind": "ssrf_probe",
                "candidate_id": "pcand_ready_1",
                "operation_id": "op_POST_/api/contact",
                "field_path": "$.callback_url",
                "reason": "ready",
            }
        ],
        "blocked_candidates_sample": [],
        "tool_failure_summaries": [],
        "llm_selected_candidate_id": "pcand_ready_1",
        "llm_selected_kind": "ssrf_probe",
        "selected_candidate_operation_id": "op_POST_/api/contact",
    }
    memory_store.store_observation(
        "obs_ssrf_trace",
        "cmp_report",
        "toolrun_ssrf_trace",
        Observation(
            observation_id="obs_ssrf_trace",
            campaign_id="cmp_report",
            tool_run_id="toolrun_ssrf_trace",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/api/contact",
                "field_path": "$.callback_url",
                "target_status_code": 400,
                "callback_received": False,
                "payload_synthesis_result": "schema_synthesized",
                "request_composer": "deterministic",
                "reason_codes": ["target_non_2xx"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report", runtime_state_snapshot=runtime)
    assert error is None and ctx is not None
    trace = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]["api7_ssrf_pipeline_trace"]
    assert trace["ssrf_candidate_signal_count"] >= 0
    assert trace["ready_ssrf_probe_count"] >= 1
    assert trace["selected_candidate_id"] == "pcand_ready_1"
    assert trace["ssrf_probe_result_emitted"] is True
    assert trace["report_context_has_ssrf_probe_results"] is True


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


def test_report_context_api7_includes_ssrf_probe_counters_and_samples() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_probe_1",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_probe_1",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_probe_result,
            details={
                "validation_mode": "ssrf_callback_probe",
                "operation_id": "op_POST_/api/v1/hooks",
                "method": "POST",
                "path": "/api/v1/hooks",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "auth_mode": "unauthenticated",
                "auth_profile_id": "",
                "role_hint": "",
                "correlation_id": "ssrf_1",
                "target_status_code": 200,
                "callback_received": True,
                "callback_method": "GET",
                "result": "callback_received",
                "evidence_strength": "high",
                "request_composer": "llm",
                "request_draft_validated": True,
                "payload_synthesis_result": "llm_composed",
                "synthesized_required_fields_count": 3,
                "rejected_fields_count": 0,
                "reason_codes": ["callback_received"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    assert api7["ssrf_probe_result_count"] == 1
    assert api7["ssrf_callback_received_count"] == 1
    assert api7["ssrf_no_callback_count"] == 0
    assert api7["ssrf_confirmable_count"] == 1
    assert len(api7["ssrf_probe_results"]) == 1
    sample = api7["ssrf_probe_results"][0]
    assert sample["request_composer"] == "llm"
    assert sample["request_draft_validated"] is True
    assert sample["payload_synthesis_result"] == "llm_composed"
    blob = json.dumps(api7, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "password", "bearer ", "token=", "body_json", "raw_headers"):
        assert bad not in blob


def test_report_context_reconciles_late_ssrf_callback() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_runtime_ssrf_callback(
        "ssrf_late_1",
        "cmp_report",
        {
            "correlation_id": "ssrf_late_1",
            "campaign_id": "cmp_report",
            "operation_id": "op_POST_/api/contact",
            "field_name": "callback_url",
            "field_path": "$.callback_url",
            "received": True,
            "callback_method": "GET",
            "headers_count": 6,
        },
    )
    memory_store.store_observation(
        "obs_ssrf_late",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_late",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/api/contact",
                "method": "POST",
                "path": "/api/contact",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "correlation_id": "ssrf_late_1",
                "target_status_code": 0,
                "callback_received": False,
                "payload_synthesis_result": "llm_composed",
                "evidence_strength": "low",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    sample = api7["ssrf_probe_results"][0]
    assert sample["callback_received"] is False
    assert sample["callback_received_effective"] is True
    assert sample["late_callback_reconciled"] is True
    assert sample["callback_store_received"] is True
    assert api7["ssrf_probe_callback_received_count"] >= 1
    assert api7["ssrf_probe_late_callback_reconciled_count"] >= 1
    blob = json.dumps(sample, ensure_ascii=False).lower()
    for bad in ("authorization", "cookie", "query=", "password", "token", "raw_headers", "raw_body"):
        assert bad not in blob


def test_report_context_counts_api7_confirmed_after_auto_judge() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_runtime_ssrf_callback(
        "ssrf_ctx_auto_1",
        "cmp_report",
        {
            "correlation_id": "ssrf_ctx_auto_1",
            "campaign_id": "cmp_report",
            "operation_id": "op_POST_/api/contact",
            "field_name": "callback_url",
            "field_path": "$.callback_url",
            "received": True,
            "callback_method": "GET",
            "headers_count": 6,
        },
    )
    memory_store.store_observation(
        "obs_ssrf_ctx_auto",
        "cmp_report",
        "toolrun_ssrf_ctx_auto",
        Observation(
            observation_id="obs_ssrf_ctx_auto",
            campaign_id="cmp_report",
            tool_run_id="toolrun_ssrf_ctx_auto",
            type=ObservationType.ssrf_probe_result,
            details={
                "operation_id": "op_POST_/api/contact",
                "method": "POST",
                "path": "/api/contact",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "correlation_id": "ssrf_ctx_auto_1",
                "target_status_code": 0,
                "callback_received": False,
                "evidence_strength": "low",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    assert api7["confirmed_findings_count"] >= 1
    assert api7["status"] == "confirmed"
    assert any(
        row.get("owasp_category") == "API7_SERVER_SIDE_REQUEST_FORGERY"
        and row.get("vulnerability_class") == "server_side_request_forgery"
        for row in (ctx.get("confirmed_findings") or [])
    )
    assert "confirmed_ssrf_evidence" in api7
    assert isinstance(api7["confirmed_ssrf_evidence"], list)


def test_report_context_api7_status_stays_diagnostic_without_confirmed_findings() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_diag",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_diag",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "operation_id": "op_POST_/hooks",
                "method": "POST",
                "path": "/hooks",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_format": "uri",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    assert api7["confirmed_findings_count"] == 0
    assert api7["status"] == "diagnostic"
    assert "подтверждение требует controlled callback proof" in str(api7.get("summary_text") or "")


def test_report_context_api9_counts_include_undocumented_endpoint_signal_and_findings() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_undoc_1",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_undoc_1",
            campaign_id="cmp_report",
            type=ObservationType.undocumented_endpoint_signal,
            details={
                "method": "GET",
                "path": "/api/hidden",
                "status_code": 200,
                "openapi_match": False,
                "is_static_asset": False,
            },
        ).model_dump(mode="json"),
    )
    finding = ConfirmedFinding(
        finding_id="finding_undoc_1",
        campaign_id="cmp_report",
        evidence_id="evp_undoc_1",
        decision_id="jdec_undoc_1",
        owasp_category="API9_IMPROPER_INVENTORY_MANAGEMENT",
        vulnerability_class="undocumented_api_endpoint",
        endpoint="/api/hidden",
        method="GET",
        title="Undocumented endpoint exposed",
        severity="low",
        summary="Runtime discovery reached an endpoint missing from OpenAPI.",
    )
    memory_store.store_confirmed_finding(
        finding.finding_id,
        finding.campaign_id,
        "fp_undoc_1",
        finding.model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id="evp_undoc_1",
        campaign_id="cmp_report",
        owasp_category="API9_IMPROPER_INVENTORY_MANAGEMENT",
        vulnerability_class="undocumented_api_endpoint",
        hypothesis="Runtime discovery observed an undocumented endpoint.",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["undocumented_endpoint_signal", "status_code:200", "openapi_match:false"],
    )
    memory_store.store_evidence_pack(
        "evp_undoc_1",
        "cmp_report",
        "obs_undoc_1",
        "",
        evidence.model_dump(mode="json"),
    )
    decision = JudgeDecisionRecord(
        decision_id="jdec_undoc_1",
        campaign_id="cmp_report",
        evidence_id="evp_undoc_1",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(
        decision.decision_id,
        "cmp_report",
        "evp_undoc_1",
        decision.model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    api9 = ctx["owasp_coverage"]["API9_IMPROPER_INVENTORY_MANAGEMENT"]
    assert api9["undocumented_endpoint_signal_count"] == 1
    assert api9["undocumented_endpoint_findings_count"] == 1


def test_report_context_api7_coverage_includes_ssrf_candidate_counts() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_1",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_1",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "operation_id": "op_POST_/api/v1/hooks",
                "method": "POST",
                "path": "/api/v1/hooks",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_type": "string",
                "schema_format": "uri",
                "validation_mode": "ssrf_candidate_detection",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    api7 = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]
    assert api7["ssrf_candidate_signal_count"] == 1
    assert api7["ssrf_candidate_operations_count"] == 1
    assert api7["ssrf_candidate_fields_count"] == 1
    assert api7["confirmed_findings_count"] == 0
    assert api7["ssrf_candidates"][0]["field_name"] == "callback_url"
    blob = json.dumps(api7, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "request_body", "response_body", "raw_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_report_context_api7_candidate_samples_prioritize_contact_like_over_image_like() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_ssrf_image",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_image",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "operation_id": "op_POST_/services/product-media",
                "method": "POST",
                "path": "/services/product-media",
                "field_name": "image_url",
                "field_path": "$.image_url",
                "schema_type": "string",
                "schema_format": "uri",
                "confidence": "high",
                "validation_mode": "ssrf_candidate_detection",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_ssrf_contact",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_ssrf_contact",
            campaign_id="cmp_report",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "operation_id": "op_POST_/services/contact-notify",
                "method": "POST",
                "path": "/services/contact-notify",
                "field_name": "callback_api",
                "field_path": "$.callback_api",
                "schema_type": "string",
                "schema_format": "uri",
                "confidence": "high",
                "validation_mode": "ssrf_candidate_detection",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    assert ctx is not None
    candidates = ctx["owasp_coverage"]["API7_SERVER_SIDE_REQUEST_FORGERY"]["ssrf_candidates"]
    assert len(candidates) >= 2
    assert candidates[0]["operation_id"] == "op_POST_/services/contact-notify"


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


def test_report_context_auth_flow_diagnostics_counts_and_safe_sample() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_af_rep",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_af_rep",
            campaign_id="cmp_report",
            type=ObservationType.auth_flow_signal,
            details={
                "source": "auth_flow_detector",
                "validation_mode": "auth_flow_detection",
                "auth_flow_detected": True,
                "signup_candidates": [
                    {"operation_id": "op_POST_/signup", "method": "POST", "path": "/signup", "confidence": "high", "reason_codes": ["path_signup_register"]},
                ],
                "login_candidates": [],
                "token_response_candidates": [],
                "profile_candidates": [],
                "missing_prerequisites": ["no_runtime_proof"],
                "reason_codes": [],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    diag = ctx.get("auth_flow_diagnostics") or {}
    assert diag.get("auth_flow_detected") is True
    assert diag.get("signup_candidate_count") == 1
    assert diag.get("login_candidate_count") == 0
    assert diag.get("token_response_candidate_count") == 0
    assert diag.get("profile_candidate_count") == 0
    assert len(diag.get("auth_flow_candidates_sample") or []) >= 1
    blob = json.dumps(diag, sort_keys=True).lower()
    for bad in ("password", "bearer ", "authorization", "secret", "token="):
        assert bad not in blob


def test_report_context_auth_flow_diagnostics_include_materialization_metadata_safely() -> None:
    _reset_store()
    _create_campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_report",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="secret-runtime-token",
        raw_credentials={"email": "vkr_owner@example.test", "password": "StrongPass!9"},
        created_by="test_account_materializer",
        metadata={"signup_operation_id": "op_signup", "login_operation_id": "op_login", "token_field_path": "$.token"},
    )
    memory_store.store_observation(
        "obs_authmat_rep",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_authmat_rep",
            campaign_id="cmp_report",
            type=ObservationType.test_account_materialization_result,
            details={
                "source": "test_account_materializer",
                "validation_mode": "test_account_materialization",
                "owner_auth_profile_id": profile.auth_profile_id,
                "attacker_auth_profile_id": "",
                "signup_success_count": 2,
                "login_success_count": 1,
                "auth_profiles_created_count": 1,
                "auth_type": "bearer",
                "token_response_detected": True,
                "materialization_errors": [{"stage": "login", "user_label": "attacker_user", "error_type": "token_not_found"}],
                "reason_codes": ["materialization_partial"],
                "materialization_reason_codes": ["materialization_partial", "possible_jwt_token_too_long"],
                "owner_signup_attempts_count": 2,
                "attacker_signup_attempts_count": 1,
                "owner_login_attempts_count": 2,
                "attacker_login_attempts_count": 0,
                "signup_retry_count": 1,
                "login_retry_count": 0,
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    diag = ctx.get("auth_flow_diagnostics") or {}
    assert diag.get("test_account_materialization_status") == "partial_or_failed"
    assert diag.get("auth_profiles_created_count") == 1
    assert diag.get("signup_success_count") == 2
    assert diag.get("login_success_count") == 1
    assert diag.get("owner_auth_profile_id") == profile.auth_profile_id
    assert diag.get("auth_type") == "bearer"
    assert diag.get("token_response_detected") is True
    assert len(diag.get("auth_profiles") or []) == 1
    assert diag.get("owner_signup_attempts_count") == 2
    assert diag.get("signup_retry_count") == 1
    assert "possible_jwt_token_too_long" in (diag.get("materialization_reason_codes") or [])
    blob = json.dumps(diag, sort_keys=True).lower()
    for bad in ("secret-runtime-token", "strongpass!9", "authorization", "cookie", "set-cookie", "bearer ", "response_body", "request_body"):
        assert bad not in blob


def test_report_context_materialization_selected_paths_and_status_codes() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_mat_paths",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_mat_paths",
            campaign_id="cmp_report",
            type=ObservationType.test_account_materialization_result,
            details={
                "source": "test_account_materializer",
                "validation_mode": "test_account_materialization",
                "signup_operation_id": "op_s",
                "login_operation_id": "op_l",
                "owner_auth_profile_id": "",
                "attacker_auth_profile_id": "",
                "signup_success_count": 2,
                "login_success_count": 0,
                "auth_profiles_created_count": 0,
                "auth_type": "unknown",
                "token_response_detected": False,
                "selected_signup_path": "/svc/api/auth/signup",
                "selected_login_path": "/svc/api/auth/login",
                "signup_response_status_codes": [201, 201],
                "login_response_status_codes": [403, 403],
                "login_payload_field_names": ["email", "password"],
                "reason_codes": ["materialization_failed", "login_http_403", "possible_invalid_credentials_or_wrong_login_endpoint"],
                "materialization_errors": [],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    diag = ctx.get("auth_flow_diagnostics") or {}
    assert diag.get("selected_signup_path") == "/svc/api/auth/signup"
    assert diag.get("selected_login_path") == "/svc/api/auth/login"
    assert diag.get("login_response_status_codes") == [403, 403]
    assert "login_http_403" in (diag.get("materialization_reason_codes") or [])
    blob = json.dumps(diag, sort_keys=True).lower()
    for bad in ("bearer ", "authorization", "set-cookie", "response_body", "request_body"):
        assert bad not in blob


def test_report_context_api3_data_exposure_counts_and_safe_samples() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_rfi_rep",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_rfi_rep",
            campaign_id="cmp_report",
            type=ObservationType.response_field_inventory,
            details={
                "tool_name": "data_exposure_validator",
                "operation_id": "op_GET_/api/users/{id}",
                "path": "/api/users/1",
                "method": "GET",
                "status_code": 200,
                "field_count": 5,
                "sensitive_field_count": 1,
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_dex_sig_rep",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_dex_sig_rep",
            campaign_id="cmp_report",
            type=ObservationType.data_exposure_signal,
            operation_id="op_GET_/api/users/{id}",
            details={
                "tool_name": "data_exposure_validator",
                "operation_id": "op_GET_/api/users/{id}",
                "path": "/api/users/1",
                "method": "GET",
                "status_code": 200,
                "sensitive_field_count": 2,
                "sensitive_categories": ["identity", "authorization"],
                "sensitive_fields": [
                    {"field_name": "email", "field_path": "$.email", "category": "identity"},
                    {"field_name": "role", "field_path": "$.role", "category": "authorization"},
                ],
            },
        ).model_dump(mode="json"),
    )
    finding = ConfirmedFinding(
        finding_id="finding_dex_api3",
        campaign_id="cmp_report",
        evidence_id="evp_dex_api3",
        decision_id="jdec_dex_api3",
        owasp_category="API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        vulnerability_class="sensitive_property_exposure",
        endpoint="/api/users/1",
        method="GET",
        title="Sensitive property exposure",
        severity="medium",
        summary="Response includes sensitive field names.",
        reproduction_pointer={"evidence_id": "evp_dex_api3", "replay_steps_count": 1},
    )
    memory_store.store_confirmed_finding(
        finding.finding_id,
        finding.campaign_id,
        "fp_dex_api3",
        finding.model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id="evp_dex_api3",
        campaign_id="cmp_report",
        owasp_category="API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
        vulnerability_class="sensitive_property_exposure",
        hypothesis="Field inventory indicates exposure risk.",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=["sensitive_field_count:2", "sensitive_field_name:email"],
    )
    memory_store.store_evidence_pack(
        "evp_dex_api3",
        "cmp_report",
        "obs_dex_sig_rep",
        "",
        evidence.model_dump(mode="json"),
    )
    decision = JudgeDecisionRecord(
        decision_id="jdec_dex_api3",
        campaign_id="cmp_report",
        evidence_id="evp_dex_api3",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(
        decision.decision_id,
        "cmp_report",
        "evp_dex_api3",
        decision.model_dump(mode="json"),
    )
    for idx, (res, status) in enumerate(
        (
            ("non_200_response", 403),
            ("non_json_response", 200),
            ("no_fields_found", 200),
            ("fields_extracted", 200),
            ("sensitive_fields_found", 200),
        ),
        start=1,
    ):
        memory_store.store_observation(
            f"obs_dex_probe_rep_{idx}",
            "cmp_report",
            "",
            Observation(
                observation_id=f"obs_dex_probe_rep_{idx}",
                campaign_id="cmp_report",
                type=ObservationType.data_exposure_probe_result,
                details={
                    "source": "data_exposure_validator",
                    "operation_id": f"op_probe_{idx}",
                    "method": "GET",
                    "path": f"/api/probe/{idx}",
                    "status_code": status,
                    "content_type": "application/json" if res != "non_json_response" else "text/html",
                    "result": res,
                    "field_count": 2 if res in {"fields_extracted", "sensitive_fields_found"} else 0,
                    "sensitive_field_count": 0,
                    "sensitive_categories": [],
                    "reason_codes": [res],
                },
            ).model_dump(mode="json"),
        )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["response_field_inventory_count"] == 1
    assert api3["data_exposure_signal_count"] == 1
    assert api3["data_exposure_probe_result_count"] == 5
    assert api3["data_exposure_non_200_count"] == 1
    assert api3["data_exposure_non_json_count"] == 1
    assert api3["data_exposure_no_fields_count"] == 1
    assert api3["data_exposure_fields_extracted_count"] == 2
    assert len(api3["data_exposure_probe_results"]) >= 1
    assert api3["data_exposure_probe_results"][0].get("operation_id")
    assert api3["data_exposure_probe_results"][0].get("result")
    assert "sensitive_fields" not in api3["data_exposure_probe_results"][0]
    assert api3["sensitive_property_exposure_findings_count"] == 1
    assert "identity" in api3["sensitive_field_categories"]
    assert "authorization" in api3["sensitive_field_categories"]
    assert any(s.get("field_name") == "email" for s in api3["sensitive_fields_sample"])
    assert len(api3["data_exposure_results"]) >= 1
    assert api3["blocked_no_sensitive_fields_count"] == "not_available"
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("response_body", "raw_body", "set-cookie", "bearer ", "token=", "secretvalue"):
        assert bad not in blob


def test_report_context_api3_includes_authenticated_data_exposure_counters_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_rfi_auth",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_rfi_auth",
            campaign_id="cmp_report",
            type=ObservationType.response_field_inventory,
            details={
                "tool_name": "data_exposure_validator",
                "operation_id": "op_GET_/api/v1/me",
                "path": "/api/v1/me",
                "method": "GET",
                "status_code": 200,
                "field_count": 4,
                "sensitive_field_count": 1,
                "auth_mode": "authenticated",
                "auth_profile_id": "authprof_owner_1",
                "role_hint": "owner",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_sig_auth",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_sig_auth",
            campaign_id="cmp_report",
            type=ObservationType.data_exposure_signal,
            details={
                "tool_name": "data_exposure_validator",
                "operation_id": "op_GET_/api/v1/me",
                "path": "/api/v1/me",
                "method": "GET",
                "status_code": 200,
                "sensitive_field_count": 1,
                "sensitive_categories": ["identity"],
                "auth_mode": "authenticated",
                "auth_profile_id": "authprof_owner_1",
                "role_hint": "owner",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_probe_auth",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_probe_auth",
            campaign_id="cmp_report",
            type=ObservationType.data_exposure_probe_result,
            details={
                "source": "data_exposure_validator",
                "operation_id": "op_GET_/api/v1/me",
                "method": "GET",
                "path": "/api/v1/me",
                "status_code": 200,
                "content_type": "application/json",
                "result": "fields_extracted",
                "field_count": 4,
                "sensitive_field_count": 1,
                "sensitive_categories": ["identity"],
                "reason_codes": ["fields_extracted"],
                "auth_mode": "authenticated",
                "auth_profile_id": "authprof_owner_1",
                "role_hint": "owner",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["authenticated_response_field_inventory_count"] == 1
    assert api3["authenticated_data_exposure_signal_count"] == 1
    assert api3["authenticated_data_exposure_probe_result_count"] == 1
    assert api3["data_exposure_authenticated_fields_extracted_count"] == 1
    assert api3["auth_profiles_used_count"] == 1
    assert api3["operations_with_authenticated_inventory"] == 1
    assert len(api3["authenticated_data_exposure_results"]) == 1
    sample = api3["authenticated_data_exposure_results"][0]
    assert sample["auth_mode"] == "authenticated"
    assert sample["auth_profile_id"] == "authprof_owner_1"
    assert sample["role_hint"] == "owner"
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("authorization", "bearer ", "token=", "response_body", "cookie", "set-cookie"):
        assert bad not in blob


def test_report_context_api3_authenticated_sensitive_fields_found_counts_as_extracted() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_probe_auth_sensitive_found",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_probe_auth_sensitive_found",
            campaign_id="cmp_report",
            type=ObservationType.data_exposure_probe_result,
            details={
                "source": "data_exposure_validator",
                "operation_id": "op_GET_/api/v1/me",
                "method": "GET",
                "path": "/api/v1/me",
                "status_code": 200,
                "content_type": "application/json",
                "result": "sensitive_fields_found",
                "field_count": 13,
                "sensitive_field_count": 3,
                "sensitive_categories": ["identity", "authorization"],
                "reason_codes": ["sensitive_fields_found"],
                "auth_mode": "authenticated",
                "auth_profile_id": "authprof_owner_1",
                "role_hint": "owner",
                "raw_secret_example": "secretvalue",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["authenticated_data_exposure_probe_result_count"] == 1
    assert api3["data_exposure_authenticated_fields_extracted_count"] == 1
    assert api3["auth_profiles_used_count"] == 1
    assert len(api3["authenticated_data_exposure_results"]) == 1
    assert api3["authenticated_data_exposure_results"][0]["result"] == "sensitive_fields_found"
    blob = json.dumps(api3, sort_keys=True).lower()
    assert "secretvalue" not in blob


def test_report_context_api3_includes_resource_instance_inventory_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_resource_inventory_report",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_resource_inventory_report",
            campaign_id="cmp_report",
            type=ObservationType.resource_instance_inventory,
            details={
                "source": "resource_instance_extractor",
                "validation_mode": "resource_instance_extraction",
                "source_observation_id": "obs_rfi_auth",
                "source_operation_id": "op_GET_/api/v1/me",
                "source_path": "/api/v1/me",
                "source_auth_profile_id": "authprof_owner_1",
                "source_role_hint": "owner",
                "resource_instances_count": 2,
                "resource_types": ["vehicle", "user"],
                "object_refs": [
                    {
                        "object_ref_id": "objref_vehicle_1",
                        "resource_type": "vehicle",
                        "object_id_field": "vehicleid",
                        "object_id_ref": "objidref_vehicle_1",
                        "confidence": "high",
                    },
                    {
                        "object_ref_id": "objref_user_1",
                        "resource_type": "user",
                        "object_id_field": "userId",
                        "object_id_ref": "objidref_user_1",
                        "confidence": "medium",
                    },
                ],
                "reason_codes": ["resource_ids_extracted"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["resource_instance_inventory_count"] == 1
    assert api3["resource_instances_count"] == 2
    assert api3["object_refs_count"] == 2
    assert api3["operations_with_resource_instances"] == 1
    assert "vehicle" in api3["resource_types"]
    assert len(api3["resource_instance_results"]) == 2
    aggregate_like = {"count", "total", "amount", "quantity", "price", "status", "page", "limit"}
    assert all(str(r.get("object_id_field") or "") not in aggregate_like for r in api3["resource_instance_results"])
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("veh-123", "user-7", "authorization", "cookie", "set-cookie", "token="):
        assert bad not in blob


def test_report_context_api3_includes_resource_seed_results_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_seed_report",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_seed_report",
            campaign_id="cmp_report",
            type=ObservationType.resource_seed_result,
            details={
                "validation_mode": "resource_seed",
                "seed_status": "seeded",
                "resource_type": "order",
                "owner_auth_profile_id": "authprof_owner_1",
                "seed_operation_id": "op_POST_/api/orders",
                "seed_method": "POST",
                "seed_path": "/api/orders",
                "followup_operation_id": "",
                "followup_method": "",
                "followup_path": "",
                "object_refs_created_count": 1,
                "object_refs": [{
                    "object_ref_id": "objref_order_1",
                    "object_id_ref": "objidref_order_1",
                    "object_id_field": "order_id",
                    "resource_type": "order",
                    "confidence": "high",
                }],
                "http_calls_count": 1,
                "reason_codes": ["resource_ids_extracted"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["resource_seed_result_count"] == 1
    assert api3["resource_seed_success_count"] == 1
    assert api3["resource_seed_object_refs_created_count"] == 1
    assert len(api3["resource_seed_results"]) == 1
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("ord-1", "authorization", "cookie", "set-cookie", "token="):
        assert bad not in blob


def test_report_context_api3_includes_bola_object_pair_inventory_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_bola_pair_inventory_report",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_bola_pair_inventory_report",
            campaign_id="cmp_report",
            type=ObservationType.bola_object_pair_inventory,
            details={
                "validation_mode": "bola_object_pair_building",
                "object_pairs_count": 1,
                "resource_types": ["vehicle"],
                "object_pairs": [{
                    "object_pair_id": "objpair_1",
                    "resource_type": "vehicle",
                    "object_ref_id": "objref_vehicle_1",
                    "object_id_ref": "objidref_vehicle_1",
                    "owner_auth_profile_id": "authprof_owner_1",
                    "attacker_auth_profile_id": "authprof_attacker_1",
                    "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                    "target_path_template": "/api/v1/vehicles/{vehicleId}",
                    "target_method": "GET",
                    "path_param_name": "vehicleId",
                    "confidence": "high",
                    "reason_codes": ["path_param_resource_match"],
                }],
                "reason_codes": ["object_pairs_built"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["bola_object_pair_inventory_count"] == 1
    assert api3["bola_object_pairs_count"] == 1
    assert api3["bola_replay_ready_count"] == 1
    assert "vehicle" in api3["bola_pair_resource_types"]
    assert len(api3["bola_object_pairs"]) == 1
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("veh-raw", "authorization", "cookie", "set-cookie", "token=", "password", "raw_body"):
        assert bad not in blob


def test_report_context_api3_includes_redirect_probe_result_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_probe_redirect_auth",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_probe_redirect_auth",
            campaign_id="cmp_report",
            type=ObservationType.data_exposure_probe_result,
            details={
                "source": "data_exposure_validator",
                "operation_id": "op_GET_/api/v1/me",
                "method": "GET",
                "path": "/api/v1/me",
                "status_code": 302,
                "content_type": "text/plain",
                "result": "redirect_response",
                "field_count": 0,
                "sensitive_field_count": 0,
                "sensitive_categories": [],
                "reason_codes": ["redirect_response", "redirect_not_followed", "redirect_host_not_allowed"],
                "auth_mode": "authenticated",
                "auth_profile_id": "authprof_owner_1",
                "role_hint": "owner",
                "redirect_same_origin": False,
                "redirect_followed": False,
                "redirect_count": 1,
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["authenticated_data_exposure_probe_result_count"] == 1
    assert len(api3["authenticated_data_exposure_results"]) == 1
    assert api3["authenticated_data_exposure_results"][0]["result"] == "redirect_response"
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=", "owner-token-secret"):
        assert bad not in blob


def test_report_context_api3_includes_bola_replay_results_safely() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_bola_replay_1",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_bola_replay_1",
            campaign_id="cmp_report",
            type=ObservationType.bola_replay_result,
            details={
                "validation_mode": "bola_replay",
                "object_pair_id": "objpair_1",
                "resource_type": "post",
                "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
                "target_path_template": "/community/api/v2/community/posts/{postId}",
                "target_method": "GET",
                "path_param_name": "postId",
                "attacker_auth_profile_id": "authprof_attacker_1",
                "owner_auth_profile_id": "authprof_owner_1",
                "status_code": 200,
                "result": "attacker_access_granted",
                "access_granted": True,
                "evidence_strength": "high",
                "reason_codes": ["owner_baseline_valid", "attacker_access_granted"],
                "owner_status_code": 200,
                "owner_result": "attacker_access_granted",
                "attacker_status_code": 200,
                "attacker_result": "attacker_access_granted",
                "replay_classification": "possible_bola",
                "owner_baseline_valid": True,
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_bola_replay_2",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_bola_replay_2",
            campaign_id="cmp_report",
            type=ObservationType.bola_replay_result,
            details={
                "validation_mode": "bola_replay",
                "object_pair_id": "objpair_2",
                "resource_type": "vehicle",
                "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                "target_path_template": "/api/v1/vehicles/{vehicleId}",
                "target_method": "GET",
                "path_param_name": "vehicleId",
                "attacker_auth_profile_id": "authprof_attacker_1",
                "owner_auth_profile_id": "authprof_owner_1",
                "status_code": 403,
                "result": "attacker_access_denied",
                "access_granted": False,
                "evidence_strength": "low",
                "reason_codes": ["owner_baseline_valid", "attacker_denied"],
                "owner_status_code": 200,
                "owner_result": "attacker_access_granted",
                "attacker_status_code": 403,
                "attacker_result": "attacker_access_denied",
                "replay_classification": "access_denied",
                "owner_baseline_valid": True,
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["bola_replay_result_count"] == 2
    assert api3["bola_replay_granted_count"] == 1
    assert api3["bola_replay_denied_count"] == 1
    assert api3["bola_replay_invalid_pair_count"] == 0
    assert api3["bola_replay_inconclusive_count"] == 0
    assert len(api3["bola_replay_results"]) == 2
    blob = json.dumps(api3, sort_keys=True).lower()
    for bad in ("post-123", "authorization", "cookie", "set-cookie", "token=", "password", "raw_body", "raw_headers"):
        assert bad not in blob


def test_report_context_api3_includes_resource_seed_attempt_counters() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_seed_attempts_1",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_seed_attempts_1",
            campaign_id="cmp_report",
            type=ObservationType.resource_seed_result,
            details={
                "validation_mode": "resource_seed",
                "seed_status": "seeded",
                "resource_seed_attempts_count": 3,
                "resource_seed_failed_count": 2,
                "resource_type": "vehicle",
                "owner_auth_profile_id": "authprof_owner_1",
                "seed_operation_id": "op_POST_/identity/api/v2/vehicle/add",
                "seed_method": "POST",
                "seed_path": "/identity/api/v2/vehicle/add",
                "object_refs_created_count": 1,
                "object_refs": [{"object_ref_id": "objref_1", "object_id_ref": "objidref_1", "object_id_field": "vehicleId", "resource_type": "vehicle", "confidence": "high"}],
                "http_calls_count": 2,
                "reason_codes": ["resource_ids_extracted"],
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["resource_seed_attempts_count"] == 3
    assert api3["resource_seed_failed_count"] == 2


def test_report_context_owasp_coverage_includes_api1_default_diagnostic() -> None:
    _reset_store()
    _create_campaign()
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None
    api1 = ctx["owasp_coverage"]["API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"]
    assert api1["status"] == "diagnostic"
    assert api1["confirmed_findings_count"] == 0
    assert api1["bola_replay_result_count"] == 0


def test_report_context_api1_confirmed_after_bola_finding() -> None:
    _reset_store()
    _create_campaign()
    finding = ConfirmedFinding(
        finding_id="finding_bola_1",
        campaign_id="cmp_report",
        evidence_id="evp_bola_1",
        decision_id="jdec_bola_1",
        owasp_category="API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        vulnerability_class="broken_object_level_authorization",
        endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        title="BOLA confirmed",
        severity="high",
        summary="Owner baseline and attacker replay succeeded on same object pair.",
    )
    memory_store.store_confirmed_finding(
        finding.finding_id,
        finding.campaign_id,
        "fp_bola_1",
        finding.model_dump(mode="json"),
    )
    evidence = EvidencePack(
        evidence_id="evp_bola_1",
        campaign_id="cmp_report",
        owasp_category="API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION",
        vulnerability_class="broken_object_level_authorization",
        operation_id="op_GET_/identity/api/v2/vehicle/{vehicleId}/location",
        endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        method="GET",
        hypothesis="Replay indicates BOLA.",
        status=EvidencePackStatus.ready_for_judge,
        judge_ready=True,
        derived_signals=[
            "object_pair_id:objpair_1",
            "owner_status_code:200",
            "attacker_status_code:200",
            "owner_baseline_valid:true",
            "access_granted:true",
            "replay_classification:possible_bola",
            "evidence_strength:high",
            "semantic_id_kind:vehicle_id",
        ],
    )
    memory_store.store_evidence_pack(
        "evp_bola_1",
        "cmp_report",
        "obs_bola_1",
        "",
        evidence.model_dump(mode="json"),
    )
    decision = JudgeDecisionRecord(
        decision_id="jdec_bola_1",
        campaign_id="cmp_report",
        evidence_id="evp_bola_1",
        verdict=JudgeVerdictKind.confirmed,
        reason="confirmed",
    )
    memory_store.store_judge_decision(
        decision.decision_id,
        "cmp_report",
        "evp_bola_1",
        decision.model_dump(mode="json"),
    )

    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api1 = ctx["owasp_coverage"]["API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"]
    assert api1["status"] == "confirmed"
    assert api1["confirmed_findings_count"] >= 1
    assert isinstance(api1["confirmed_bola_evidence"], list)
    assert api1["confirmed_bola_evidence"]
    row = api1["confirmed_bola_evidence"][0]
    assert row["evidence_id"] == "evp_bola_1"
    assert row["object_pair_id"] == "objpair_1"
    assert row["attacker_access_granted"] is True


def test_report_context_includes_bola_baseline_probability_diagnostics() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_bola_pair_diag",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_bola_pair_diag",
            campaign_id="cmp_report",
            type=ObservationType.bola_object_pair_inventory,
            details={
                "validation_mode": "bola_object_pair_building",
                "object_pairs_count": 1,
                "object_pairs": [{
                    "object_pair_id": "objpair_diag_1",
                    "resource_type": "vehicle",
                    "object_ref_id": "objref_1",
                    "object_id_ref": "objidref_1",
                    "owner_auth_profile_id": "authprof_owner_1",
                    "attacker_auth_profile_id": "authprof_attacker_1",
                    "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                    "target_path_template": "/api/v1/vehicles/{vehicleId}",
                    "target_method": "GET",
                    "path_param_name": "vehicleId",
                    "confidence": "high",
                    "metadata": {
                        "baseline_probability_score": 88.0,
                        "baseline_probability_reasons": ["consumer_method_get", "pair_confidence_high"],
                        "dependency_edge_confidence": "high",
                        "dependency_edge": {"param_location": "path"},
                    },
                }],
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_bola_replay_diag",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_bola_replay_diag",
            campaign_id="cmp_report",
            type=ObservationType.bola_replay_result,
            details={
                "validation_mode": "bola_replay",
                "object_pair_id": "objpair_diag_1",
                "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                "resource_type": "vehicle",
                "result": "invalid_object_pair",
                "owner_status_code": 400,
                "attacker_status_code": 0,
                "replay_classification": "invalid_object_pair",
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api1 = ctx["owasp_coverage"]["API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"]
    assert api1["top_object_pair_score"] >= 80
    assert api1["invalid_pair_rework_count"] >= 1
    compact = api1["api1_bola_compact_diagnostics"]
    assert compact["best_pair_operation_id"] == "op_GET_/api/v1/vehicles/{vehicleId}"
    assert compact["owner_baseline_status_code"] == 400


def test_report_context_api1_typed_object_ref_and_blocked_pair_counters() -> None:
    _reset_store()
    _create_campaign()
    memory_store.store_observation(
        "obs_resource_refs_typed",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_resource_refs_typed",
            campaign_id="cmp_report",
            type=ObservationType.resource_instance_inventory,
            details={
                "source": "resource_instance_extractor",
                "validation_mode": "resource_instance_extraction",
                "source_operation_id": "op_GET_/community/posts/recent",
                "source_path": "/community/posts/recent",
                "source_auth_profile_id": "authprof_owner_1",
                "source_role_hint": "owner",
                "resource_instances_count": 1,
                "object_refs": [{
                    "object_ref_id": "objref_typed_1",
                    "resource_type": "post",
                    "object_id_field": "id",
                    "object_id_ref": "objidref_typed_1",
                    "confidence": "high",
                    "id_json_path": "$.posts[0].id",
                    "semantic_id_kind": "post_id",
                    "source_status_code": 200,
                    "source_content_type": "application/json",
                    "owner_evidence": True,
                }],
                "reason_codes": ["resource_ids_extracted"],
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_pair_blocked",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_pair_blocked",
            campaign_id="cmp_report",
            type=ObservationType.bola_object_pair_inventory,
            details={
                "validation_mode": "bola_object_pair_building",
                "object_pairs_count": 1,
                "object_pairs": [{
                    "object_pair_id": "objpair_blocked_1",
                    "resource_type": "post",
                    "target_operation_id": "op_GET_/api/posts/{postId}",
                    "target_path_template": "/api/posts/{postId}",
                    "target_method": "GET",
                    "path_param_name": "postId",
                    "confidence": "low",
                    "metadata": {
                        "baseline_probability_score": 10.0,
                        "baseline_probability_reasons": ["path_param_semantic_mismatch"],
                        "baseline_block_reasons": ["object_id_field_semantic_mismatch"],
                    },
                }],
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_replay_granted_count",
        "cmp_report",
        "",
        Observation(
            observation_id="obs_replay_granted_count",
            campaign_id="cmp_report",
            type=ObservationType.bola_replay_result,
            details={
                "validation_mode": "bola_replay",
                "result": "attacker_access_granted",
                "access_granted": True,
                "owner_baseline_valid": True,
                "owner_status_code": 200,
                "attacker_status_code": 200,
            },
        ).model_dump(mode="json"),
    )
    ctx, error = ReportContextBuilder().build("cmp_report")
    assert error is None and ctx is not None
    api3 = ctx["owasp_coverage"]["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"]
    assert api3["api1_typed_object_ref_count"] >= 1
    assert api3["api1_owner_evidence_object_ref_count"] >= 1
    assert api3["api1_blocked_pair_count"] >= 1
    assert api3["api1_attacker_access_granted_count"] >= 1


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
