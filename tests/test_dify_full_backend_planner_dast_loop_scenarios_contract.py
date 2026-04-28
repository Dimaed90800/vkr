"""Phase 15C — Dify workflow contract for planner loop + ScenarioPlan snapshot."""
from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
LOOP_SCENARIOS = ROOT / "dify" / "wf-full-backend-planner-dast-loop-scenarios.yml"
LOOP_ORIGINAL = ROOT / "dify" / "wf-full-backend-planner-dast-loop.yml"


def _sc_text() -> str:
    return LOOP_SCENARIOS.read_text(encoding="utf-8")


def _sc_yaml() -> dict:
    return yaml.safe_load(_sc_text())


def _nodes() -> list[dict]:
    return _sc_yaml()["workflow"]["graph"]["nodes"]


def _nodes_by_id() -> dict[str, dict]:
    return {node["id"]: node for node in _nodes()}


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _edges() -> list[dict]:
    return _sc_yaml()["workflow"]["graph"]["edges"]


def _has_edge(source: str, target: str, source_handle: str | None = None) -> bool:
    for edge in _edges():
        if edge.get("source") != source or edge.get("target") != target:
            continue
        if source_handle is not None and edge.get("sourceHandle") != source_handle:
            continue
        return True
    return False


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def _is_in_loop(node_id: str) -> bool:
    node = _nodes_by_id()[node_id]
    return bool(node.get("parentId") == "main_loop_v1" and _node_data(node_id).get("isInLoop") is True)


def _run_code_node(node_id: str, **kwargs) -> dict:
    scope: dict[str, object] = {}
    exec(_node_data(node_id)["code"], scope)
    return scope["main"](**kwargs)


def test_loop_scenarios_workflow_exists() -> None:
    assert LOOP_SCENARIOS.exists()
    assert "wf-full-backend-planner-dast-loop-scenarios" in _sc_text()


def test_base_loop_workflow_still_exists() -> None:
    assert LOOP_ORIGINAL.exists()
    assert "wf-full-backend-planner-dast-loop" in LOOP_ORIGINAL.read_text(encoding="utf-8")


def test_loop_scenarios_calls_scenarios_plan_endpoint_once_before_loop() -> None:
    assert "/v1/scenarios/plan/{{#extract_campaign.campaign_id#}}" in _node_data("call_scenario_plan")["url"]
    assert _has_edge("init_loop_state", "emit_scenario_plan_request_body")
    assert _has_edge("emit_scenario_plan_request_body", "call_scenario_plan")
    assert _has_edge("call_scenario_plan", "merge_scenario_plan_into_planner_request")
    assert _has_edge("merge_scenario_plan_into_planner_request", "main_loop_v1")
    assert _has_edge("build_graph", "init_loop_state")


def test_has_openapi_spec_considers_openapi_url() -> None:
    norm = _node_data("normalize_inputs")["code"]
    assert "openapi_url_str" in norm
    assert "openapi_text.strip() or openapi_url_str" in norm


def test_build_graph_body_includes_openapi_url() -> None:
    body = _http_body("build_graph")
    assert "openapi_url" in body
    assert "openapi_url_json" in body
    assert "openapi_spec_text_json" in body


def test_skip_graph_when_no_openapi_text_or_url() -> None:
    norm = _node_data("normalize_inputs")["code"]
    assert "'has_openapi_spec': 'true' if (openapi_text.strip() or openapi_url_str) else 'false'" in norm


def test_scenario_plan_request_body_contains_max_operations_max_scenarios_llm_fields() -> None:
    code = _node_data("emit_scenario_plan_request_body")["code"]
    assert "max_operations" in code
    assert "max_scenarios" in code
    assert '"enabled"' in code or "'enabled'" in code
    assert "prompt_version" in code


def test_scenario_plan_error_degrades_to_base_planner_request() -> None:
    code = _node_data("merge_scenario_plan_into_planner_request")["code"]
    assert "scenario_plan_unavailable" in code
    assert '"include_scenario_compiler": False' in code or "'include_scenario_compiler': False" in code


def test_scenario_plan_merge_keeps_accepted_and_blocked_filters_rejected() -> None:
    code = _node_data("merge_scenario_plan_into_planner_request")["code"]
    assert "accepted" in code and "blocked" in code
    assert "rejected" in code


def test_planner_request_includes_scenario_plan_and_include_scenario_compiler() -> None:
    code = _node_data("merge_scenario_plan_into_planner_request")["code"]
    assert "scenario_plan" in code
    assert "include_scenario_compiler" in code


def test_planner_call_uses_effective_request_not_raw_normalize_inputs() -> None:
    body = _http_body("call_planner_candidates")
    assert "prepare_planner_body_from_state.body_json" in body
    assert "{{#normalize_inputs.planner_request_json#}}" not in body


def test_scenario_plan_called_outside_loop_not_inside_loop() -> None:
    assert not _is_in_loop("call_scenario_plan")
    assert not _is_in_loop("merge_scenario_plan_into_planner_request")
    assert not _is_in_loop("emit_scenario_plan_request_body")


def test_main_loop_still_contains_planner_run_normalize_triage() -> None:
    assert _is_in_loop("call_planner_candidates")
    assert _is_in_loop("prepare_planner_body_from_state")
    assert _is_in_loop("normalize_observations")
    assert _is_in_loop("triage_observation")


def test_fair_selection_defaults_raise_max_candidates_to_50() -> None:
    normalize_code = _node_data("normalize_inputs")["code"]
    merge_code = _node_data("merge_scenario_plan_into_planner_request")["code"]
    assert '"max_candidates": 50' in normalize_code
    assert '"max_candidates": 50' in merge_code


def test_init_loop_state_initializes_fair_selection_fields() -> None:
    code = _node_data("init_loop_state")["code"]
    for field in (
        '"kind_caps"',
        '"executed_by_kind"',
        '"skipped_by_kind_cap_count"',
        '"ready_candidates_by_kind_count"',
        '"ready_candidates_sample"',
        '"last_selection_outcome"',
        '"tool_failures_count"',
        '"failed_by_kind"',
        '"tool_failure_summaries"',
        '"last_tool_error_type"',
        '"last_tool_error_safe_message"',
        '"max_tool_failures_total"',
        '"max_tool_failures_by_kind"',
        '"max_tool_failures_total": 5',
        '"max_tool_failures_by_kind": 3',
        '"property_mutation_test": 2',
        '"injection_test": 2',
        '"schemathesis_negative_test": 4',
        '"cors_validator": 1',
        '"cookie_flag_validator": 1',
        '"js_endpoint_extractor": 1',
        '"auth_flow_detector": 1',
        '"test_account_materializer": 1',
        '"ssrf_candidate_detector": 2',
        '"undocumented_endpoint_validator": 2',
        '"data_exposure_validator": 8',
        '"resource_instance_extractor": 3',
        '"resource_seed_worker": 3',
        '"bola_object_pair_builder": 2',
        '"bola_replay_probe": 5',
        '"security_header_validator": 3',
    ):
        assert field in code


def test_init_loop_state_kind_caps_includes_bola_replay_probe() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"bola_replay_probe": 5' in code


def test_select_ready_candidate_uses_fair_selection_state_and_caps_exhausted() -> None:
    code = _node_data("select_ready_candidate")["code"]
    for needle in (
        "state_json",
        "kind_caps",
        "executed_by_kind",
        "skipped_by_kind_cap_count",
        "selection_outcome",
        "caps_exhausted",
        "skipped_by_kind_cap_delta",
        "blocked_candidates_sample_json",
        "blocked_candidates_count_total",
        "blocked_candidates_by_kind_count_json",
        "ready_candidates_sample_json",
        "ready_candidates_by_kind_count_json",
        "MAX_BLOCKED_CANDIDATE_SAMPLE",
        "MAX_READY_CANDIDATE_SAMPLE",
    ):
        assert needle in code


def test_stop_no_ready_candidate_records_cap_exhaustion_without_incrementing_executed_by_kind() -> None:
    code = _node_data("stop_no_ready_candidate")["code"]
    assert "caps_exhausted" in code
    assert "skipped_by_kind_cap_count" in code
    assert "selection_outcome" in code
    assert "state[\"executed_by_kind\"]" not in code
    assert "_increment_executed" not in code


def test_record_no_observations_updates_executed_by_kind() -> None:
    code = _node_data("record_no_observations")["code"]
    assert "_increment_executed" in code
    assert 'state["executed_by_kind"] = merged' in code


def test_record_finding_created_updates_executed_by_kind() -> None:
    code = _node_data("record_finding_created")["code"]
    assert "_increment_executed" in code
    assert 'state["executed_by_kind"] = merged' in code


def test_record_pending_verification_updates_executed_by_kind() -> None:
    code = _node_data("record_pending_verification")["code"]
    assert "_increment_executed" in code
    assert 'state["executed_by_kind"] = merged' in code


def test_stop_tool_failed_updates_executed_by_kind() -> None:
    code = _node_data("stop_tool_failed")["code"]
    assert "_increment_executed" in code
    assert 'state["executed_by_kind"] = merged' in code
    assert "tool_failures_count" in code
    assert "failed_by_kind" in code
    assert "too_many_tool_failures" in code
    assert "tool_failure_summaries" in code


def test_extract_tool_run_exposes_safe_failure_fields() -> None:
    code = _node_data("extract_tool_run")["code"]
    for needle in (
        "tool_error_type",
        "tool_error_safe_message",
        "tool_error_count",
        "tool_name",
        "_clean_message",
    ):
        assert needle in code


def test_loop_scenarios_preserves_evidence_capable_types() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'bola_replay_result'" in code
    assert "'cross_role_access_signal'" in code
    assert "'validated_security_header_issue'" in code
    assert "'schema_mismatch'" in code


def test_loop_scenarios_preserves_pending_only_types() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'zap_alert'" in code
    assert "'discovered_endpoint'" in code
    pending_block = code.split("is_pending_only = obs_type in {", 1)[1].split("}", 1)[0]
    assert "'injection_signal'" not in pending_block


def test_loop_scenarios_observation_priority_includes_schema_mismatch() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "strong_bola = [" in code
    assert "obs.get('type') == 'bola_replay_result'" in code
    assert "owner_baseline_valid" in code
    assert "access_granted" in code
    assert "evidence_strength" in code
    assert "schema = [obs for obs in observations if obs.get('type') == 'schema_mismatch']" in code
    assert "strong_bola[0] if strong_bola else (" in code
    assert "validated_headers[0] if validated_headers else (" in code
    assert "schema[0] if schema else (" in code


def test_loop_scenarios_observation_priority_prefers_strong_bola_before_schema() -> None:
    code = _node_data("summarize_observations")["code"]
    idx_bola = code.find("strong_bola[0] if strong_bola else (")
    idx_schema = code.find("schema[0] if schema else (")
    assert idx_bola != -1 and idx_schema != -1 and idx_bola < idx_schema


def test_loop_scenarios_summary_includes_bola_replay_counters() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "'bola_replay_result_count'" in code
    assert "'strong_bola_replay_count'" in code


def test_loop_scenarios_schema_mismatch_is_evidence_capable() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'schema_mismatch'" in code
    assert "is_evidence_capable = obs_type in {" in code
    assert "'validated_security_header_issue'" in code
    assert "'cross_role_access_signal'" in code


def test_loop_scenarios_schema_mismatch_removed_from_pending_only() -> None:
    code = _node_data("route_by_observation_type")["code"]
    pending_block = code.split("is_pending_only = obs_type in {", 1)[1].split("}", 1)[0]
    assert "'schema_mismatch'" not in pending_block


def test_loop_scenarios_schema_mismatch_reaches_build_evidence_pack_tail() -> None:
    assert _has_edge("route_by_observation_type", "is_evidence_capable")
    assert _has_edge("is_evidence_capable", "build_evidence_pack", source_handle="true")
    assert _has_edge("build_evidence_pack", "compact_evidence_for_judge")


def test_loop_scenarios_schema_mismatch_without_verification_plan_stays_pending() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "has_plan = bool(str(verification_plan_id or '').strip())" in code
    assert "'schema_mismatch'" in code
    assert "} and has_plan" in code
    evidence_set = code.split("is_evidence_capable = obs_type in {", 1)[1].split(
        "} and has_plan", 1
    )[0]
    assert "'bola_replay_result'" in evidence_set
    assert "'schema_mismatch'" in evidence_set
    assert "verification_route': 'evidence_judge_apply' if is_evidence_capable else 'pending_verification'" in code
    assert _has_edge("is_evidence_capable", "record_pending_verification", source_handle="false")


def test_loop_scenarios_judge_prompt_has_schema_contract_guidance() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "For bola / bola_replay_result runtime evidence" in prompt
    assert "owner_baseline_valid=true" in prompt
    assert "access_granted=true" in prompt
    assert "evidence_strength is medium or high" in prompt
    assert "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION" in prompt
    assert "vulnerability_class=bola" in prompt
    assert "object_pair_id" in prompt
    assert "target_path_template" in prompt
    assert "replay_classification" in prompt
    assert "api_schema_contract_violation / schema_mismatch evidence" in prompt
    assert "tool_name:schemathesis_negative_test" in prompt
    assert "signal:5xx" in prompt
    assert "signal:schema_violation" in prompt
    assert "signal:unexpected_2xx" in prompt


def test_loop_scenarios_schema_contract_prompt_does_not_require_bola_proof() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert (
        "do not require BOLA baseline, ownership proof, diff, or request_ref for this class."
        in prompt
    )


def test_loop_scenarios_compact_judge_input_includes_schema_contract_fields() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    assert "strong_schema_signals" in code
    assert "schema_contract_interpretation" in code
    assert "tool_run_ids" in code
    assert "observation_id" in code


def test_loop_scenarios_judge_prompt_schema_contract_rework_policy() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"].lower()
    assert "rework only if operation context" in prompt
    assert "reject or inconclusive" in prompt


def test_loop_scenarios_judge_prompt_does_not_rework_schema_for_missing_bola_refs() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"].lower()
    assert "do not use absence of baseline" in prompt


def test_loop_scenarios_schema_contract_compact_input_has_no_raw_body_headers_tokens() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    for bad in ("request_body", "response_body", "Authorization", "Cookie:", "Bearer "):
        assert bad not in code


def test_loop_scenarios_judge_prompt_forbids_raw_bola_secrets_and_substituted_urls() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "raw object ids" in prompt
    assert "raw substituted URLs" in prompt
    assert "raw HTTP bodies" in prompt
    assert "raw headers" in prompt
    assert "tokens, passwords, cookies, or Authorization values" in prompt


def test_loop_scenarios_observation_priority_includes_injection_signal() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "injection = [obs for obs in observations if obs.get('type') == 'injection_signal']" in code
    assert "injection[0] if injection else (" in code
    idx_inj = code.find("injection[0]")
    idx_zap = code.find("alerts[0]")
    assert idx_inj != -1 and idx_zap != -1 and idx_inj < idx_zap


def test_loop_scenarios_injection_signal_is_evidence_capable_with_plan() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'injection_signal'" in code
    assert "has_plan = bool(str(verification_plan_id or '').strip())" in code
    evidence_set = code.split("is_evidence_capable = obs_type in {", 1)[1].split(
        "} and has_plan", 1
    )[0]
    assert "'injection_signal'" in evidence_set


def test_loop_scenarios_injection_signal_without_plan_stays_pending_or_non_evidence() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'injection_signal'" in code
    assert "} and has_plan" in code
    pending_block = code.split("is_pending_only = obs_type in {", 1)[1].split("}", 1)[0]
    assert "'injection_signal'" not in pending_block


def test_loop_scenarios_judge_prompt_has_injection_policy() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "potential_injection / injection_signal" in prompt
    assert "injection_strong_signals" in prompt
    assert "baseline_attack_delta" in prompt


def test_loop_scenarios_injection_compact_input_has_no_raw_payload_body_headers_tokens() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    assert "potential_injection" in code
    assert "injection_strong_signals" in code
    for bad in ("request_body", "response_body", "Authorization", "Cookie:", "Bearer ", "payload_raw"):
        assert bad not in code


def test_final_report_contains_compact_scenario_summary() -> None:
    code = _node_data("build_final_report")["code"]
    for key in (
        "scenario_plan_source",
        "scenario_plan_graph_empty",
        "scenarios_total",
        "accepted_scenarios_count",
        "blocked_scenarios_count",
        "rejected_scenarios_count",
        "scenario_types",
        "scenario_plan_warnings_sample",
        "blocked_candidates_count_total",
        "blocked_candidates_sample",
    ):
        assert key in code


def test_final_report_includes_fair_selection_observability() -> None:
    code = _node_data("build_final_report")["code"]
    for key in (
        "kind_caps",
        "executed_by_kind",
        "skipped_by_kind_cap_count",
        "tool_failures_count",
        "failed_by_kind",
        "tool_failure_summaries",
        "last_tool_error_type",
        "last_tool_error_safe_message",
        "max_tool_failures_total",
        "max_tool_failures_by_kind",
        "last_selection_outcome",
        "ready_candidates_by_kind_count",
        "ready_candidates_sample",
    ):
        assert key in code


def test_final_report_does_not_include_full_scenario_plan_or_rationale() -> None:
    code = _node_data("build_final_report")["code"]
    assert "rationale" not in code.lower()
    assert "planner_request_effective_json" not in code
    assert "command_json" not in code
    assert "state.get('scenario_plan'" not in code
    assert "json.dumps(state.get('scenarios" not in code


def test_state_does_not_include_openapi_spec_text_tokens_headers_cookies_bodies() -> None:
    init_code = _node_data("init_loop_state")["code"]
    merge_code = _node_data("merge_scenario_plan_into_planner_request")["code"]
    for needle in ("openapi_spec_text", "Authorization", "Cookie", "request_body", "response_body"):
        assert needle not in init_code
    assert "openapi_spec_text" not in merge_code


def test_no_legacy_scheduler_wrappers_corpus_add() -> None:
    t = _sc_text()
    for bad in ("task_scheduler", "TaskScheduler", "corpus_add", "legacy_scheduler"):
        assert bad not in t


def test_command_and_verdict_object_interpolation_preserved() -> None:
    body_cmd = _http_body("run_selected_command")
    assert '"command": {{#select_ready_candidate.command_json#}}' in body_cmd
    body_ver = _http_body("apply_judge_verdict")
    assert '"verdict": {{#parse_judge_verdict.judge_verdict_json#}}' in body_ver


def test_include_scenario_compiler_start_input_default_true() -> None:
    start_vars = _node_data("start")["variables"]
    names = [v.get("variable") for v in start_vars]
    assert "include_scenario_compiler" in names
    assert "profile" in names
    norm = _node_data("normalize_inputs")["code"]
    assert "inc_scen = _bool_str(include_scenario_compiler, 'true')" in norm


def test_scenario_llm_start_inputs_default_safe_stub() -> None:
    norm = _node_data("normalize_inputs")["code"]
    assert "scen_llm = _bool_str(scenario_llm_enabled, 'false')" in norm
    emit = _node_data("emit_scenario_plan_request_body")["code"]
    assert "llm_on" in emit


def test_existing_loop_yaml_scenario_compat_smoke_only() -> None:
    """Smoke check only.

    TODO: Re-enable running tests/test_dify_full_backend_planner_dast_loop_contract.py
    once base-loop YAML is synchronized with its own contract suite.
    """
    orig = LOOP_ORIGINAL.read_text(encoding="utf-8")
    assert "merge_scenario_plan_into_planner_request" not in orig
    assert "call_scenario_plan" not in orig


def test_loop_seed_and_final_state_use_merged_scenario_state() -> None:
    lv = _node_data("main_loop_v1")["loop_variables"]
    assert lv[0]["value"] == ["merge_scenario_plan_into_planner_request", "state_json"]
    vars_ = _node_data("final_loop_state")["variables"]
    seed = next(v for v in vars_ if v.get("variable") == "seed_state_json")
    assert seed["value_selector"] == ["merge_scenario_plan_into_planner_request", "state_json"]


def test_normalize_inputs_safe_profile_defaults_to_35_iterations() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="",
        profile="safe",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["profile"] == "safe"
    assert result["max_iterations"] == "35"


def test_normalize_inputs_missing_profile_uses_project_default_safe() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="",
        profile="",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["profile"] == "safe"
    assert result["max_iterations"] == "35"


def test_normalize_inputs_balanced_profile_defaults_to_55_iterations() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="",
        profile="balanced",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["profile"] == "balanced"
    assert result["max_iterations"] == "55"


def test_normalize_inputs_workflow_encodes_safe_35_balanced_55_profile_iteration_defaults() -> None:
    code = _node_data("normalize_inputs")["code"]
    assert '"safe": 35' in code
    assert '"balanced": 55' in code
    assert '"aggressive": 70' in code


def test_normalize_inputs_aggressive_profile_defaults_to_70_iterations() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="",
        profile="aggressive",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["profile"] == "aggressive"
    assert result["max_iterations"] == "70"


def test_normalize_inputs_clamps_explicit_max_iterations_to_80() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="999",
        profile="balanced",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["max_iterations"] == "80"


def test_normalize_inputs_invalid_or_missing_max_iterations_use_profile_default() -> None:
    invalid = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="not-a-number",
        profile="balanced",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    missing = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="",
        profile="balanced",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert invalid["max_iterations"] == "55"
    assert missing["max_iterations"] == "55"


def test_normalize_inputs_respects_explicit_valid_max_iterations() -> None:
    result = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json="",
        task_id="",
        judge_model="",
        max_iterations="42",
        profile="safe",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    assert result["max_iterations"] == "42"


def test_default_planner_request_includes_enable_llm_candidate_advisor_false() -> None:
    norm = _node_data("normalize_inputs")["code"]
    merge = _node_data("merge_scenario_plan_into_planner_request")["code"]
    assert '"enable_llm_candidate_advisor": False' in norm
    assert '"enable_llm_candidate_advisor": False' in merge


def test_effective_planner_request_preserves_enable_cors_baseline_true_when_custom_request_omits_it() -> None:
    normalized = _run_code_node(
        "normalize_inputs",
        toolbox_url="http://toolbox.local",
        target_url="http://target.local",
        openapi_spec_text="",
        openapi_url="",
        allowed_hosts_json='["target.local"]',
        roles_json="[]",
        planner_request_json=json.dumps({"zap": {"enabled": False}}, ensure_ascii=False),
        task_id="",
        judge_model="",
        max_iterations="",
        profile="safe",
        include_scenario_compiler="true",
        scenario_max_operations="120",
        scenario_max_scenarios="30",
        scenario_llm_enabled="false",
        scenario_llm_model="",
        scenario_prompt_version="scenario-planner/v1",
    )
    init_state = _run_code_node(
        "init_loop_state",
        campaign_id="cmp_profile",
        max_iterations=normalized["max_iterations"],
        planner_request_json=normalized["planner_request_json"],
        profile=normalized["profile"],
        include_scenario_compiler="true",
    )
    merged = _run_code_node(
        "merge_scenario_plan_into_planner_request",
        init_state_json=init_state["state_json"],
        scenario_http_body="{}",
        normalize_planner_request_json=normalized["planner_request_json"],
        include_scenario_compiler_flag="true",
    )
    state = json.loads(merged["state_json"])
    effective = json.loads(state["planner_request_effective_json"])
    assert effective["enable_cors_baseline"] is True
    assert effective["enable_cookie_baseline"] is True
    assert effective.get("enable_llm_candidate_advisor") is False


def test_select_ready_candidate_skips_capped_first_ready_and_picks_next_kind() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_inj",
                        "kind": "injection_test",
                        "status": "ready",
                        "command": {"tool_name": "injection_test"},
                    },
                    {
                        "candidate_id": "cand_prop",
                        "kind": "property_mutation_test",
                        "status": "ready",
                        "command": {"tool_name": "property_mutation_test"},
                    },
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "injection_test": 2,
                    "property_mutation_test": 2,
                },
                "executed_by_kind": {
                    "injection_test": 2,
                },
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "property_mutation_test"
    assert result["selection_outcome"] == "selected_ready"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {"injection_test": 1}
    assert int(result["blocked_candidates_count_total"]) == 0
    assert json.loads(result["blocked_candidates_sample_json"]) == []


def test_select_ready_candidate_extracts_blocked_candidates_sample_with_allowlist() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_blocked_mass",
                        "kind": "property_mutation_test",
                        "status": "blocked",
                        "reason": "Property_mutation_test blocked: no mass-assignment sensitive fields selected.",
                        "missing_inputs": ["no_writable_sensitive_fields"],
                        "summary": {
                            "operation_id": "op_POST_/community/api/v2/community/posts/{postId}/comment",
                            "scenario_type": "mass_assignment",
                            "mass_assignment_candidate_result": "blocked_no_sensitive_fields",
                            "audit_flags": ["no_sensitive_fields", "missing_seed_context"],
                            "fields_considered_count": 1,
                            "fields_selected_count": 0,
                            "seed_request_id_present": False,
                            "reason_codes": ["no_writable_sensitive_fields", "missing_seed_context"],
                        },
                        "command": {"inputs": {"headers": {"Authorization": "Bearer secret"}}},
                    },
                    {
                        "candidate_id": "cand_ready_inj",
                        "kind": "injection_test",
                        "status": "ready",
                        "command": {"tool_name": "injection_test"},
                    },
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"injection_test": 2},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "injection_test"
    assert result["selection_outcome"] == "selected_ready"
    assert int(result["blocked_candidates_count_total"]) >= 1
    by_kind = json.loads(result["blocked_candidates_by_kind_count_json"])
    assert by_kind.get("property_mutation_test") == 1
    sample = json.loads(result["blocked_candidates_sample_json"])
    assert isinstance(sample, list) and sample
    row = sample[0]
    assert row["kind"] == "property_mutation_test"
    assert row["status"] == "blocked"
    assert row["mass_assignment_candidate_result"] == "blocked_no_sensitive_fields"
    assert row["fields_selected_count"] == 0
    assert row["seed_request_id_present"] is False
    assert set(row.keys()) == {
        "kind",
        "status",
        "operation_id",
        "scenario_type",
        "reason",
        "missing_inputs",
        "audit_flags",
        "mass_assignment_candidate_result",
        "fields_considered_count",
        "fields_selected_count",
        "seed_request_id_present",
        "reason_codes",
        "undocumented_candidate_source",
        "js_candidate_source",
        "ssrf_candidate_source",
        "js_url_sanitized",
        "source_observation_id",
        "validation_mode",
        "candidate_field_count",
        "candidate_fields_sample",
        "confidence",
        "field_name",
        "field_path",
        "schema_format",
        "max_endpoints",
        "openapi_match",
        "is_static_asset",
        "data_exposure_candidate_source",
        "auth_mode",
        "auth_profile_id",
        "role_hint",
        "prior_unauth_status_code",
        "prior_unauth_result",
        "operations_with_authenticated_inventory",
        "path_template",
        "field_count",
        "sensitive_field_count",
        "sensitive_categories",
        "llm_candidate_advisor_used",
        "llm_candidate_priority",
        "llm_candidate_reason",
        "llm_requires_seed",
        "llm_requires_auth",
        "auth_flow_detected",
        "signup_candidate_count",
        "login_candidate_count",
        "token_response_candidate_count",
        "profile_candidate_count",
        "auth_candidate_source",
        "test_account_materialization_status",
        "auth_profiles_created_count",
        "signup_success_count",
        "login_success_count",
            "owner_auth_profile_id",
            "attacker_auth_profile_id",
            "auth_type",
            "token_response_detected",
            "resource_instance_candidate_source",
            "resource_seed_candidate_source",
            "bola_pair_candidate_source",
            "seed_status",
            "object_pairs_count",
            "bola_replay_ready_count",
            "bola_pair_resource_types",
            "object_pairs",
            "object_pair_id",
        "bola_replay_candidate_source",
        "target_operation_id",
        "target_path_template",
        "target_method",
        "path_param_name",
        "status_code",
        "result",
        "access_granted",
        "evidence_strength",
        "response_fingerprint_match",
            "source_operation_id",
            "source_path",
            "source_auth_profile_id",
            "source_role_hint",
            "seed_operation_id",
            "seed_method",
            "seed_path",
            "followup_operation_id",
            "followup_method",
            "followup_path",
            "resource_instances_count",
            "object_refs_count",
            "object_refs_created_count",
            "resource_types",
            "object_refs",
            "http_calls_count",
            "object_ref_id",
            "object_id_ref",
            "object_id_field",
            "resource_type",
            "confidence",
            "materialization_errors",
            "auth_profiles",
        }


def test_select_ready_candidate_extracts_ready_candidates_sample_js_first_among_contract_and_surface_ready() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_inj",
                        "kind": "injection_test",
                        "status": "ready",
                        "reason": "Injection replay candidate ready.",
                        "summary": {
                            "operation_id": "op_GET_/search",
                            "scenario_type": "injection",
                            "reason_codes": ["baseline_available"],
                            "audit_flags": ["query_param"],
                        },
                        "command": {
                            "tool_name": "injection_test",
                            "worker_class": "contract_fuzzing",
                            "strategy": "validate_injection_impact",
                            "inputs": {"headers": {"Authorization": "Bearer secret"}, "request_body": "boom"},
                        },
                    },
                    {
                        "candidate_id": "cand_cors",
                        "kind": "cors_validator",
                        "status": "ready",
                        "reason": "Baseline CORS validation candidate generated from safe campaign/passive context.",
                        "summary": {
                            "operation_id": "",
                            "scenario_type": "",
                            "cors_candidate_source": "baseline",
                            "validation_mode": "baseline_cors_check",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "cors_validator",
                            "worker_class": "misconfiguration",
                            "strategy": "validate_cors_policy",
                            "inputs": {"cookie": "secret=value", "token": "leak"},
                        },
                    },
                    {
                        "candidate_id": "cand_undoc",
                        "kind": "undocumented_endpoint_validator",
                        "status": "ready",
                        "reason": "Discovered runtime endpoint is outside the OpenAPI graph and eligible for safe validation.",
                        "summary": {
                            "operation_id": "",
                            "scenario_type": "",
                            "undocumented_candidate_source": "zap_spider",
                            "validation_mode": "one_shot_undocumented_endpoint_check",
                            "openapi_match": False,
                            "is_static_asset": False,
                            "audit_flags": [],
                            "reason_codes": ["undocumented_path"],
                        },
                        "command": {
                            "tool_name": "undocumented_endpoint_validator",
                            "worker_class": "discovery_inventory",
                            "strategy": "validate_undocumented_endpoint",
                            "inputs": {"request_body": "ignore"},
                        },
                    },
                    {
                        "candidate_id": "cand_js_extract",
                        "kind": "js_endpoint_extractor",
                        "status": "ready",
                        "reason": "Discovered in-scope JavaScript asset is eligible for safe endpoint extraction.",
                        "summary": {
                            "js_candidate_source": "zap_spider",
                            "js_url_sanitized": "http://target.local/static/app.js",
                            "source_observation_id": "obs_js_1",
                            "validation_mode": "static_js_endpoint_extraction",
                            "max_endpoints": 50,
                            "reason_codes": [],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "js_endpoint_extractor",
                            "worker_class": "discovery_inventory",
                            "strategy": "extract_js_endpoints",
                            "inputs": {"request_body": "ignore"},
                        },
                    },
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"injection_test": 2, "cors_validator": 1, "undocumented_endpoint_validator": 2, "js_endpoint_extractor": 1},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "js_endpoint_extractor"
    ready_by_kind = json.loads(result["ready_candidates_by_kind_count_json"])
    assert ready_by_kind == {"injection_test": 1, "cors_validator": 1, "undocumented_endpoint_validator": 1, "js_endpoint_extractor": 1}
    sample = json.loads(result["ready_candidates_sample_json"])
    assert len(sample) == 4
    assert sample[0]["kind"] == "js_endpoint_extractor"
    assert sample[0]["tool_name"] == "js_endpoint_extractor"
    assert sample[0]["worker_class"] == "discovery_inventory"
    assert sample[0]["strategy"] == "extract_js_endpoints"
    assert set(sample[0].keys()) == {
        "kind",
        "status",
        "operation_id",
        "scenario_type",
        "reason",
        "tool_name",
        "worker_class",
        "strategy",
        "cors_candidate_source",
        "cookie_candidate_source",
        "undocumented_candidate_source",
        "js_candidate_source",
        "ssrf_candidate_source",
        "js_url_sanitized",
        "source_observation_id",
        "validation_mode",
        "candidate_field_count",
        "candidate_fields_sample",
        "confidence",
        "field_name",
        "field_path",
        "schema_format",
        "max_endpoints",
        "openapi_match",
        "is_static_asset",
        "audit_flags",
        "reason_codes",
        "fields_selected_count",
        "seed_request_id_present",
        "mass_assignment_candidate_result",
        "data_exposure_candidate_source",
        "auth_mode",
        "auth_profile_id",
        "role_hint",
        "prior_unauth_status_code",
        "prior_unauth_result",
        "operations_with_authenticated_inventory",
        "path_template",
        "field_count",
        "sensitive_field_count",
        "sensitive_categories",
        "llm_candidate_advisor_used",
        "llm_candidate_priority",
        "llm_candidate_reason",
        "llm_requires_seed",
        "llm_requires_auth",
        "auth_flow_detected",
        "signup_candidate_count",
        "login_candidate_count",
        "token_response_candidate_count",
        "profile_candidate_count",
        "auth_candidate_source",
        "test_account_materialization_status",
        "auth_profiles_created_count",
        "signup_success_count",
        "login_success_count",
            "owner_auth_profile_id",
            "attacker_auth_profile_id",
            "auth_type",
            "token_response_detected",
            "resource_instance_candidate_source",
            "resource_seed_candidate_source",
            "bola_pair_candidate_source",
            "seed_status",
            "object_pairs_count",
            "bola_replay_ready_count",
            "bola_pair_resource_types",
            "object_pairs",
            "object_pair_id",
        "bola_replay_candidate_source",
        "target_operation_id",
        "target_path_template",
        "target_method",
        "path_param_name",
        "status_code",
        "result",
        "access_granted",
        "evidence_strength",
        "response_fingerprint_match",
            "source_operation_id",
            "source_path",
            "source_auth_profile_id",
            "source_role_hint",
            "seed_operation_id",
            "seed_method",
            "seed_path",
            "followup_operation_id",
            "followup_method",
            "followup_path",
            "resource_instances_count",
            "object_refs_count",
            "object_refs_created_count",
            "resource_types",
            "object_refs",
            "http_calls_count",
            "object_ref_id",
            "object_id_ref",
            "object_id_field",
            "resource_type",
            "confidence",
            "materialization_errors",
            "auth_profiles",
        }
    blob = json.dumps(sample, ensure_ascii=False).lower()
    for bad in ("authorization", "set-cookie", "request_body", "response_body", "raw_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_select_ready_candidate_ready_sample_includes_cookie_candidate_source() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_cookie",
                        "kind": "cookie_flag_validator",
                        "status": "ready",
                        "reason": "Baseline cookie flag validation candidate generated from safe campaign/passive context.",
                        "summary": {
                            "operation_id": "",
                            "scenario_type": "",
                            "cookie_candidate_source": "baseline",
                            "validation_mode": "baseline_cookie_flag_check",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "cookie_flag_validator",
                            "worker_class": "misconfiguration",
                            "strategy": "validate_cookie_flags",
                            "inputs": {"headers": {"Cookie": "secret=value"}},
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"cookie_flag_validator": 1},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    sample = json.loads(result["ready_candidates_sample_json"])
    assert sample[0]["kind"] == "cookie_flag_validator"
    assert sample[0]["cookie_candidate_source"] == "baseline"
    assert sample[0]["validation_mode"] == "baseline_cookie_flag_check"


def test_select_ready_candidate_ready_sample_includes_undocumented_candidate_fields() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_undoc",
                        "kind": "undocumented_endpoint_validator",
                        "status": "ready",
                        "reason": "Discovered runtime endpoint is outside the OpenAPI graph and eligible for safe validation.",
                        "summary": {
                            "undocumented_candidate_source": "zap_spider",
                            "validation_mode": "one_shot_undocumented_endpoint_check",
                            "openapi_match": False,
                            "is_static_asset": False,
                            "reason_codes": ["undocumented_path"],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "undocumented_endpoint_validator",
                            "worker_class": "discovery_inventory",
                            "strategy": "validate_undocumented_endpoint",
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"undocumented_endpoint_validator": 2},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    sample = json.loads(result["ready_candidates_sample_json"])
    assert sample[0]["kind"] == "undocumented_endpoint_validator"
    assert sample[0]["undocumented_candidate_source"] == "zap_spider"
    assert sample[0]["validation_mode"] == "one_shot_undocumented_endpoint_check"
    assert sample[0]["openapi_match"] is False
    assert sample[0]["is_static_asset"] is False


def test_select_ready_candidate_ready_sample_includes_js_extractor_fields() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_js_1",
                        "kind": "js_endpoint_extractor",
                        "status": "ready",
                        "reason": "Discovered in-scope JavaScript asset is eligible for safe endpoint extraction.",
                        "summary": {
                            "js_candidate_source": "zap_spider",
                            "js_url_sanitized": "http://target.local/static/app.js",
                            "source_observation_id": "obs_js_1",
                            "validation_mode": "static_js_endpoint_extraction",
                            "max_endpoints": 50,
                            "reason_codes": [],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "js_endpoint_extractor",
                            "worker_class": "discovery_inventory",
                            "strategy": "extract_js_endpoints",
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"js_endpoint_extractor": 1},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    sample = json.loads(result["ready_candidates_sample_json"])
    assert sample[0]["kind"] == "js_endpoint_extractor"
    assert sample[0]["js_candidate_source"] == "zap_spider"
    assert sample[0]["js_url_sanitized"] == "http://target.local/static/app.js"
    assert sample[0]["source_observation_id"] == "obs_js_1"
    assert sample[0]["validation_mode"] == "static_js_endpoint_extraction"
    assert sample[0]["max_endpoints"] == 50


def test_init_loop_state_kind_caps_includes_data_exposure_validator() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"data_exposure_validator": 8' in code


def test_init_loop_state_kind_caps_includes_ssrf_candidate_detector() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"ssrf_candidate_detector": 2' in code


def test_init_loop_state_kind_caps_includes_auth_flow_detector() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"auth_flow_detector": 1' in code


def test_init_loop_state_kind_caps_includes_test_account_materializer() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"test_account_materializer": 1' in code


def test_init_loop_state_kind_caps_includes_resource_instance_extractor() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"resource_instance_extractor": 3' in code


def test_init_loop_state_kind_caps_includes_resource_seed_worker() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"resource_seed_worker": 3' in code


def test_init_loop_state_kind_caps_includes_bola_object_pair_builder() -> None:
    code = _node_data("init_loop_state")["code"]
    assert '"bola_object_pair_builder": 2' in code


def test_select_ready_candidate_kind_priority_orders_data_exposure_before_api8_and_property_mutation() -> None:
    code = _node_data("select_ready_candidate")["code"]
    kpi = code.find("KIND_PRIORITY = [")
    assert kpi != -1
    bracket_end = code.find("]", kpi)
    prio_block = code[kpi:bracket_end]
    dex = prio_block.index("data_exposure_validator")
    assert dex < prio_block.index("injection_test")
    assert dex < prio_block.index("security_header_validator")
    assert dex < prio_block.index("cors_validator")
    assert dex < prio_block.index("cookie_flag_validator")
    assert dex < prio_block.index("property_mutation_test")


def test_select_ready_candidate_kind_priority_places_resource_instance_after_data_exposure_and_before_undocumented_and_api8() -> None:
    code = _node_data("select_ready_candidate")["code"]
    kpi = code.find("KIND_PRIORITY = [")
    assert kpi != -1
    bracket_end = code.find("]", kpi)
    prio_block = code[kpi:bracket_end]
    dexi = prio_block.index("data_exposure_validator")
    resi = prio_block.index("resource_instance_extractor")
    undi = prio_block.index("undocumented_endpoint_validator")
    shi = prio_block.index("security_header_validator")
    assert dexi < resi < undi
    assert resi < shi


def test_select_ready_candidate_kind_priority_places_resource_seed_between_resource_instance_and_undocumented() -> None:
    code = _node_data("select_ready_candidate")["code"]
    kpi = code.find("KIND_PRIORITY = [")
    assert kpi != -1
    bracket_end = code.find("]", kpi)
    prio_block = code[kpi:bracket_end]
    resi = prio_block.index("resource_instance_extractor")
    seedi = prio_block.index("resource_seed_worker")
    undi = prio_block.index("undocumented_endpoint_validator")
    assert resi < seedi < undi


def test_select_ready_candidate_kind_priority_places_bola_pair_builder_between_seed_and_bola_replay() -> None:
    code = _node_data("select_ready_candidate")["code"]
    kpi = code.find("KIND_PRIORITY = [")
    assert kpi != -1
    bracket_end = code.find("]", kpi)
    prio_block = code[kpi:bracket_end]
    seedi = prio_block.index("resource_seed_worker")
    pairi = prio_block.index("bola_object_pair_builder")
    bolai = prio_block.index("bola_replay_probe")
    undi = prio_block.index("undocumented_endpoint_validator")
    assert seedi < pairi < bolai < undi


def test_select_ready_candidate_kind_priority_places_ssrf_after_bola_replay_and_before_undocumented() -> None:
    code = _node_data("select_ready_candidate")["code"]
    kpi = code.find("KIND_PRIORITY = [")
    assert kpi != -1
    bracket_end = code.find("]", kpi)
    prio_block = code[kpi:bracket_end]
    jsi = prio_block.index("js_endpoint_extractor")
    afi = prio_block.index("auth_flow_detector")
    tami = prio_block.index("test_account_materializer")
    dexi = prio_block.index("data_exposure_validator")
    resi = prio_block.index("resource_seed_worker")
    bolai = prio_block.index("bola_replay_probe")
    ssrfi = prio_block.index("ssrf_candidate_detector")
    undi = prio_block.index("undocumented_endpoint_validator")
    assert jsi < afi < tami < dexi < resi < bolai < ssrfi < undi


def test_select_ready_candidate_safe_samples_include_data_exposure_allowlist_fields() -> None:
    code = _node_data("select_ready_candidate")["code"]
    for needle in (
        "'data_exposure_candidate_source'",
        "'auth_mode'",
        "'auth_profile_id'",
        "'role_hint'",
        "'prior_unauth_status_code'",
        "'prior_unauth_result'",
        "'operations_with_authenticated_inventory'",
        "'path_template'",
        "'field_count'",
        "'sensitive_field_count'",
        "'sensitive_categories'",
        "'llm_candidate_advisor_used'",
        "'llm_candidate_priority'",
        "'llm_candidate_reason'",
        "'llm_requires_seed'",
        "'llm_requires_auth'",
        "'resource_instance_candidate_source'",
        "'source_observation_id'",
        "'source_operation_id'",
        "'source_path'",
        "'source_auth_profile_id'",
        "'source_role_hint'",
        "'resource_instances_count'",
        "'object_refs_count'",
        "'resource_types'",
        "'object_ref_id'",
        "'object_id_ref'",
        "'object_id_field'",
        "'resource_type'",
        "'resource_seed_candidate_source'",
        "'bola_pair_candidate_source'",
        "'seed_status'",
        "'object_pairs_count'",
        "'bola_replay_ready_count'",
        "'bola_pair_resource_types'",
        "'object_pairs'",
        "'object_pair_id'",
        "'bola_replay_candidate_source'",
        "'target_operation_id'",
        "'target_path_template'",
        "'target_method'",
        "'path_param_name'",
        "'status_code'",
        "'result'",
        "'access_granted'",
        "'evidence_strength'",
        "'response_fingerprint_match'",
        "'seed_operation_id'",
        "'seed_method'",
        "'seed_path'",
        "'followup_operation_id'",
        "'followup_method'",
        "'followup_path'",
        "'object_refs_created_count'",
        "'object_refs'",
        "'http_calls_count'",
    ):
        assert needle in code
    assert "def _safe_ready" in code
    assert "def _safe_blocked" in code


def test_select_ready_candidate_safe_samples_include_ssrf_allowlist_fields() -> None:
    code = _node_data("select_ready_candidate")["code"]
    for needle in (
        "'ssrf_candidate_source'",
        "'candidate_field_count'",
        "'candidate_fields_sample'",
        "'confidence'",
        "'field_name'",
        "'field_path'",
        "'schema_format'",
    ):
        assert needle in code


def test_select_ready_candidate_safe_samples_include_auth_flow_allowlist_fields() -> None:
    code = _node_data("select_ready_candidate")["code"]
    for needle in (
        "'auth_flow_detected'",
        "'signup_candidate_count'",
        "'login_candidate_count'",
        "'token_response_candidate_count'",
        "'profile_candidate_count'",
        "'auth_candidate_source'",
    ):
        assert needle in code


def test_select_ready_candidate_safe_samples_include_test_account_materializer_allowlist_fields() -> None:
    code = _node_data("select_ready_candidate")["code"]
    for needle in (
        "'test_account_materialization_status'",
        "'auth_profiles_created_count'",
        "'signup_success_count'",
        "'login_success_count'",
        "'owner_auth_profile_id'",
        "'attacker_auth_profile_id'",
        "'auth_type'",
        "'token_response_detected'",
        "'materialization_errors'",
        "'auth_profiles'",
    ):
        assert needle in code


def test_select_ready_candidate_prefers_auth_flow_detector_before_data_exposure_validator() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {
                            "operation_id": "op_GET_/api/profile",
                            "validation_mode": "response_field_inventory_check",
                            "data_exposure_candidate_source": "openapi_graph",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                    {
                        "candidate_id": "c_af",
                        "kind": "auth_flow_detector",
                        "status": "ready",
                        "reason": "OpenAPI graph available for diagnostic auth-flow candidate detection.",
                        "summary": {
                            "validation_mode": "auth_flow_detection",
                            "operation_id": "",
                            "path_template": "",
                            "method": "N/A",
                            "data_source": "openapi_graph",
                            "auth_flow_detected": True,
                            "signup_candidate_count": 1,
                            "login_candidate_count": 0,
                            "token_response_candidate_count": 0,
                            "profile_candidate_count": 1,
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "auth_flow_detector",
                            "worker_class": "auth_context",
                            "strategy": "detect_auth_flow",
                        },
                    },
                ],
                "ready_count": "2",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"auth_flow_detector": 1, "data_exposure_validator": 5},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "auth_flow_detector"
    sample = json.loads(result["ready_candidates_sample_json"])
    af_row = next(r for r in sample if r.get("kind") == "auth_flow_detector")
    assert af_row["tool_name"] == "auth_flow_detector"
    assert af_row["validation_mode"] == "auth_flow_detection"
    assert af_row["auth_candidate_source"] == "openapi_graph"
    assert af_row["signup_candidate_count"] == 1
    assert af_row["token_response_candidate_count"] == 0
    assert af_row["audit_flags"] == []


def test_select_ready_candidate_prefers_test_account_materializer_before_data_exposure_validator() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {
                            "operation_id": "op_GET_/api/profile",
                            "validation_mode": "response_field_inventory_check",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                    {
                        "candidate_id": "c_tam",
                        "kind": "test_account_materializer",
                        "status": "ready",
                        "reason": "materialize",
                        "summary": {
                            "validation_mode": "test_account_materialization",
                            "test_account_materialization_status": "pending",
                            "auth_profiles_created_count": 0,
                            "signup_success_count": 0,
                            "login_success_count": 0,
                            "owner_auth_profile_id": "",
                            "attacker_auth_profile_id": "",
                            "auth_type": "bearer",
                            "token_response_detected": False,
                            "materialization_errors": [],
                            "auth_profiles": [],
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "test_account_materializer",
                            "worker_class": "auth_context",
                            "strategy": "materialize_test_accounts",
                        },
                    },
                ],
                "ready_count": "2",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"test_account_materializer": 1, "data_exposure_validator": 5},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "test_account_materializer"
    sample = json.loads(result["ready_candidates_sample_json"])
    tam_row = next(r for r in sample if r.get("kind") == "test_account_materializer")
    assert tam_row["test_account_materialization_status"] == "pending"
    assert tam_row["auth_profiles_created_count"] == 0
    assert tam_row["token_response_detected"] is False


def test_select_ready_candidate_prefers_auth_flow_detector_over_materializer_and_data_exposure_when_all_ready() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {"operation_id": "op_GET_/api/profile", "audit_flags": [], "reason_codes": []},
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                    {
                        "candidate_id": "c_tam",
                        "kind": "test_account_materializer",
                        "status": "ready",
                        "reason": "materialize",
                        "summary": {"audit_flags": [], "reason_codes": []},
                        "command": {
                            "tool_name": "test_account_materializer",
                            "worker_class": "auth_context",
                            "strategy": "materialize_test_accounts",
                        },
                    },
                    {
                        "candidate_id": "c_af",
                        "kind": "auth_flow_detector",
                        "status": "ready",
                        "reason": "graph",
                        "summary": {"audit_flags": [], "reason_codes": []},
                        "command": {
                            "tool_name": "auth_flow_detector",
                            "worker_class": "auth_context",
                            "strategy": "detect_auth_flow",
                        },
                    },
                ],
                "ready_count": "3",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "auth_flow_detector": 1,
                    "test_account_materializer": 1,
                    "data_exposure_validator": 5,
                },
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "auth_flow_detector"


def test_select_ready_candidate_prefers_data_exposure_validator_before_property_mutation_when_both_ready() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_pm",
                        "kind": "property_mutation_test",
                        "status": "ready",
                        "reason": "ready",
                        "summary": {"operation_id": "op_PATCH_/x"},
                        "command": {
                            "tool_name": "property_mutation_test",
                            "worker_class": "access_control",
                            "strategy": "validate_mass_assignment_impact",
                        },
                    },
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {
                            "operation_id": "op_GET_/api/profile",
                            "data_exposure_candidate_source": "openapi_graph",
                            "path_template": "/api/profile",
                            "validation_mode": "response_field_inventory_check",
                            "field_count": 5,
                            "sensitive_field_count": 2,
                            "sensitive_categories": ["identity"],
                            "reason_codes": [],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                ],
                "ready_count": "2",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"property_mutation_test": 2, "data_exposure_validator": 5},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "data_exposure_validator"
    sample = json.loads(result["ready_candidates_sample_json"])
    dex_row = next(r for r in sample if r.get("kind") == "data_exposure_validator")
    assert dex_row["data_exposure_candidate_source"] == "openapi_graph"
    assert dex_row["path_template"] == "/api/profile"
    assert dex_row["validation_mode"] == "response_field_inventory_check"
    assert dex_row["field_count"] == 5
    assert dex_row["sensitive_field_count"] == 2
    assert dex_row["sensitive_categories"] == ["identity"]
    blob = json.dumps(sample, ensure_ascii=False).lower()
    for bad in ("authorization", "set-cookie", "request_body", "response_body", "bearer ", "token="):
        assert bad not in blob


def test_select_ready_candidate_ready_sample_includes_ssrf_candidate_fields() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_ssrf",
                        "kind": "ssrf_candidate_detector",
                        "status": "ready",
                        "reason": "OpenAPI operation contains URL-like request fields that are SSRF-relevant candidates.",
                        "summary": {
                            "operation_id": "op_POST_/workshop/api/mechanic/receive_report",
                            "ssrf_candidate_source": "openapi_schema",
                            "validation_mode": "ssrf_candidate_detection",
                            "candidate_field_count": 1,
                            "candidate_fields_sample": [
                                {
                                    "field_name": "mechanic_api",
                                    "field_path": "$.mechanic_api",
                                    "schema_format": "uri",
                                    "confidence": "high",
                                    "reason_codes": ["url_like_field_name", "schema_format_uri"],
                                }
                            ],
                            "reason_codes": ["url_like_field_name", "schema_format_uri"],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "ssrf_candidate_detector",
                            "worker_class": "input_validation",
                            "strategy": "detect_ssrf_candidate_fields",
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"ssrf_candidate_detector": 2},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "ssrf_candidate_detector"
    sample = json.loads(result["ready_candidates_sample_json"])
    row = sample[0]
    assert row["kind"] == "ssrf_candidate_detector"
    assert row["tool_name"] == "ssrf_candidate_detector"
    assert row["worker_class"] == "input_validation"
    assert row["strategy"] == "detect_ssrf_candidate_fields"
    assert row["ssrf_candidate_source"] == "openapi_schema"
    assert row["candidate_field_count"] == 1
    assert row["candidate_fields_sample"][0]["field_name"] == "mechanic_api"
    assert row["candidate_fields_sample"][0]["field_path"] == "$.mechanic_api"
    assert row["candidate_fields_sample"][0]["schema_format"] == "uri"
    assert row["candidate_fields_sample"][0]["confidence"] == "high"


def test_select_ready_candidate_prefers_data_exposure_validator_before_ssrf_candidate_detector() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {"operation_id": "op_GET_/api/profile"},
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                    {
                        "candidate_id": "c_ssrf",
                        "kind": "ssrf_candidate_detector",
                        "status": "ready",
                        "reason": "ssrf-diagnostic",
                        "summary": {"operation_id": "op_POST_/api/hooks"},
                        "command": {
                            "tool_name": "ssrf_candidate_detector",
                            "worker_class": "input_validation",
                            "strategy": "detect_ssrf_candidate_fields",
                        },
                    },
                ],
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"ssrf_candidate_detector": 2, "data_exposure_validator": 5},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "data_exposure_validator"


def test_select_ready_candidate_prefers_data_exposure_validator_before_security_header_validator_when_both_ready() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_sh",
                        "kind": "security_header_validator",
                        "status": "ready",
                        "reason": "baseline",
                        "summary": {
                            "operation_id": "op_GET_/api/health",
                            "validation_mode": "baseline_security_header_check",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "security_header_validator",
                            "worker_class": "misconfiguration",
                            "strategy": "validate_security_headers",
                        },
                    },
                    {
                        "candidate_id": "c_dex",
                        "kind": "data_exposure_validator",
                        "status": "ready",
                        "reason": "openapi_get_inventory",
                        "summary": {
                            "operation_id": "op_GET_/workshop/api/shop/orders/{order_id}",
                            "path_template": "/workshop/api/shop/orders/{order_id}",
                            "data_exposure_candidate_source": "openapi_graph",
                            "validation_mode": "response_field_inventory_check",
                            "field_count": 0,
                            "sensitive_field_count": 0,
                            "sensitive_categories": [],
                            "reason_codes": [],
                            "audit_flags": [],
                        },
                        "command": {
                            "tool_name": "data_exposure_validator",
                            "worker_class": "access_control",
                            "strategy": "validate_response_field_exposure",
                        },
                    },
                ],
                "ready_count": "2",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"security_header_validator": 3, "data_exposure_validator": 5},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "data_exposure_validator"
    assert result["selection_outcome"] == "selected_ready"


def test_select_ready_candidate_prefers_resource_instance_extractor_before_undocumented_endpoint_validator() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "c_undoc",
                        "kind": "undocumented_endpoint_validator",
                        "status": "ready",
                        "reason": "undocumented-runtime-check",
                        "summary": {
                            "operation_id": "op_GET_/api/hidden",
                            "undocumented_candidate_source": "discovered_endpoint",
                            "validation_mode": "one_shot_undocumented_endpoint_check",
                            "audit_flags": [],
                            "reason_codes": [],
                        },
                        "command": {
                            "tool_name": "undocumented_endpoint_validator",
                            "worker_class": "discovery_inventory",
                            "strategy": "validate_undocumented_endpoint",
                        },
                    },
                    {
                        "candidate_id": "c_resource",
                        "kind": "resource_instance_extractor",
                        "status": "ready",
                        "reason": "authenticated inventory available",
                        "summary": {
                            "source_observation_id": "obs_rfi_auth_1",
                            "source_operation_id": "op_GET_/api/me",
                            "source_path": "/api/me",
                            "source_auth_profile_id": "authprof_owner_1",
                            "source_role_hint": "owner",
                            "resource_instance_candidate_source": "authenticated_inventory",
                            "resource_instances_count": 0,
                            "object_refs_count": 0,
                            "resource_types": ["vehicle"],
                            "validation_mode": "resource_instance_extraction",
                            "audit_flags": [],
                            "reason_codes": ["authenticated_inventory_available"],
                        },
                        "command": {
                            "tool_name": "resource_instance_extractor",
                            "worker_class": "auth_context",
                            "strategy": "extract_resource_instances",
                        },
                    },
                ],
                "ready_count": "2",
                "blocked_count": "0",
                "skipped_existing_count": "0",
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"resource_instance_extractor": 2, "undocumented_endpoint_validator": 2},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "resource_instance_extractor"
    sample = json.loads(result["ready_candidates_sample_json"])
    row = next(r for r in sample if r.get("kind") == "resource_instance_extractor")
    assert row["source_observation_id"] == "obs_rfi_auth_1"
    assert row["source_operation_id"] == "op_GET_/api/me"
    assert row["source_auth_profile_id"] == "authprof_owner_1"
    assert row["resource_instance_candidate_source"] == "authenticated_inventory"
    assert row["resource_types"] == ["vehicle"]


def test_select_ready_candidate_caps_blocked_candidates_sample_to_10() -> None:
    blocked_rows = [
        {
            "candidate_id": f"cand_blocked_{idx}",
            "kind": "property_mutation_test",
            "status": "blocked",
            "reason": f"blocked-{idx}",
            "missing_inputs": ["missing_seed_context"],
            "summary": {"fields_selected_count": 0, "operation_id": f"op_{idx}"},
        }
        for idx in range(15)
    ]
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps({"candidates": blocked_rows}, ensure_ascii=False),
        state_json=json.dumps({"kind_caps": {}, "executed_by_kind": {}, "skipped_by_kind_cap_count": {}}, ensure_ascii=False),
    )
    sample = json.loads(result["blocked_candidates_sample_json"])
    assert len(sample) == 10
    by_kind = json.loads(result["blocked_candidates_by_kind_count_json"])
    assert by_kind.get("property_mutation_test") == 15


def test_select_ready_candidate_blocked_sample_includes_js_extractor_fields() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_js_blocked",
                        "kind": "js_endpoint_extractor",
                        "status": "blocked",
                        "reason": "Discovered js_url is outside campaign scope.",
                        "missing_inputs": ["host_not_allowed"],
                        "summary": {
                            "js_candidate_source": "zap_spider",
                            "js_url_sanitized": "http://evil.local/static/app.js",
                            "source_observation_id": "obs_js_1",
                            "validation_mode": "static_js_endpoint_extraction",
                            "max_endpoints": 50,
                            "reason_codes": ["host_not_allowed"],
                            "audit_flags": [],
                        },
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps({"kind_caps": {}, "executed_by_kind": {}, "skipped_by_kind_cap_count": {}}, ensure_ascii=False),
    )
    sample = json.loads(result["blocked_candidates_sample_json"])
    assert sample[0]["kind"] == "js_endpoint_extractor"
    assert sample[0]["js_candidate_source"] == "zap_spider"
    assert sample[0]["js_url_sanitized"] == "http://evil.local/static/app.js"
    assert sample[0]["source_observation_id"] == "obs_js_1"
    assert sample[0]["validation_mode"] == "static_js_endpoint_extraction"
    assert sample[0]["max_endpoints"] == 50


def test_select_ready_candidate_representative_sample_includes_property_mutation_with_noisy_security_headers() -> None:
    noisy = [
        {
            "candidate_id": f"cand_sh_{idx}",
            "kind": "security_header_validator",
            "status": "blocked",
            "reason": "ZAP alert does not map to a supported security-header validator rule.",
            "missing_inputs": ["supported_security_header_mapping"],
            "summary": {"operation_id": "", "fields_selected_count": 0},
        }
        for idx in range(15)
    ]
    mass_blocked = {
        "candidate_id": "cand_mass_blocked",
        "kind": "property_mutation_test",
        "status": "blocked",
        "reason": "Property_mutation_test blocked: no mass-assignment sensitive fields selected.",
        "missing_inputs": ["no_writable_sensitive_fields"],
        "summary": {
            "operation_id": "op_POST_/community/api/v2/community/posts/{postId}/comment",
            "mass_assignment_candidate_result": "blocked_no_sensitive_fields",
            "audit_flags": ["no_sensitive_fields", "missing_seed_context"],
            "fields_considered_count": 1,
            "fields_selected_count": 0,
            "seed_request_id_present": False,
            "reason_codes": ["no_writable_sensitive_fields", "missing_seed_context"],
        },
    }
    ready = {
        "candidate_id": "cand_ready_inj",
        "kind": "injection_test",
        "status": "ready",
        "command": {"tool_name": "injection_test"},
    }
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps({"candidates": [*noisy, mass_blocked, ready]}, ensure_ascii=False),
        state_json=json.dumps({"kind_caps": {"injection_test": 2}, "executed_by_kind": {}, "skipped_by_kind_cap_count": {}}, ensure_ascii=False),
    )
    assert result["candidate_kind"] == "injection_test"
    assert int(result["blocked_candidates_count_total"]) == 16
    by_kind = json.loads(result["blocked_candidates_by_kind_count_json"])
    assert by_kind.get("security_header_validator") == 15
    assert by_kind.get("property_mutation_test") == 1
    sample = json.loads(result["blocked_candidates_sample_json"])
    assert len(sample) <= 10
    assert any(row.get("kind") == "property_mutation_test" for row in sample)
    sec_rows = [row for row in sample if row.get("kind") == "security_header_validator"]
    assert len(sec_rows) <= 1


def test_select_ready_candidate_returns_caps_exhausted_when_all_ready_are_capped() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_inj",
                        "kind": "injection_test",
                        "status": "ready",
                        "command": {"tool_name": "injection_test"},
                    },
                    {
                        "candidate_id": "cand_schema",
                        "kind": "schemathesis_negative_test",
                        "status": "ready",
                        "command": {"tool_name": "schemathesis_negative_test"},
                    },
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "injection_test": 2,
                    "schemathesis_negative_test": 4,
                },
                "executed_by_kind": {
                    "injection_test": 2,
                    "schemathesis_negative_test": 4,
                },
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["has_ready_candidate"] == "false"
    assert result["candidate_kind"] == ""
    assert result["selection_outcome"] == "caps_exhausted"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {
        "injection_test": 1,
        "schemathesis_negative_test": 1,
    }


def test_select_ready_candidate_returns_no_ready_candidate_when_none_ready() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_blocked",
                        "kind": "injection_test",
                        "status": "blocked",
                        "command": None,
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"injection_test": 2},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["has_ready_candidate"] == "false"
    assert result["selection_outcome"] == "no_ready_candidate"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {}


def test_select_ready_candidate_treats_unknown_kind_as_uncapped() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_unknown",
                        "kind": "future_worker_kind",
                        "status": "ready",
                        "command": {"tool_name": "future_worker_kind"},
                    }
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {"injection_test": 2},
                "executed_by_kind": {"future_worker_kind": 99},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["has_ready_candidate"] == "true"
    assert result["candidate_kind"] == "future_worker_kind"
    assert result["selection_outcome"] == "selected_ready"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {}


def test_select_ready_candidate_prefers_js_extractor_over_late_validators_when_uncapped() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {"candidate_id": "cand_sec", "kind": "security_header_validator", "status": "ready", "command": {"tool_name": "security_header_validator"}},
                    {"candidate_id": "cand_cors", "kind": "cors_validator", "status": "ready", "command": {"tool_name": "cors_validator"}},
                    {"candidate_id": "cand_cookie", "kind": "cookie_flag_validator", "status": "ready", "command": {"tool_name": "cookie_flag_validator"}},
                    {"candidate_id": "cand_js", "kind": "js_endpoint_extractor", "status": "ready", "command": {"tool_name": "js_endpoint_extractor"}},
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "security_header_validator": 3,
                    "cors_validator": 1,
                    "cookie_flag_validator": 1,
                    "js_endpoint_extractor": 1,
                },
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "js_endpoint_extractor"
    assert result["selection_outcome"] == "selected_ready"


def test_select_ready_candidate_prefers_undocumented_validator_over_security_headers_when_uncapped() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {"candidate_id": "cand_sec", "kind": "security_header_validator", "status": "ready", "command": {"tool_name": "security_header_validator"}},
                    {"candidate_id": "cand_undoc", "kind": "undocumented_endpoint_validator", "status": "ready", "command": {"tool_name": "undocumented_endpoint_validator"}},
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "security_header_validator": 3,
                    "undocumented_endpoint_validator": 2,
                },
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "undocumented_endpoint_validator"
    assert result["selection_outcome"] == "selected_ready"


def test_select_ready_candidate_falls_through_when_js_extractor_cap_exhausted() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {"candidate_id": "cand_js", "kind": "js_endpoint_extractor", "status": "ready", "command": {"tool_name": "js_endpoint_extractor"}},
                    {"candidate_id": "cand_sec", "kind": "security_header_validator", "status": "ready", "command": {"tool_name": "security_header_validator"}},
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "js_endpoint_extractor": 1,
                    "security_header_validator": 3,
                },
                "executed_by_kind": {"js_endpoint_extractor": 1},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "security_header_validator"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {"js_endpoint_extractor": 1}
    assert result["selection_outcome"] == "selected_ready"


def test_select_ready_candidate_falls_through_when_undocumented_validator_cap_exhausted() -> None:
    result = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {"candidate_id": "cand_undoc", "kind": "undocumented_endpoint_validator", "status": "ready", "command": {"tool_name": "undocumented_endpoint_validator"}},
                    {"candidate_id": "cand_sec", "kind": "security_header_validator", "status": "ready", "command": {"tool_name": "security_header_validator"}},
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(
            {
                "kind_caps": {
                    "undocumented_endpoint_validator": 2,
                    "security_header_validator": 3,
                },
                "executed_by_kind": {"undocumented_endpoint_validator": 2},
                "skipped_by_kind_cap_count": {},
            },
            ensure_ascii=False,
        ),
    )
    assert result["candidate_kind"] == "security_header_validator"
    assert json.loads(result["skipped_by_kind_cap_delta_json"]) == {"undocumented_endpoint_validator": 1}
    assert result["selection_outcome"] == "selected_ready"


def test_extract_tool_run_returns_safe_failure_fields() -> None:
    result = _run_code_node(
        "extract_tool_run",
        body=json.dumps(
            {
                "tool_run_id": "toolrun_1",
                "tool_name": "security_header_validator",
                "status": "failed",
                "result": {
                    "tool_run_id": "toolrun_1",
                    "tool_name": "security_header_validator",
                    "status": "failed",
                    "errors": [
                        {
                            "error_type": "response_too_large",
                            "message": "HTTP response exceeded max_response_bytes.",
                        }
                    ],
                },
            },
            ensure_ascii=False,
        ),
    )
    assert result["tool_run_id"] == "toolrun_1"
    assert result["tool_name"] == "security_header_validator"
    assert result["tool_result_status"] == "failed"
    assert result["tool_error_type"] == "response_too_large"
    assert result["tool_error_safe_message"] == "HTTP response exceeded max_response_bytes."
    assert result["tool_error_count"] == "1"


def test_extract_tool_run_sanitizes_failure_message_with_forbidden_markers() -> None:
    result = _run_code_node(
        "extract_tool_run",
        body=json.dumps(
            {
                "tool_run_id": "toolrun_2",
                "tool_name": "security_header_validator",
                "status": "failed",
                "result": {
                    "tool_run_id": "toolrun_2",
                    "tool_name": "security_header_validator",
                    "status": "failed",
                    "errors": [
                        {
                            "error_type": "unsafe_error",
                            "message": "Authorization header leaked with token=abc",
                        }
                    ],
                },
            },
            ensure_ascii=False,
        ),
    )
    assert result["tool_error_type"] == "unsafe_error"
    assert result["tool_error_safe_message"] == "tool run failed"


def test_stop_tool_failed_below_threshold_records_failure_and_continues() -> None:
    input_state = {
        "iterations_run": 0,
        "executed_by_kind": {},
        "failed_by_kind": {},
        "tool_failures_count": 0,
        "tool_failure_summaries": [],
        "last_tool_error_type": "",
        "last_tool_error_safe_message": "",
        "max_tool_failures_total": 5,
        "max_tool_failures_by_kind": 3,
        "tool_failed_fatal_mode": False,
        "skipped_by_kind_cap_count": {},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_tool_failed",
        state_json=json.dumps(input_state, ensure_ascii=False),
        candidate_kind="security_header_validator",
        tool_run_id="toolrun_failed_1",
        tool_name="security_header_validator",
        tool_result_status="failed",
        tool_error_type="response_too_large",
        tool_error_safe_message="HTTP response exceeded max_response_bytes.",
        blocked_candidates_sample_json="[]",
        blocked_candidates_count_total="0",
        blocked_candidates_by_kind_count_json="{}",
        ready_candidates_sample_json='[{"kind":"cors_validator","status":"ready","tool_name":"cors_validator","validation_mode":"baseline_cors_check"}]',
        ready_candidates_by_kind_count_json='{"cors_validator":1}',
        selection_outcome="selected_ready",
        skipped_by_kind_cap_delta_json='{"security_header_validator":1}',
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is False
    assert state["iterations_run"] == 1
    assert state["tool_failures_count"] == 1
    assert state["failed_by_kind"] == {"security_header_validator": 1}
    assert state["executed_by_kind"] == {"security_header_validator": 1}
    assert state["stopped_reason"] == ""
    assert state["last_tool_error_type"] == "response_too_large"
    assert state["last_tool_error_safe_message"] == "HTTP response exceeded max_response_bytes."
    assert state["skipped_by_kind_cap_count"] == {"security_header_validator": 1}
    assert state["ready_candidates_by_kind_count"] == {"cors_validator": 1}
    assert state["iteration_summaries"][-1]["outcome"] == "tool_failed"
    assert state["iteration_summaries"][-1]["tool_error_type"] == "response_too_large"
    assert state["tool_failure_summaries"][-1]["candidate_kind"] == "security_header_validator"
    assert len(state["tool_failure_summaries"]) == 1


def test_stop_tool_failed_stops_on_by_kind_threshold() -> None:
    input_state = {
        "iterations_run": 2,
        "executed_by_kind": {"security_header_validator": 2},
        "failed_by_kind": {"security_header_validator": 2},
        "tool_failures_count": 2,
        "tool_failure_summaries": [],
        "max_tool_failures_total": 5,
        "max_tool_failures_by_kind": 3,
        "tool_failed_fatal_mode": False,
        "skipped_by_kind_cap_count": {},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_tool_failed",
        state_json=json.dumps(input_state, ensure_ascii=False),
        candidate_kind="security_header_validator",
        tool_run_id="toolrun_failed_2",
        tool_name="security_header_validator",
        tool_result_status="failed",
        tool_error_type="response_too_large",
        tool_error_safe_message="HTTP response exceeded max_response_bytes.",
        blocked_candidates_sample_json="[]",
        blocked_candidates_count_total="0",
        blocked_candidates_by_kind_count_json="{}",
        ready_candidates_sample_json="[]",
        ready_candidates_by_kind_count_json="{}",
        selection_outcome="selected_ready",
        skipped_by_kind_cap_delta_json="{}",
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is True
    assert state["tool_failures_count"] == 3
    assert state["failed_by_kind"]["security_header_validator"] == 3
    assert state["stopped_reason"] == "too_many_tool_failures"


def test_stop_tool_failed_stops_on_total_threshold() -> None:
    input_state = {
        "iterations_run": 4,
        "executed_by_kind": {"security_header_validator": 2, "injection_test": 2},
        "failed_by_kind": {"security_header_validator": 2, "injection_test": 2},
        "tool_failures_count": 4,
        "tool_failure_summaries": [],
        "max_tool_failures_total": 5,
        "max_tool_failures_by_kind": 5,
        "tool_failed_fatal_mode": False,
        "skipped_by_kind_cap_count": {},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_tool_failed",
        state_json=json.dumps(input_state, ensure_ascii=False),
        candidate_kind="cors_validator",
        tool_run_id="toolrun_failed_3",
        tool_name="cors_validator",
        tool_result_status="failed",
        tool_error_type="tool_failed",
        tool_error_safe_message="tool run failed",
        blocked_candidates_sample_json="[]",
        blocked_candidates_count_total="0",
        blocked_candidates_by_kind_count_json="{}",
        ready_candidates_sample_json="[]",
        ready_candidates_by_kind_count_json="{}",
        selection_outcome="selected_ready",
        skipped_by_kind_cap_delta_json="{}",
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is True
    assert state["tool_failures_count"] == 5
    assert state["failed_by_kind"]["cors_validator"] == 1
    assert state["stopped_reason"] == "too_many_tool_failures"


def test_stop_tool_failed_honors_legacy_fatal_mode_flag() -> None:
    input_state = {
        "iterations_run": 0,
        "executed_by_kind": {},
        "failed_by_kind": {},
        "tool_failures_count": 0,
        "tool_failure_summaries": [],
        "max_tool_failures_total": 5,
        "max_tool_failures_by_kind": 3,
        "tool_failed_fatal_mode": True,
        "skipped_by_kind_cap_count": {},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_tool_failed",
        state_json=json.dumps(input_state, ensure_ascii=False),
        candidate_kind="security_header_validator",
        tool_run_id="toolrun_failed_legacy",
        tool_name="security_header_validator",
        tool_result_status="failed",
        tool_error_type="response_too_large",
        tool_error_safe_message="HTTP response exceeded max_response_bytes.",
        blocked_candidates_sample_json="[]",
        blocked_candidates_count_total="0",
        blocked_candidates_by_kind_count_json="{}",
        ready_candidates_sample_json="[]",
        ready_candidates_by_kind_count_json="{}",
        selection_outcome="selected_ready",
        skipped_by_kind_cap_delta_json="{}",
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is True
    assert state["stopped_reason"] == "tool_failed"


def test_runtime_style_failed_security_header_allows_next_cors_selection() -> None:
    failure_result = _run_code_node(
        "stop_tool_failed",
        state_json=json.dumps(
            {
                "iterations_run": 9,
                "executed_by_kind": {"security_header_validator": 2},
                "failed_by_kind": {},
                "tool_failures_count": 0,
                "tool_failure_summaries": [],
                "max_tool_failures_total": 5,
                "max_tool_failures_by_kind": 3,
                "tool_failed_fatal_mode": False,
                "kind_caps": {"security_header_validator": 3, "cors_validator": 1},
                "skipped_by_kind_cap_count": {},
                "iteration_summaries": [],
            },
            ensure_ascii=False,
        ),
        candidate_kind="security_header_validator",
        tool_run_id="toolrun_failed_runtime",
        tool_name="security_header_validator",
        tool_result_status="failed",
        tool_error_type="response_too_large",
        tool_error_safe_message="HTTP response exceeded max_response_bytes.",
        blocked_candidates_sample_json="[]",
        blocked_candidates_count_total="0",
        blocked_candidates_by_kind_count_json="{}",
        ready_candidates_sample_json='[{"kind":"cors_validator","status":"ready","tool_name":"cors_validator","validation_mode":"baseline_cors_check"}]',
        ready_candidates_by_kind_count_json='{"security_header_validator":1,"cors_validator":1}',
        selection_outcome="selected_ready",
        skipped_by_kind_cap_delta_json="{}",
    )
    continued_state = json.loads(failure_result["state_json"])
    assert failure_result["should_exit_loop"] is False
    assert continued_state["executed_by_kind"]["security_header_validator"] == 3
    next_pick = _run_code_node(
        "select_ready_candidate",
        body=json.dumps(
            {
                "candidates": [
                    {
                        "candidate_id": "cand_sec",
                        "kind": "security_header_validator",
                        "status": "ready",
                        "command": {"tool_name": "security_header_validator"},
                    },
                    {
                        "candidate_id": "cand_cors",
                        "kind": "cors_validator",
                        "status": "ready",
                        "command": {"tool_name": "cors_validator"},
                    },
                ]
            },
            ensure_ascii=False,
        ),
        state_json=json.dumps(continued_state, ensure_ascii=False),
    )
    assert next_pick["candidate_kind"] == "cors_validator"
    assert next_pick["selection_outcome"] == "selected_ready"
    assert json.loads(next_pick["skipped_by_kind_cap_delta_json"]) == {"security_header_validator": 1}


def test_stop_no_ready_candidate_caps_exhausted_keeps_executed_counts_and_sets_reason() -> None:
    input_state = {
        "iterations_run": 2,
        "executed_by_kind": {"injection_test": 2},
        "skipped_by_kind_cap_count": {"injection_test": 1},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_no_ready_candidate",
        state_json=json.dumps(input_state, ensure_ascii=False),
        ready_count="2",
        blocked_count="0",
        skipped_existing_count="0",
        blocked_missing_inputs_summary="[]",
        blocked_candidates_sample_json='[{"kind":"property_mutation_test","status":"blocked","mass_assignment_candidate_result":"blocked_no_sensitive_fields"}]',
        blocked_candidates_count_total="1",
        blocked_candidates_by_kind_count_json='{"property_mutation_test":1}',
        selection_outcome="caps_exhausted",
        skipped_by_kind_cap_delta_json=json.dumps({"injection_test": 2}, ensure_ascii=False),
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is True
    assert state["stopped_reason"] == "caps_exhausted"
    assert state["last_selection_outcome"] == "caps_exhausted"
    assert state["executed_by_kind"] == {"injection_test": 2}
    assert state["skipped_by_kind_cap_count"] == {"injection_test": 3}
    assert state["blocked_candidates_count_total"] == 1
    assert state["blocked_candidates_by_kind_count"] == {"property_mutation_test": 1}
    assert state["blocked_candidates_sample"][0]["mass_assignment_candidate_result"] == "blocked_no_sensitive_fields"


def test_stop_no_ready_candidate_no_ready_sets_reason_and_keeps_executed_counts() -> None:
    input_state = {
        "iterations_run": 1,
        "executed_by_kind": {"schemathesis_negative_test": 1},
        "skipped_by_kind_cap_count": {},
        "iteration_summaries": [],
    }
    result = _run_code_node(
        "stop_no_ready_candidate",
        state_json=json.dumps(input_state, ensure_ascii=False),
        ready_count="0",
        blocked_count="2",
        skipped_existing_count="3",
        blocked_missing_inputs_summary="[]",
        blocked_candidates_sample_json='[{"kind":"property_mutation_test","status":"blocked","fields_selected_count":0,"seed_request_id_present":false}]',
        blocked_candidates_count_total="2",
        blocked_candidates_by_kind_count_json='{"security_header_validator":1,"property_mutation_test":1}',
        selection_outcome="no_ready_candidate",
        skipped_by_kind_cap_delta_json=json.dumps({"schemathesis_negative_test": 1}, ensure_ascii=False),
    )
    state = json.loads(result["state_json"])
    assert result["should_exit_loop"] is True
    assert state["stopped_reason"] == "no_ready_candidate"
    assert state["last_selection_outcome"] == "no_ready_candidate"
    assert state["executed_by_kind"] == {"schemathesis_negative_test": 1}
    assert state["skipped_by_kind_cap_count"] == {"schemathesis_negative_test": 1}
    assert state["blocked_candidates_count_total"] == 2
    assert state["blocked_candidates_by_kind_count"] == {"security_header_validator": 1, "property_mutation_test": 1}
    assert state["blocked_candidates_sample"][0]["fields_selected_count"] == 0


def test_blocked_candidate_observability_code_and_final_report_are_safe() -> None:
    select_code = _node_data("select_ready_candidate")["code"]
    report_code = _node_data("build_final_report")["code"]
    for bad in (
        "request_body",
        "response_body",
        "raw_body",
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "headers",
        "bearer",
        "token=",
    ):
        assert bad not in select_code
        assert bad not in report_code


def test_tool_failure_extraction_and_report_code_are_safe() -> None:
    extract_code = _node_data("extract_tool_run")["code"]
    report_code = _node_data("build_final_report")["code"]
    for bad in (
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "request_body",
        "response_body",
        "raw_body",
        "headers",
        "bearer",
        "token=",
    ):
        assert bad not in extract_code
        assert bad not in report_code


def test_build_final_report_includes_blocked_candidate_observability_fields() -> None:
    result = _run_code_node(
        "build_final_report",
        state_json=json.dumps(
            {
                "campaign_id": "cmp_1",
                "iterations_run": 1,
                "max_iterations": 10,
                "stopped_reason": "no_ready_candidate",
                "confirmed_findings_count": 0,
                "finding_ids": [],
                "pending_verification_count": 0,
                "kind_caps": {},
                "executed_by_kind": {},
                "skipped_by_kind_cap_count": {},
                "tool_failures_count": 1,
                "failed_by_kind": {"security_header_validator": 1},
                "tool_failure_summaries": [
                    {
                        "iteration_index": 1,
                        "candidate_kind": "security_header_validator",
                        "tool_name": "security_header_validator",
                        "tool_run_id": "toolrun_1",
                        "error_type": "response_too_large",
                        "message": "HTTP response exceeded max_response_bytes.",
                        "status": "failed",
                    }
                ],
                "last_tool_error_type": "response_too_large",
                "last_tool_error_safe_message": "HTTP response exceeded max_response_bytes.",
                "max_tool_failures_total": 5,
                "max_tool_failures_by_kind": 3,
                "last_candidate_kind": "",
                "last_tool_run_status": "",
                "last_selection_outcome": "no_ready_candidate",
                "iteration_summaries": [],
                "pending_summaries": [],
                "scenario_plan_source": "test",
                "scenario_plan_graph_empty": False,
                "scenarios_total": 1,
                "accepted_scenarios_count": 0,
                "blocked_scenarios_count": 1,
                "rejected_scenarios_count": 0,
                "scenario_types": ["mass_assignment:1"],
                "scenario_plan_warnings_sample": [],
                "scenario_plan_unavailable": False,
                "ready_candidates_by_kind_count": {"cors_validator": 1},
                "ready_candidates_sample": [
                    {
                        "kind": "cors_validator",
                        "status": "ready",
                        "tool_name": "cors_validator",
                        "worker_class": "misconfiguration",
                        "strategy": "validate_cors_policy",
                        "cors_candidate_source": "baseline",
                        "validation_mode": "baseline_cors_check",
                        "audit_flags": [],
                        "reason_codes": [],
                        "fields_selected_count": 0,
                        "seed_request_id_present": False,
                        "mass_assignment_candidate_result": "",
                        "operation_id": "",
                        "scenario_type": "",
                        "reason": "Baseline CORS validation candidate generated from safe campaign/passive context.",
                    }
                ],
                "blocked_candidates_count_total": 1,
                "blocked_candidates_by_kind_count": {"property_mutation_test": 1},
                "blocked_candidates_sample": [
                    {
                        "kind": "property_mutation_test",
                        "status": "blocked",
                        "mass_assignment_candidate_result": "blocked_no_sensitive_fields",
                        "fields_selected_count": 0,
                        "seed_request_id_present": False,
                    }
                ],
            },
            ensure_ascii=False,
        ),
    )
    text = result["answer_text"]
    assert "ready_candidates_by_kind_count:" in text
    assert "ready_candidates_sample:" in text
    assert "cors_validator" in text
    assert "baseline_cors_check" in text
    assert "tool_failures_count: 1" in text
    assert "failed_by_kind:" in text
    assert "tool_failure_summaries:" in text
    assert "last_tool_error_type: response_too_large" in text
    assert "last_tool_error_safe_message: HTTP response exceeded max_response_bytes." in text
    assert "blocked_candidates_count_total: 1" in text
    assert "blocked_candidates_sample:" in text
    assert "blocked_candidates_by_kind_count:" in text
    assert "mass_assignment_candidate_result" in text
    assert "fields_selected_count" in text
    assert "seed_request_id_present" in text


def test_report_context_http_node_exists_and_calls_reports_context_endpoint() -> None:
    node = _node_data("call_report_context")
    assert node["type"] == "http-request"
    url = node["url"]
    assert "/v1/reports/" in url
    assert "/context" in url
    body = _http_body("call_report_context")
    assert "emit_report_context_body.report_context_body_json" in body
    assert "runtime_state_snapshot" in _node_data("emit_report_context_body")["code"]


def test_emit_report_context_body_parses_final_state_json_safely() -> None:
    code = _node_data("emit_report_context_body")["code"]
    assert "json.loads" in code
    assert "runtime_state_snapshot" in code
    assert "snapshot_unavailable" in code
    assert "invalid final loop state json" in code
    result = _run_code_node("emit_report_context_body", state_json='{"campaign_id":"cmp_1"}')
    assert result["report_context_body_status"] == "snapshot_ready"
    payload = json.loads(result["report_context_body_json"])
    assert payload["runtime_state_snapshot"]["campaign_id"] == "cmp_1"


def test_extract_report_context_validates_schema_and_markdown_gate() -> None:
    code = _node_data("extract_report_context")["code"]
    assert 'EXPECTED_SCHEMA = "report-context/v1"' in code
    assert "report_generation_status" in code
    assert "report_context_error" in code
    assert "can_generate_markdown" in code
    assert "unexpected report context schema" in code

    ok = _run_code_node(
        "extract_report_context",
        body=json.dumps({"schema_version": "report-context/v1", "campaign": {}}, ensure_ascii=False),
        status_code="200",
    )
    assert ok["report_generation_status"] == "context_ready"
    assert ok["can_generate_markdown"] == "true"

    bad_schema = _run_code_node(
        "extract_report_context",
        body=json.dumps({"schema_version": "wrong/v1"}, ensure_ascii=False),
        status_code="200",
    )
    assert bad_schema["report_generation_status"] == "context_unavailable"
    assert bad_schema["can_generate_markdown"] == "false"
    assert bad_schema["report_context_error"] == "unexpected report context schema"


def test_llm_report_agent_prompt_has_required_factual_and_safety_constraints() -> None:
    prompts = _node_data("llm_report_agent")["prompt_template"]
    sys_prompt = prompts[0]["text"]
    user_prompt = prompts[1]["text"]
    assert "Пиши отчёт на русском языке" in sys_prompt
    assert "Не придумывай уязвимости" in sys_prompt
    assert "Только элементы confirmed_findings являются подтверждёнными уязвимостями" in sys_prompt
    assert "pending_verification, blocked_checks" in sys_prompt
    assert "Markdown only" in sys_prompt
    assert "Что найдено" in sys_prompt
    assert "Как обнаружено" in sys_prompt
    assert "Как воспроизвести / подтвердить" in sys_prompt
    assert "Потенциальное влияние" in sys_prompt
    assert "Рекомендации по устранению" in sys_prompt
    assert "report-context/v1" in sys_prompt
    assert "Finding ID" in sys_prompt
    assert "Evidence ID" in sys_prompt
    assert "OWASP category" in sys_prompt
    assert "Vulnerability class" in sys_prompt
    assert "Worker" in sys_prompt
    assert "Observation type" in sys_prompt
    assert "Judge verdict" in sys_prompt
    assert "технически грамотным русским языком" in sys_prompt
    assert "статического ресурса" in sys_prompt
    assert "сгруппируй их в один подраздел" in sys_prompt
    assert "candidates_considered" in sys_prompt
    assert "blocked_no_sensitive_fields_count" in sys_prompt
    assert "blocked_missing_seed_context_count" in sys_prompt
    assert "mass_assignment_signal_count" in sys_prompt
    assert "runtime_effect_proven_count" in sys_prompt
    assert "confirmed_findings_count" in sys_prompt
    assert "response_field_inventory_count" in sys_prompt
    assert "data_exposure_signal_count" in sys_prompt
    assert "sensitive_property_exposure_findings_count" in sys_prompt
    assert "sensitive_field_categories" in sys_prompt
    assert "sensitive_fields_sample" in sys_prompt
    assert "data_exposure_results" in sys_prompt
    assert "data_exposure_probe_result_count" in sys_prompt
    assert "data_exposure_non_200_count" in sys_prompt
    assert "data_exposure_non_json_count" in sys_prompt
    assert "data_exposure_no_fields_count" in sys_prompt
    assert "data_exposure_fields_extracted_count" in sys_prompt
    assert "data_exposure_probe_results" in sys_prompt
    assert "authenticated_response_field_inventory_count" in sys_prompt
    assert "authenticated_data_exposure_signal_count" in sys_prompt
    assert "authenticated_data_exposure_probe_result_count" in sys_prompt
    assert "authenticated_data_exposure_results" in sys_prompt
    assert "auth_profiles_used_count" in sys_prompt
    assert "operations_with_authenticated_inventory" in sys_prompt
    assert "data_exposure_authenticated_non_200_count" in sys_prompt
    assert "data_exposure_authenticated_fields_extracted_count" in sys_prompt
    assert "resource_instance_inventory_count" in sys_prompt
    assert "resource_instances_count" in sys_prompt
    assert "object_refs_count" in sys_prompt
    assert "operations_with_resource_instances" in sys_prompt
    assert "resource_types" in sys_prompt
    assert "resource_instance_results" in sys_prompt
    assert "resource_seed_result_count" in sys_prompt
    assert "resource_seed_success_count" in sys_prompt
    assert "resource_seed_object_refs_created_count" in sys_prompt
    assert "resource_seed_results" in sys_prompt
    assert "bola_object_pair_inventory_count" in sys_prompt
    assert "bola_object_pairs_count" in sys_prompt
    assert "bola_pair_resource_types" in sys_prompt
    assert "bola_replay_ready_count" in sys_prompt
    assert "bola_object_pairs" in sys_prompt
    assert "bola_replay_result_count" in sys_prompt
    assert "bola_replay_granted_count" in sys_prompt
    assert "bola_replay_denied_count" in sys_prompt
    assert "bola_replay_results" in sys_prompt
    assert "auth_profile_id — безопасная ссылка на auth profile" in sys_prompt
    assert "Извлечение ресурсных идентификаторов" in sys_prompt
    assert "object_id_ref — безопасная ссылка, а не raw object id" in sys_prompt
    assert "resource_instance_inventory — диагностический и context-producing результат, а не уязвимость" in sys_prompt
    assert "resource_seed_result — диагностический и context-producing результат, а не уязвимость" in sys_prompt
    assert "bola_object_pair_inventory — диагностический и context-producing результат, а не уязвимость" in sys_prompt
    assert "object_pair_id — безопасная ссылка для планирования replay" in sys_prompt
    assert "object_id_ref/object_ref_id — безопасные ссылки" in sys_prompt
    assert "bola_replay_result — runtime evidence" in sys_prompt
    assert "не автоматически confirmed finding" in sys_prompt
    assert "raw URL" in sys_prompt
    assert "Safe Resource Seeding" in sys_prompt
    assert "BOLA Object Pair Builder" in sys_prompt
    assert "BOLA Replay Diagnostics" in sys_prompt
    assert "Safe resource seeding created object references for BOLA/object-pair follow-up." in sys_prompt
    assert "Resource seeding was attempted but did not create object references; use reason_codes as blockers." in sys_prompt
    assert "BOLA replay can be planned using prepared object pairs." in sys_prompt
    assert "BOLA replay remains blocked because no object pairs were prepared." in sys_prompt
    assert "можно планировать следующий шаг BOLA/object-pair follow-up" in sys_prompt
    assert "последующие проверки API3 с аутентификацией успешно извлекли response field inventory" in sys_prompt
    assert "authenticated follow-up выполнялся, но inventory полей не извлечён" in sys_prompt
    assert "аутентификация разблокировала получение API3 field inventory" in sys_prompt
    assert "Диагностика data_exposure_validator" in sys_prompt
    assert "data_exposure_probe_result не является уязвимостью" in sys_prompt
    assert (
        "data_exposure_validator был выполнен, но не создал response_field_inventory. Причина указана в data_exposure_probe_results. Эти диагностические результаты не являются подтверждёнными уязвимостями."
        in sys_prompt
    )
    assert (
        "Часть проверок не дала inventory из-за non-200 ответов; endpoint-ы могут требовать авторизацию, seed context, параметры или предварительное состояние."
        in sys_prompt
    )
    assert "response_field_inventory — диагностический inventory" in sys_prompt
    assert "data_exposure_signal — сигнал" in sys_prompt
    assert (
        "обнаружены сигналы потенциального раскрытия чувствительных свойств, но подтверждённые уязвимости не созданы без вердикта Judge"
        in sys_prompt
    )
    assert "llm_candidate_advisor_used" in sys_prompt
    assert "не утверждай, что использовался LLM candidate advisor" in sys_prompt
    assert "не как подтверждение уязвимости и не как замену вердикта Judge" in sys_prompt
    assert "finding не создаётся без runtime_effect_proven:true" in sys_prompt
    assert "Раздел \"Покрытие OWASP API Top 10\" всегда должен содержать" in sys_prompt
    assert "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION" in sys_prompt
    assert "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION" in sys_prompt
    assert "при наличии confirmed findings класса bola выведи их в секции «Подтверждённые уязвимости»" in sys_prompt
    assert "если confirmed_findings_count = 0" in sys_prompt
    assert "finding.resource_context.is_static_asset=true" in sys_prompt
    assert "Находка относится к статическому ресурсу; влияние обычно ниже, чем для бизнес-API, но заголовки безопасности рекомендуется применять централизованно." in sys_prompt
    assert "finding.resource_context.impact_note" in sys_prompt
    assert "одинаковый finding_group_key" in sys_prompt
    assert "Если finding_groups не пустой, используй finding_groups как основу группировки" in sys_prompt
    assert "внутри группы обязательно выведи таблицу affected findings" in sys_prompt
    assert "Запрещено группировать findings без перечисления Finding ID и Evidence ID." in sys_prompt
    assert "affected endpoints" in sys_prompt
    assert "traceability" in sys_prompt
    assert "Раздел \"Область проверки\" должен выводить" in sys_prompt
    assert "Campaign ID" in sys_prompt
    assert "Target URL" in sys_prompt
    assert "OpenAPI URL" in sys_prompt
    assert "Profile" in sys_prompt
    assert "Stopped Reason" in sys_prompt
    assert "все worker kinds из worker_execution_summary/executed_by_kind" in sys_prompt
    assert "zap_discovery_passive" in sys_prompt
    assert "cors_validator" in sys_prompt
    assert "cookie_flag_validator" in sys_prompt
    assert "API7_SERVER_SIDE_REQUEST_FORGERY" in sys_prompt
    assert "js_endpoint_extractor трактуй строго как worker расширения поверхности и discovery" in sys_prompt
    assert "это не уязвимость и не прямой источник finding" in sys_prompt
    assert "ssrf_candidate_detector и ssrf_candidate_signal трактуй строго как диагностический API7 coverage" in sys_prompt
    assert "запрещено описывать покрытие API7 одной фразой «не доступно» целиком" in sys_prompt
    assert "диагностические SSRF-кандидаты обнаружены, подтверждённых SSRF-уязвимостей нет" in sys_prompt
    assert "ssrf_candidate_signal не является confirmed vulnerability" in sys_prompt
    assert "Auth Flow Diagnostics" in sys_prompt
    assert "auth_flow_diagnostics" in sys_prompt
    assert "auth_flow_signal — диагностический сигнал" in sys_prompt
    assert "auth_flow_detector не создаёт пользователей и не выполняет login/signup" in sys_prompt
    assert "token_response_candidate_count — безопасный числовой счётчик" in sys_prompt
    assert "test_account_materialization_status" in sys_prompt
    assert "auth_profiles_created_count" in sys_prompt
    assert "signup_success_count" in sys_prompt
    assert "login_success_count" in sys_prompt
    assert "test_account_materializer может выполнять signup/login только как ограниченный backend worker" in sys_prompt
    assert "не выводи raw token, password, cookie, Authorization, raw request body, raw response body" in sys_prompt
    assert "test_account_materialization_result — диагностический контекст, не confirmed vulnerability" in sys_prompt
    assert "auth_profiles_created_count >= 2" in sys_prompt
    assert "authenticated follow-up checks" in sys_prompt
    assert "Не выводи raw tokens, passwords, cookies, Authorization headers, Set-Cookie." in sys_prompt
    assert "не утверждай SSRF exploitability без callback/runtime proof" in sys_prompt
    assert "runtime/callback verification" in sys_prompt
    assert "Обнаружены входные поля, потенциально релевантные SSRF. Эти сигналы не являются подтверждёнными уязвимостями, так как в текущей фазе не выполнялась runtime/callback verification." in sys_prompt
    assert "Для каждого элемента ssrf_candidates выводи только безопасные поля: operation_id, method, path, field_name, field_path, schema_type, schema_format, confidence, reason_codes." in sys_prompt
    assert "Ожидающие проверки не считаются подтверждёнными уязвимостями." in sys_prompt
    assert "Ошибка инструмента не является подтверждённой уязвимостью." in sys_prompt
    assert "Не используй форму \"endpoint-ах\"" in sys_prompt
    assert "конечных точках API" in sys_prompt
    assert "ограниченную проверку контракта по OpenAPI" in sys_prompt
    assert "метаданные ответа" in sys_prompt
    assert "заголовок безопасности" in sys_prompt
    assert "подтверждённые уязвимости" in sys_prompt
    assert "сильные сигналы не обнаружены" in sys_prompt
    assert "undocumented_endpoint_signal_count" in sys_prompt
    assert "undocumented_endpoint_findings_count" in sys_prompt
    assert "schema_mismatch_count" in sys_prompt
    assert "js_endpoint_extraction_count" in sys_prompt
    assert "js_route_fragments_count" in sys_prompt
    assert "js_route_fragments_matched_count" in sys_prompt
    assert "js_endpoints_emitted_count" in sys_prompt
    assert "js_extraction_results" in sys_prompt
    assert "ssrf_candidate_signal_count" in sys_prompt
    assert "ssrf_candidate_operations_count" in sys_prompt
    assert "ssrf_candidate_fields_count" in sys_prompt
    assert "ssrf_candidates" in sys_prompt
    assert "Извлечение поверхности из JavaScript" in sys_prompt
    assert "JS surface extraction" in sys_prompt
    assert (
        "JS-бандл содержит относительные маршруты; часть маршрутов сопоставлена с OpenAPI graph, поэтому они не считаются undocumented endpoints. Новых undocumented endpoint signals по JS extraction не выявлено."
        in sys_prompt
    )
    assert "не называй вывод js_endpoint_extractor подтверждённой уязвимостью" in sys_prompt
    assert "диагностическая проверка выполнена, подтверждённых уязвимостей нет" in sys_prompt
    assert "не описывай весь раздел API3 одной фразой «не доступно»" in sys_prompt
    assert "bounded contract check against OpenAPI" not in sys_prompt
    assert "В кратком резюме не утверждай, что только N итераций завершились обнаружением" in sys_prompt
    assert "В ходе N итераций выполнены проверки несколькими worker-ами. Подтверждено M уязвимостей: ..." in sys_prompt
    assert "не используй формулировку \"авторизованный запрос\"" in sys_prompt
    assert "В рамках разрешённой тестовой среды" in sys_prompt
    assert "Повторить ограниченную проверку" in sys_prompt
    assert "Сопоставить результат с Evidence ID" in sys_prompt
    assert "авторизованный запрос" not in user_prompt.lower()
    for needle in (
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "request/response bodies",
        "raw HTTP headers",
        "tokens",
        "bearer",
    ):
        assert needle in sys_prompt
    for section in (
        "## 1. Область проверки",
        "## 2. Краткое резюме",
        "## 2a. Auth Flow Diagnostics",
        "## 3. Покрытие OWASP API Top 10",
        "## 4. Подтверждённые уязвимости",
        "## 5. Детали API8 Security Misconfiguration",
        "## 6. Детали API9 Improper Inventory Management",
        "## 7. Детали API7 Server-Side Request Forgery",
        "Извлечение поверхности из JavaScript",
        "## 8. Диагностика API3 BOPLA / Mass Assignment",
        "## 9. Ожидающие проверки",
        "## 10. Заблокированные и пропущенные проверки",
        "## 11. Сводка выполнения worker-ов",
        "## 12. Ошибки инструментов",
        "## 13. Ограничения",
        "## 14. Общие рекомендации",
    ):
        assert section in user_prompt
    assert "js_endpoint_extraction_count" in user_prompt
    assert "для API1 (owasp_coverage.API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION)" in user_prompt
    assert "js_extraction_results" in user_prompt
    assert "не называй js_endpoint_extractor источником уязвимостей или findings" in user_prompt
    assert "ssrf_candidate_signal_count" in user_prompt
    assert "ssrf_candidate_operations_count" in user_prompt
    assert "ssrf_candidate_fields_count" in user_prompt
    assert "ssrf_candidates" in user_prompt
    assert "Не называй ssrf_candidate_signal подтверждённой SSRF-уязвимостью" in user_prompt
    assert "запрещено писать, что API7 целиком «не доступно»" in user_prompt
    assert "field_path, schema_type, schema_format, confidence, reason_codes" in user_prompt
    assert "ssrf_candidate_signal не является confirmed vulnerability" in user_prompt
    assert "не своди статус к «не доступно»" in user_prompt
    assert "диагностическая проверка выполнена, подтверждённых уязвимостей нет" in user_prompt
    assert "response_field_inventory_count" in user_prompt
    assert "data_exposure_signal_count" in user_prompt
    assert "sensitive_property_exposure_findings_count" in user_prompt
    assert "sensitive_field_categories" in user_prompt
    assert "sensitive_fields_sample" in user_prompt
    assert "data_exposure_results" in user_prompt
    assert "data_exposure_probe_result_count" in user_prompt
    assert "data_exposure_non_200_count" in user_prompt
    assert "data_exposure_non_json_count" in user_prompt
    assert "data_exposure_no_fields_count" in user_prompt
    assert "data_exposure_fields_extracted_count" in user_prompt
    assert "data_exposure_probe_results" in user_prompt
    assert "authenticated_response_field_inventory_count" in user_prompt
    assert "authenticated_data_exposure_signal_count" in user_prompt
    assert "authenticated_data_exposure_probe_result_count" in user_prompt
    assert "authenticated_data_exposure_results" in user_prompt
    assert "auth_profiles_used_count" in user_prompt
    assert "operations_with_authenticated_inventory" in user_prompt
    assert "data_exposure_authenticated_non_200_count" in user_prompt
    assert "data_exposure_authenticated_fields_extracted_count" in user_prompt
    assert "resource_instance_inventory_count" in user_prompt
    assert "resource_instances_count" in user_prompt
    assert "object_refs_count" in user_prompt
    assert "operations_with_resource_instances" in user_prompt
    assert "resource_types" in user_prompt
    assert "resource_instance_results" in user_prompt
    assert "resource_seed_result_count" in user_prompt
    assert "resource_seed_success_count" in user_prompt
    assert "resource_seed_object_refs_created_count" in user_prompt
    assert "resource_seed_results" in user_prompt
    assert "bola_object_pair_inventory_count" in user_prompt
    assert "bola_object_pairs_count" in user_prompt
    assert "bola_pair_resource_types" in user_prompt
    assert "bola_replay_ready_count" in user_prompt
    assert "bola_object_pairs" in user_prompt
    assert "bola_replay_result_count" in user_prompt
    assert "bola_replay_granted_count" in user_prompt
    assert "bola_replay_denied_count" in user_prompt
    assert "bola_replay_results" in user_prompt
    assert "auth_profile_id — безопасная ссылка" in user_prompt
    assert "Извлечение ресурсных идентификаторов" in user_prompt
    assert "object_id_ref — безопасная ссылка, а не raw object id" in user_prompt
    assert "resource_instance_inventory не является уязвимостью" in user_prompt
    assert "resource_seed_result не является уязвимостью" in user_prompt
    assert "bola_object_pair_inventory не является уязвимостью" in user_prompt
    assert "object_pair_id — безопасная ссылка для replay planning" in user_prompt
    assert "object_id_ref/object_ref_id — безопасные ссылки" in user_prompt
    assert "bola_replay_result не является автоматически confirmed vulnerability" in user_prompt
    assert "raw URL" in user_prompt
    assert "Safe Resource Seeding" in user_prompt
    assert "BOLA Object Pair Builder" in user_prompt
    assert "BOLA Replay Diagnostics" in user_prompt
    assert "Safe resource seeding created object references for BOLA/object-pair follow-up." in user_prompt
    assert "Resource seeding was attempted but did not create object references; use reason_codes as blockers." in user_prompt
    assert "BOLA replay can be planned using prepared object pairs." in user_prompt
    assert "BOLA replay remains blocked because no object pairs were prepared." in user_prompt
    assert "Если resource_instances_count > 0, укажи, что можно планировать BOLA/object-pair follow-up." in user_prompt
    assert "не выводи raw token, password, cookie, Authorization, raw request/response body" in user_prompt
    assert "Не выводи raw object id values, raw payloads, raw responses, raw token, password, cookie, Authorization." in user_prompt
    assert "raw headers" in user_prompt
    assert "аутентификация разблокировала API3 field inventory" in user_prompt
    assert "Диагностика data_exposure_validator" in user_prompt
    assert "non-200" in user_prompt.lower()
    assert "авторизац" in user_prompt.lower()
    assert "seed context" in user_prompt.lower()
    assert "Только элементы confirmed_findings — подтверждённые уязвимости" in user_prompt
    assert "auth_flow_signal — диагностика, не уязвимость" in user_prompt
    assert "auth_flow_detector не выполняет login/signup" in user_prompt
    assert "token_response_candidate_count — безопасный счётчик, не значение токена" in user_prompt
    assert "test_account_materialization_status" in user_prompt
    assert "auth_profiles_created_count" in user_prompt
    assert "signup_success_count" in user_prompt
    assert "login_success_count" in user_prompt
    assert "test_account_materialization_result — диагностика, не уязвимость" in user_prompt
    assert "не выводи raw token, password, cookie, Authorization, raw request/response body" in user_prompt
    assert "auth_profiles_created_count >= 2" in user_prompt
    assert "authenticated follow-up checks" in user_prompt
    assert "raw tokens, passwords, cookies, Authorization" in user_prompt
    assert "## 13. Ограничения" in user_prompt
    assert "llm_candidate_advisor_used=false" in user_prompt
    assert "не пиши, что LLM advisor подтверждал уязвимости" in user_prompt


def test_report_markdown_branching_and_merge_fallback_edges_exist() -> None:
    assert _has_edge("final_loop_state", "emit_report_context_body")
    assert _has_edge("emit_report_context_body", "call_report_context")
    assert _has_edge("call_report_context", "extract_report_context")
    assert _has_edge("extract_report_context", "can_generate_markdown")
    assert _has_edge("can_generate_markdown", "llm_report_agent", source_handle="true")
    assert _has_edge("can_generate_markdown", "merge_report_output", source_handle="false")
    assert _has_edge("llm_report_agent", "merge_report_output")
    assert _has_edge("build_final_report", "merge_report_output")
    assert _has_edge("merge_report_output", "answer_final_report")


def test_merge_report_output_prefers_markdown_else_uses_compact_fallback() -> None:
    code = _node_data("merge_report_output")["code"]
    assert "markdown_generated" in code
    assert "Markdown report generation unavailable; returning compact fallback." in code
    assert "fallback_report" in code
    with_md = _run_code_node(
        "merge_report_output",
        fallback_report="compact",
        report_generation_status="context_ready",
        report_context_error="",
        markdown_report="# REST API DAST Security Report",
    )
    assert with_md["final_report"].startswith("# REST API DAST Security Report")
    assert with_md["report_generation_status"] == "markdown_generated"
    without_md = _run_code_node(
        "merge_report_output",
        fallback_report="compact report",
        report_generation_status="context_unavailable",
        report_context_error="invalid report context json",
        markdown_report="",
    )
    assert "compact report" in without_md["final_report"]
    assert "Markdown report generation unavailable; returning compact fallback." in without_md["final_report"]
    assert without_md["report_generation_status"] == "context_unavailable"
    assert without_md["report_context_error"] == "invalid report context json"


def test_llm_report_prompt_declares_compact_mode_and_artifact_path_rules() -> None:
    prompts = _node_data("llm_report_agent")["prompt_template"]
    sys_prompt = prompts[0]["text"]
    user_prompt = prompts[1]["text"]
    assert "Режим отчёта: COMPACT" in sys_prompt
    assert "В каждой Markdown-таблице выводи максимум 5 строк данных." in sys_prompt
    assert "Диагностические сигналы не являются подтверждёнными уязвимостями." in sys_prompt
    assert "Пути к артефактам" in user_prompt
    assert "logs/dast_runs/<campaign_id>/reports/report_full.md" in user_prompt
    assert "logs/dast_runs/<campaign_id>/reports/report_confirmed_findings.md" in user_prompt
    assert "logs/dast_runs/<campaign_id>/reports/report_context_sanitized.json" in user_prompt


def test_build_final_report_mentions_report_artifact_paths() -> None:
    code = _node_data("build_final_report")["code"]
    assert "/v1/reports/{campaign_id}/write-artifacts" in code
    assert "report_full_path" in code
    assert "report_confirmed_findings_path" in code
    assert "report_context_sanitized_path" in code


def test_final_loop_state_sets_max_iterations_reached_when_reason_missing() -> None:
    result = _run_code_node(
        "final_loop_state",
        seed_state_json=json.dumps({"iterations_run": 0, "max_iterations": 10, "stopped_reason": ""}, ensure_ascii=False),
        loop_state_json=json.dumps({"iterations_run": 10, "max_iterations": 10, "stopped_reason": ""}, ensure_ascii=False),
        current_state_json="",
    )
    state = json.loads(result["state_json"])
    assert state["stopped_reason"] == "max_iterations_reached"


def test_final_loop_state_keeps_caps_exhausted_reason() -> None:
    result = _run_code_node(
        "final_loop_state",
        seed_state_json=json.dumps({"iterations_run": 0, "max_iterations": 10, "stopped_reason": ""}, ensure_ascii=False),
        loop_state_json=json.dumps({"iterations_run": 10, "max_iterations": 10, "stopped_reason": "caps_exhausted"}, ensure_ascii=False),
        current_state_json="",
    )
    state = json.loads(result["state_json"])
    assert state["stopped_reason"] == "caps_exhausted"


def test_final_loop_state_keeps_no_ready_candidate_reason() -> None:
    result = _run_code_node(
        "final_loop_state",
        seed_state_json=json.dumps({"iterations_run": 0, "max_iterations": 10, "stopped_reason": ""}, ensure_ascii=False),
        loop_state_json=json.dumps({"iterations_run": 7, "max_iterations": 10, "stopped_reason": "no_ready_candidate"}, ensure_ascii=False),
        current_state_json="",
    )
    state = json.loads(result["state_json"])
    assert state["stopped_reason"] == "no_ready_candidate"
