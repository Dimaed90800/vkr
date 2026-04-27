"""Phase 15C — Dify workflow contract for planner loop + ScenarioPlan snapshot."""
from __future__ import annotations

import subprocess
import sys
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


def test_loop_scenarios_preserves_evidence_capable_types() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'cross_role_access_signal'" in code
    assert "'validated_security_header_issue'" in code
    assert "'schema_mismatch'" in code


def test_loop_scenarios_preserves_pending_only_types() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'zap_alert'" in code
    assert "'discovered_endpoint'" in code


def test_loop_scenarios_observation_priority_includes_schema_mismatch() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "schema = [obs for obs in observations if obs.get('type') == 'schema_mismatch']" in code
    assert "validated_headers[0] if validated_headers else (" in code
    assert "schema[0] if schema else (" in code


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
    assert "'schema_mismatch'" in evidence_set
    assert "verification_route': 'evidence_judge_apply' if is_evidence_capable else 'pending_verification'" in code
    assert _has_edge("is_evidence_capable", "record_pending_verification", source_handle="false")


def test_loop_scenarios_judge_prompt_has_schema_contract_guidance() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "api_schema_contract_violation / schema_mismatch evidence" in prompt
    assert "tool_name:schemathesis_negative_test" in prompt
    assert "signal:5xx" in prompt
    assert "signal:schema_violation" in prompt
    assert "signal:unexpected_2xx" in prompt


def test_loop_scenarios_schema_contract_prompt_does_not_require_bola_proof() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "do not require BOLA baseline, ownership proof, or diff." in prompt


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
    norm = _node_data("normalize_inputs")["code"]
    assert "inc_scen = _bool_str(include_scenario_compiler, 'true')" in norm


def test_scenario_llm_start_inputs_default_safe_stub() -> None:
    norm = _node_data("normalize_inputs")["code"]
    assert "scen_llm = _bool_str(scenario_llm_enabled, 'false')" in norm
    emit = _node_data("emit_scenario_plan_request_body")["code"]
    assert "llm_on" in emit


def test_existing_loop_contract_still_passes() -> None:
    """Original loop YAML must remain unchanged; original contract tests still pass."""
    orig = LOOP_ORIGINAL.read_text(encoding="utf-8")
    assert "merge_scenario_plan_into_planner_request" not in orig
    assert "call_scenario_plan" not in orig
    r = subprocess.run(
        [sys.executable, "-m", "pytest", str(ROOT / "tests/test_dify_full_backend_planner_dast_loop_contract.py"), "-q"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stdout + r.stderr


def test_loop_seed_and_final_state_use_merged_scenario_state() -> None:
    lv = _node_data("main_loop_v1")["loop_variables"]
    assert lv[0]["value"] == ["merge_scenario_plan_into_planner_request", "state_json"]
    vars_ = _node_data("final_loop_state")["variables"]
    seed = next(v for v in vars_ if v.get("variable") == "seed_state_json")
    assert seed["value_selector"] == ["merge_scenario_plan_into_planner_request", "state_json"]
