"""Phase 14A full backend planner DAST loop workflow contract tests."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
LOOP_WORKFLOW = ROOT / "dify" / "wf-full-backend-planner-dast-loop.yml"
FULL_WORKFLOW = ROOT / "dify" / "wf-full-backend-planner-dast.yml"
SMOKE_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
REAL_BOLA_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
REAL_BOLA_LLM_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola-llm.yml"
ZAP_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-zap-discovery.yml"
PLANNER_RUN_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-planner-run.yml"
LEGACY_MULTIAGENT_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _loop_text() -> str:
    return LOOP_WORKFLOW.read_text(encoding="utf-8")


def _loop_yaml() -> dict:
    return yaml.safe_load(_loop_text())


def _nodes() -> list[dict]:
    return _loop_yaml()["workflow"]["graph"]["nodes"]


def _nodes_by_id() -> dict[str, dict]:
    return {node["id"]: node for node in _nodes()}


def _node(node_id: str) -> dict:
    return _nodes_by_id()[node_id]


def _node_data(node_id: str) -> dict:
    return _node(node_id)["data"]


def _edges() -> list[dict]:
    return _loop_yaml()["workflow"]["graph"]["edges"]


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
    node = _node(node_id)
    return bool(node.get("parentId") == "main_loop_v1" and _node_data(node_id).get("isInLoop") is True)


def test_loop_workflow_exists() -> None:
    assert LOOP_WORKFLOW.exists()
    assert "wf-full-backend-planner-dast-loop" in _loop_text()


def test_existing_workflows_still_exist() -> None:
    for workflow in [
        FULL_WORKFLOW,
        SMOKE_WORKFLOW,
        REAL_BOLA_WORKFLOW,
        REAL_BOLA_LLM_WORKFLOW,
        ZAP_WORKFLOW,
        PLANNER_RUN_WORKFLOW,
        LEGACY_MULTIAGENT_WORKFLOW,
    ]:
        assert workflow.exists()


def test_loop_workflow_contains_loop_node() -> None:
    node = _node("main_loop_v1")
    assert _node_data("main_loop_v1")["type"] == "loop"
    assert _node_data("main_loop_v1")["start_node_id"] == "main_loop_start"
    assert _node("main_loop_start")["type"] == "custom-loop-start"
    assert _node_data("main_loop_start")["type"] == "loop-start"


def test_loop_workflow_has_loop_count_hard_ceiling() -> None:
    node = _node_data("main_loop_v1")
    assert node["loop_count"] == 10
    assert "planner-loop-break" in _loop_text()
    assert node["break_conditions"][0]["variable_selector"] == ["finalize_iteration", "should_exit_loop"]


def test_loop_workflow_supports_max_iterations_input_default() -> None:
    start_vars = _node_data("start")["variables"]
    assert any(item["variable"] == "max_iterations" for item in start_vars)
    code = _node_data("normalize_inputs")["code"]
    assert "max_iterations" in code
    assert "_int_value(max_iterations, 3)" in code
    assert "'max_iterations': str(max_iters)" in code
    assert "if parsed > 10:" in code
    assert "return 10" in code


def test_loop_workflow_caps_max_iterations_to_hard_ceiling_10() -> None:
    normalize_code = _node_data("normalize_inputs")["code"]
    init_code = _node_data("init_loop_state")["code"]
    assert "if parsed > 10:" in normalize_code
    assert "return 10" in normalize_code
    assert "if max_iters > 10:" in init_code
    assert 'state["max_iterations"]' not in init_code
    assert '"max_iterations": max_iters' in init_code


def test_loop_workflow_initializes_compact_loop_state() -> None:
    code = _node_data("init_loop_state")["code"]
    for field in [
        '"campaign_id"',
        '"iterations_run"',
        '"max_iterations"',
        '"confirmed_findings_count"',
        '"finding_ids"',
        '"pending_verification_count"',
        '"last_candidate_kind"',
        '"last_tool_run_status"',
        '"last_observation_type"',
        '"last_verification_plan_id"',
        '"stopped_reason"',
        '"iteration_summaries"',
        '"pending_summaries"',
    ]:
        assert field in code


def test_planner_call_is_inside_loop() -> None:
    assert _is_in_loop("call_planner_candidates")
    assert "/v1/planner/{{#extract_campaign.campaign_id#}}/candidates" in _node_data("call_planner_candidates")["url"]


def test_tools_runs_start_is_inside_loop() -> None:
    assert _is_in_loop("run_selected_command")
    assert _node_data("run_selected_command")["url"].endswith("/v1/tools/runs/start")


def test_selected_command_object_interpolation_not_quoted() -> None:
    body = _http_body("run_selected_command")
    assert '"command": {{#select_ready_candidate.command_json#}}' in body
    assert '"command": "{{#select_ready_candidate.command_json#}}"' not in body


def test_observations_normalize_is_inside_loop() -> None:
    assert _is_in_loop("normalize_observations")
    assert "/v1/observations/normalize/" in _node_data("normalize_observations")["url"]


def test_triage_is_inside_loop() -> None:
    assert _is_in_loop("triage_observation")
    assert "/v1/observations/triage/" in _node_data("triage_observation")["url"]


def test_observation_priority_cross_role_validated_header_zap_discovered() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "obs.get('type') == 'cross_role_access_signal'" in code
    assert "obs.get('type') == 'validated_security_header_issue'" in code
    assert "obs.get('type') == 'zap_alert'" in code
    assert "obs.get('type') == 'discovered_endpoint'" in code
    assert "validated_headers[0] if validated_headers else (" in code


def test_evidence_capable_types_route_to_judge_tail() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'cross_role_access_signal'" in code
    assert "'validated_security_header_issue'" in code
    assert _has_edge("is_evidence_capable", "build_evidence_pack", "true")
    assert _has_edge("build_evidence_pack", "compact_evidence_for_judge")
    assert _has_edge("compact_evidence_for_judge", "llm_judge")
    assert _has_edge("llm_judge", "parse_judge_verdict")
    assert _has_edge("parse_judge_verdict", "apply_judge_verdict")
    assert _has_edge("apply_judge_verdict", "extract_apply_result")
    assert _has_edge("extract_apply_result", "list_confirmed_findings")


def test_loop_judge_prompt_has_type_aware_security_header_rules() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "security_header_misconfiguration" in prompt
    assert "validated_security_header_issue" in prompt
    assert "do not require BOLA baseline, attack, ownership_proof, or diff" in prompt


def test_loop_judge_prompt_keeps_bola_specific_requirements_for_bola_only() -> None:
    prompt = _node_data("llm_judge")["prompt_template"][0]["text"]
    assert "For BOLA / cross_role_access_signal evidence" in prompt
    assert "baseline, attack, ownership proof" in prompt
    assert "Apply BOLA-only evidence requirements only to BOLA evidence types." in prompt


def test_loop_compact_judge_input_contains_security_header_fields() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    for field in [
        "'vulnerability_class'",
        "'owasp_category'",
        "'hypothesis'",
        "'status'",
        "'judge_ready'",
        "'missing_evidence'",
        "'derived_signals'",
        "'replay_steps_count'",
        "'replay_step_refs'",
    ]:
        assert field in code


def test_loop_parse_judge_verdict_validates_severity_enum() -> None:
    code = _node_data("parse_judge_verdict")["code"]
    assert "SEVERITIES = {'info', 'low', 'medium', 'high', 'critical'}" in code
    assert "if str(payload.get('severity') or '') not in SEVERITIES:" in code
    assert "raise ValueError('invalid_severity')" in code
    assert "candidate_severity and candidate_severity not in SEVERITIES" in code


def test_loop_parse_judge_verdict_validates_confidence_range() -> None:
    code = _node_data("parse_judge_verdict")["code"]
    assert "def _is_valid_confidence(value) -> bool:" in code
    assert "parsed = float(value)" in code
    assert "return 0.0 <= parsed <= 1.0" in code
    assert "if not _is_valid_confidence(payload.get('confidence')):" in code
    assert "raise ValueError('invalid_confidence')" in code


def test_loop_parse_judge_verdict_validates_finding_candidate_shape() -> None:
    code = _node_data("parse_judge_verdict")["code"]
    assert "if not isinstance(payload.get('finding_candidate'), dict):" in code
    assert "raise ValueError('finding_candidate_not_object')" in code
    assert "if not isinstance(candidate.get('title', ''), str):" in code
    assert "if not isinstance(candidate.get('vulnerability_class', ''), str):" in code
    assert "if not isinstance(candidate.get('summary', ''), str):" in code
    assert "if not isinstance(candidate.get('extras', {}), dict):" in code
    assert "if not isinstance(payload.get('duplicate_of_finding_id'), str):" in code
    assert "if not isinstance(payload.get('reason'), str):" in code


def test_loop_compact_judge_input_does_not_pass_replay_url() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    assert "'url':" not in code


def test_loop_compact_judge_input_keeps_safe_replay_fields() -> None:
    code = _node_data("compact_evidence_for_judge")["code"]
    for field in [
        "'order'",
        "'role'",
        "'method'",
        "'path_template'",
        "'path'",
        "'description'",
        "'request_id'",
    ]:
        assert field in code
    assert "def safe_path(value):" in code
    assert "return raw.split('?', 1)[0]" in code


def test_pending_only_types_do_not_route_to_judge_tail() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "'zap_alert'" in code
    assert "'discovered_endpoint'" in code
    assert _has_edge("is_evidence_capable", "record_pending_verification", "false")
    assert not _has_edge("record_pending_verification", "build_evidence_pack")
    assert not _has_edge("record_pending_verification", "apply_judge_verdict")
    assert not _has_edge("record_pending_verification", "list_confirmed_findings")


def test_verdict_object_interpolation_not_quoted() -> None:
    body = _http_body("apply_judge_verdict")
    assert '"verdict": {{#parse_judge_verdict.judge_verdict_json#}}' in body
    assert '"verdict": "{{#parse_judge_verdict.judge_verdict_json#}}"' not in body


def test_loop_stop_conditions_no_ready_max_iterations_tool_failed() -> None:
    assert "no_ready_candidate" in _node_data("stop_no_ready_candidate")["code"]
    assert "max_iterations_reached" in _node_data("stop_max_iterations")["code"]
    assert "tool_failed" in _node_data("stop_tool_failed")["code"]
    assert "iterations_run >= max_iterations" in _node_data("check_iteration_limit")["code"]


def test_finalize_iteration_exit_logic_no_ready_not_masked_by_false() -> None:
    code = _node_data("finalize_iteration")["code"]
    assert "should_exit_loop = any([" in code
    assert "bool(stop_no_ready_candidate_exit)" in code
    assert "should_exit_loop = _pick(" not in code


def test_finalize_iteration_exit_logic_tool_failed_not_masked_by_false() -> None:
    code = _node_data("finalize_iteration")["code"]
    assert "should_exit_loop = any([" in code
    assert "bool(stop_tool_failed_exit)" in code
    assert "should_exit_loop = _pick(" not in code


def test_no_observations_continues_or_records_summary() -> None:
    code = _node_data("record_no_observations")["code"]
    assert '"outcome": "no_observations"' in code
    assert '"should_exit_loop": False' in code
    assert _has_edge("has_observation", "record_no_observations", "false")


def test_final_report_contains_iterations_findings_pending_stopped_reason() -> None:
    code = _node_data("build_final_report")["code"]
    for field in [
        "campaign_id",
        "iterations_run",
        "max_iterations",
        "stopped_reason",
        "confirmed_findings_count",
        "finding_ids",
        "pending_verification_count",
        "last_candidate_kind",
        "last_tool_run_status",
    ]:
        assert field in code


def test_final_loop_state_prefers_loop_variable_current_state() -> None:
    code = _node_data("final_loop_state")["code"]
    assert "loop_state_json" in code
    assert "value = str(loop_state_json or '').strip()" in code
    assert "if not value:" in code
    assert "value = str(current_state_json or '').strip()" in code
    vars_data = _node_data("final_loop_state")["variables"]
    assert any(item.get("value_selector") == ["main_loop_v1", "_current_loop_state"] for item in vars_data)


def test_final_report_contains_compact_iteration_summaries() -> None:
    code = _node_data("build_final_report")["code"]
    assert "iteration_summaries" in code
    update_code = _node_data("record_finding_created")["code"] + _node_data("record_no_observations")["code"]
    assert '"iteration_index"' in update_code
    assert '"candidate_kind"' in update_code
    assert '"tool_run_id"' in update_code
    assert '"tool_result_status"' in update_code
    assert '"observations_count"' in update_code
    assert '"first_observation_type"' in update_code
    assert '"verification_plan_id"' in update_code
    assert '"outcome"' in update_code


def test_loop_iteration_outcome_finding_created_requires_finding_id() -> None:
    code = _node_data("record_finding_created")["code"]
    assert "finding_id_value = str(finding_id or '').strip()" in code
    assert 'if finding_id_value:' in code
    assert 'outcome = "finding_created"' in code


def test_loop_iteration_outcome_rework_without_finding_is_not_finding_created() -> None:
    code = _node_data("record_finding_created")["code"]
    assert "elif verdict_name:" in code
    assert 'outcome = f"judge_{verdict_name}"' in code
    assert 'outcome = "judged_no_finding"' in code
    assert '"outcome": "finding_created"' not in code


def test_final_report_contains_compact_pending_summaries() -> None:
    code = _node_data("build_final_report")["code"]
    update_code = _node_data("record_pending_verification")["code"]
    assert "pending_summaries" in code
    assert '"observation_id"' in update_code
    assert '"observation_type"' in update_code
    assert '"verification_plan_id"' in update_code
    assert '"candidate_kind"' in update_code


def test_loop_does_not_call_legacy_scheduler() -> None:
    text = _loop_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text


def test_loop_does_not_call_wrappers_execute() -> None:
    assert "/v1/tools/wrappers/execute" not in _loop_text()


def test_loop_does_not_call_corpus_add() -> None:
    assert "/v1/corpus/add" not in _loop_text()


def test_loop_compact_state_only() -> None:
    text = _loop_text()
    for forbidden in [
        "raw_json",
        "tool_result_json",
        "observation_json",
        "planner_response_json",
        "plan_json",
        "artifact_content",
        "Authorization",
        "Cookie",
        "Bearer",
        "bearer_token",
        "request_body",
        "response_body",
        "raw headers",
        "raw bodies",
        "raw artifacts",
        "full ToolResult",
        "full corpus",
    ]:
        assert forbidden not in text


def test_final_report_does_not_include_command_json() -> None:
    assert "command_json" in _node_data("select_ready_candidate")["code"]
    assert "command_json" not in _node_data("build_final_report")["code"]
    assert "command_json" not in _node_data("answer_final_report")["answer"]


def test_loop_reuses_backend_planner_not_legacy_queue() -> None:
    text = _loop_text()
    assert "/v1/planner/" in text
    assert "Planner Candidates" in text
    assert "schedule_next_task" not in text
    assert "pending_tasks" not in text
