"""Phase 13A full backend planner DAST Dify workflow contract tests."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
FULL_WORKFLOW = ROOT / "dify" / "wf-full-backend-planner-dast.yml"
SMOKE_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
REAL_BOLA_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
REAL_BOLA_LLM_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola-llm.yml"
ZAP_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-zap-discovery.yml"
PLANNER_RUN_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-planner-run.yml"
LEGACY_MULTIAGENT_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _full_text() -> str:
    return FULL_WORKFLOW.read_text(encoding="utf-8")


def _full_yaml() -> dict:
    return yaml.safe_load(_full_text())


def _nodes_by_id() -> dict[str, dict]:
    return {
        node["id"]: node
        for node in _full_yaml()["workflow"]["graph"]["nodes"]
    }


def _edges() -> list[dict]:
    return _full_yaml()["workflow"]["graph"]["edges"]


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def _has_edge(source: str, target: str, source_handle: str | None = None) -> bool:
    for edge in _edges():
        if edge.get("source") != source or edge.get("target") != target:
            continue
        if source_handle is not None and edge.get("sourceHandle") != source_handle:
            continue
        return True
    return False


def test_full_planner_dast_workflow_exists() -> None:
    assert FULL_WORKFLOW.exists()
    assert "wf-full-backend-planner-dast" in _full_text()


def test_existing_workflows_still_exist() -> None:
    for workflow in [
        SMOKE_WORKFLOW,
        REAL_BOLA_WORKFLOW,
        REAL_BOLA_LLM_WORKFLOW,
        ZAP_WORKFLOW,
        PLANNER_RUN_WORKFLOW,
        LEGACY_MULTIAGENT_WORKFLOW,
    ]:
        assert workflow.exists()


def test_full_workflow_calls_campaign_create() -> None:
    assert "/v1/campaigns" in _full_text()
    assert _node_data("create_campaign")["url"].endswith("/v1/campaigns")


def test_full_workflow_optionally_builds_graph() -> None:
    text = _full_text()
    assert "Has OpenAPI Spec?" in text
    assert "/v1/graph/{{#extract_campaign.campaign_id#}}/build" in text
    assert _node_data("has_openapi_spec")["type"] == "if-else"
    assert _node_data("skip_graph")["type"] == "code"
    assert "openapi_spec_text_json" in _node_data("normalize_inputs")["code"]


def test_full_workflow_calls_planner_candidates() -> None:
    text = _full_text()
    assert "/v1/planner/{{#extract_campaign.campaign_id#}}/candidates" in text
    assert _node_data("call_planner_candidates")["url"].endswith(
        "/v1/planner/{{#extract_campaign.campaign_id#}}/candidates"
    )
    assert "{{#normalize_inputs.planner_request_json#}}" in _http_body("call_planner_candidates")
    assert '"{{#normalize_inputs.planner_request_json#}}"' not in _http_body("call_planner_candidates")


def test_full_workflow_runs_selected_command() -> None:
    assert "/v1/tools/runs/start" in _full_text()
    assert _node_data("run_selected_command")["url"].endswith("/v1/tools/runs/start")


def test_full_workflow_sends_command_as_object_not_string() -> None:
    body = _http_body("run_selected_command")
    assert '"execution_mode": "sync"' in body
    assert '"command": {{#select_ready_candidate.command_json#}}' in body
    assert '"command": "{{#select_ready_candidate.command_json#}}"' not in body


def test_full_workflow_normalizes_observations() -> None:
    text = _full_text()
    assert "/v1/observations/normalize/" in text
    assert "{{#extract_tool_run.tool_run_id#}}" in _node_data("normalize_observations")["url"]


def test_full_workflow_triages_observation() -> None:
    text = _full_text()
    assert "/v1/observations/triage/" in text
    assert "{{#summarize_observations.first_observation_id#}}" in _node_data("triage_observation")["url"]


def test_full_workflow_observation_priority_cross_role_zap_discovered() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "obs.get('type') == 'cross_role_access_signal'" in code
    assert "obs.get('type') == 'zap_alert'" in code
    assert "obs.get('type') == 'discovered_endpoint'" in code
    assert "selected = cross[0] if cross else (alerts[0] if alerts else (discovered[0] if discovered else {}))" in code


def test_full_workflow_has_observation_derived_from_first_observation_id() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "first_observation_id = str(selected.get('observation_id') or selected.get('id') or '')" in code
    assert "'has_observation': 'true' if first_observation_id else 'false'" in code
    assert "'has_observation': 'true' if selected else 'false'" not in code


def test_full_workflow_has_no_ready_candidate_branch() -> None:
    assert _node_data("has_ready_candidate")["type"] == "if-else"
    assert _node_data("answer_no_ready_candidate")["type"] == "answer"
    assert _has_edge("has_ready_candidate", "answer_no_ready_candidate", "false")
    assert "No ready planner candidate found." in _node_data("answer_no_ready_candidate")["answer"]


def test_full_workflow_has_no_observations_branch() -> None:
    assert _node_data("has_observation")["type"] == "if-else"
    assert _node_data("answer_no_observations")["type"] == "answer"
    assert _has_edge("has_observation", "answer_no_observations", "false")
    assert "no actionable observations were normalized" in _node_data("answer_no_observations")["answer"]


def test_full_workflow_has_cross_role_branch_to_evidence() -> None:
    code = _node_data("route_by_observation_type")["code"]
    assert "obs_type == 'cross_role_access_signal'" in code
    assert "verification_plan_id" in code
    assert _node_data("is_cross_role_signal")["type"] == "if-else"
    assert _has_edge("is_cross_role_signal", "build_evidence_pack", "true")
    assert "/v1/evidence/build-from-plan/{{#extract_verification_plan.verification_plan_id#}}" in _node_data("build_evidence_pack")["url"]


def test_full_workflow_has_llm_judge_node() -> None:
    nodes = _nodes_by_id()
    assert nodes["llm_judge"]["data"]["type"] == "llm"
    assert "LLM Judge" in _full_text()
    prompt = str(_node_data("llm_judge").get("prompt_template", ""))
    assert "Do not create findings" in prompt
    assert "Do not call tools" in prompt
    assert "JudgeVerdictPayload" in prompt


def test_full_workflow_has_parse_validate_judge_verdict_node() -> None:
    parse = _node_data("parse_judge_verdict")
    code = parse["code"]
    assert parse["type"] == "code"
    assert "Parse/Validate Judge Verdict" in _full_text()
    assert "json.loads" in code
    assert "ALLOWED" in code
    assert "REQUIRED" in code
    assert "finding_candidate" in code


def test_full_workflow_has_invalid_json_fallback() -> None:
    code = _node_data("parse_judge_verdict")["code"]
    assert "invalid_llm_json" in code
    assert "LLM judge returned invalid JSON" in code
    assert "'verdict': 'inconclusive'" in code
    assert "'severity': 'info'" in code


def test_full_workflow_calls_judge_apply() -> None:
    assert "/v1/judge/apply" in _full_text()
    assert _node_data("apply_judge_verdict")["url"].endswith("/v1/judge/apply")


def test_full_workflow_sends_verdict_as_object_not_string() -> None:
    body = _http_body("apply_judge_verdict")
    assert '"verdict": {{#parse_judge_verdict.judge_verdict_json#}}' in body
    assert '"verdict": "{{#parse_judge_verdict.judge_verdict_json#}}"' not in body


def test_full_workflow_lists_confirmed_findings() -> None:
    text = _full_text()
    assert "/v1/findings/confirmed/" in text
    assert "{{#extract_campaign.campaign_id#}}" in _node_data("list_confirmed_findings")["url"]


def test_full_workflow_has_pending_verification_branch_for_zap_and_discovered() -> None:
    code = _node_data("route_by_observation_type")["code"]
    answer = _node_data("answer_pending_verification")["answer"]
    assert "'zap_alert'" in code
    assert "'discovered_endpoint'" in code
    assert "pending_verification" in code
    assert "pending_verification" in answer
    assert _has_edge("is_cross_role_signal", "answer_pending_verification", "false")
    assert not _has_edge("answer_pending_verification", "build_evidence_pack")
    assert not _has_edge("answer_pending_verification", "apply_judge_verdict")


def test_pending_branch_message_says_non_bola_stops_at_verification() -> None:
    answer = _node_data("answer_pending_verification")["answer"]
    assert "Non-BOLA signal stopped at VerificationPlan in Phase 13A." in answer


def test_full_workflow_does_not_call_legacy_scheduler_or_wrappers() -> None:
    text = _full_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text
    assert "/v1/tools/wrappers/execute" not in text


def test_full_workflow_does_not_call_corpus_add() -> None:
    assert "/v1/corpus/add" not in _full_text()


def test_full_workflow_does_not_directly_store_findings() -> None:
    text = _full_text()
    for forbidden in [
        "store_confirmed_finding",
        "store_judge_decision",
        "confirmed_findings_by_campaign",
        "confirmed_findings_by_fingerprint",
        "memory_store.findings",
        "findings_by_session",
    ]:
        assert forbidden not in text


def test_full_workflow_compact_state_only() -> None:
    text = _full_text()
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
    ]:
        assert forbidden not in text
    for compact in [
        "campaign_id",
        "candidate_id",
        "candidate_kind",
        "tool_run_id",
        "tool_result_status",
        "observations_count",
        "first_observation_id",
        "first_observation_type",
        "verification_plan_id",
        "evidence_id",
        "judge_verdict_json",
        "apply_status",
        "finding_id",
        "confirmed_findings_count",
    ]:
        assert compact in text


def test_final_answers_do_not_include_command_json() -> None:
    assert "command_json" in _node_data("select_ready_candidate")["code"]
    assert "command_json" not in _node_data("final_finding_report")["code"]
    for node_id in [
        "answer_finding_result",
        "answer_pending_verification",
        "answer_no_observations",
        "answer_no_ready_candidate",
    ]:
        assert "command_json" not in _node_data(node_id)["answer"]


def test_full_workflow_supports_planner_request_json() -> None:
    text = _full_text()
    assert "planner_request_json" in text
    assert '"include_blocked": True' in _node_data("normalize_inputs")["code"]
    assert "{{#normalize_inputs.planner_request_json#}}" in _http_body("call_planner_candidates")


def test_full_workflow_supports_judge_model_default() -> None:
    text = _full_text()
    code = _node_data("normalize_inputs")["code"]
    parse_code = _node_data("parse_judge_verdict")["code"]
    assert "judge_model" in text
    assert "bridge-full-backend-planner-dast-llm" in code
    assert "bridge-full-backend-planner-dast-llm" in parse_code
    assert "judge_model" in str(_node_data("llm_judge").get("prompt_template", ""))
