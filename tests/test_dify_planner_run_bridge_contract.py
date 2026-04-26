"""Phase 12B planner-run Dify bridge workflow contract tests."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
PLANNER_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-planner-run.yml"
SMOKE_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
REAL_BOLA_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
REAL_BOLA_LLM_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola-llm.yml"
ZAP_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-zap-discovery.yml"
LEGACY_MULTIAGENT_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _planner_text() -> str:
    return PLANNER_WORKFLOW.read_text(encoding="utf-8")


def _planner_yaml() -> dict:
    return yaml.safe_load(_planner_text())


def _nodes_by_id() -> dict[str, dict]:
    return {
        node["id"]: node
        for node in _planner_yaml()["workflow"]["graph"]["nodes"]
    }


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def test_planner_run_workflow_exists() -> None:
    assert PLANNER_WORKFLOW.exists()
    assert "wf-backend-bridge-planner-run" in _planner_text()


def test_planner_run_workflow_calls_campaign_create() -> None:
    assert "/v1/campaigns" in _planner_text()
    assert _node_data("create_campaign")["url"].endswith("/v1/campaigns")


def test_planner_run_workflow_optionally_builds_graph() -> None:
    text = _planner_text()
    assert "Has OpenAPI Spec?" in text
    assert "/v1/graph/{{#extract_campaign.campaign_id#}}/build" in text
    assert _node_data("has_openapi_spec")["type"] == "if-else"
    assert _node_data("skip_graph")["type"] == "code"
    assert "openapi_spec_text_json" in _node_data("normalize_inputs")["code"]


def test_planner_run_workflow_calls_planner_candidates() -> None:
    text = _planner_text()
    assert "/v1/planner/{{#extract_campaign.campaign_id#}}/candidates" in text
    assert _node_data("call_planner_candidates")["url"].endswith(
        "/v1/planner/{{#extract_campaign.campaign_id#}}/candidates"
    )


def test_planner_run_workflow_supports_planner_request_json() -> None:
    text = _planner_text()
    assert "planner_request_json" in text
    assert '"include_blocked": True' in _node_data("normalize_inputs")["code"]
    assert "{{#normalize_inputs.planner_request_json#}}" in _http_body("call_planner_candidates")
    assert '"{{#normalize_inputs.planner_request_json#}}"' not in _http_body("call_planner_candidates")


def test_planner_run_workflow_selects_first_ready_candidate() -> None:
    code = _node_data("select_ready_candidate")["code"]
    assert "candidate.get('status') == 'ready'" in code
    assert "isinstance(command, dict)" in code
    assert "has_ready_candidate" in code
    assert "command_json" in code


def test_planner_run_workflow_has_no_ready_candidate_branch() -> None:
    text = _planner_text()
    assert "Has Ready Candidate?" in text
    assert "Answer No Ready Candidate" in text
    assert "No ready planner candidate found." in text
    assert _node_data("has_ready_candidate")["type"] == "if-else"
    assert _node_data("answer_no_ready_candidate")["type"] == "answer"


def test_planner_run_workflow_calls_tools_runs_start() -> None:
    assert "/v1/tools/runs/start" in _planner_text()
    assert _node_data("run_selected_command")["url"].endswith("/v1/tools/runs/start")


def test_planner_run_workflow_sends_command_as_object_not_string() -> None:
    body = _http_body("run_selected_command")
    assert '"execution_mode": "sync"' in body
    assert '"command": {{#select_ready_candidate.command_json#}}' in body
    assert '"command": "{{#select_ready_candidate.command_json#}}"' not in body


def test_planner_run_workflow_calls_observations_normalize() -> None:
    text = _planner_text()
    assert "/v1/observations/normalize/" in text
    assert "{{#extract_tool_run.tool_run_id#}}" in _node_data("normalize_observations")["url"]


def test_planner_run_workflow_summarizes_observations() -> None:
    code = _node_data("summarize_observations")["code"]
    for expected in [
        "observations_count",
        "cross_role_access_count",
        "zap_alerts_count",
        "discovered_endpoints_count",
        "first_observation_id",
        "first_observation_type",
    ]:
        assert expected in code


def test_planner_run_workflow_observation_priority_cross_role_then_zap_then_discovered() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "obs.get('type') == 'cross_role_access_signal'" in code
    assert "obs.get('type') == 'zap_alert'" in code
    assert "obs.get('type') == 'discovered_endpoint'" in code
    assert "selected = cross[0] if cross else (alerts[0] if alerts else (discovered[0] if discovered else {}))" in code


def test_planner_run_workflow_has_no_observations_branch() -> None:
    text = _planner_text()
    assert "Has Observation?" in text
    assert "Answer No Observations" in text
    assert "Planner selected and ran a command, but no actionable observations were normalized." in text
    assert _node_data("answer_no_observations")["type"] == "answer"


def test_planner_run_workflow_calls_observations_triage() -> None:
    text = _planner_text()
    assert "/v1/observations/triage/" in text
    assert "{{#summarize_observations.first_observation_id#}}" in _node_data("triage_observation")["url"]


def test_planner_run_workflow_does_not_call_evidence() -> None:
    assert "/v1/evidence/" not in _planner_text()


def test_planner_run_workflow_does_not_call_judge_apply() -> None:
    assert "/v1/judge/apply" not in _planner_text()


def test_planner_run_workflow_does_not_call_findings() -> None:
    assert "/v1/findings/" not in _planner_text()


def test_planner_run_workflow_does_not_call_scheduler_or_wrappers() -> None:
    text = _planner_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text
    assert "/v1/tools/wrappers/execute" not in text


def test_planner_run_workflow_does_not_call_corpus_add() -> None:
    assert "/v1/corpus/add" not in _planner_text()


def test_planner_run_workflow_compact_state_only() -> None:
    text = _planner_text()
    for forbidden in [
        "raw_json",
        "tool_result_json",
        "observation_json",
        "planner_response_json",
        "artifact_content",
        "Authorization",
        "Cookie",
        "Bearer",
        "request_body",
        "response_body",
        "/v1/evidence/",
        "/v1/judge/apply",
        "/v1/findings/",
    ]:
        assert forbidden not in text
    for compact in [
        "campaign_id",
        "graph_built",
        "graph_status",
        "candidate_id",
        "candidate_kind",
        "ready_count",
        "blocked_count",
        "skipped_existing_count",
        "tool_run_id",
        "tool_result_status",
        "observations_count",
        "first_observation_id",
        "first_observation_type",
        "verification_plan_id",
    ]:
        assert compact in text


def test_planner_run_workflow_final_answer_does_not_include_command_json() -> None:
    assert "command_json" in _node_data("select_ready_candidate")["code"]
    assert "command_json" not in _node_data("final_report")["code"]
    assert "command_json" not in _node_data("answer_success")["answer"]
    assert "command_json" not in _node_data("answer_no_observations")["answer"]
    assert "command_json" not in _node_data("answer_no_ready_candidate")["answer"]


def test_existing_workflows_still_exist() -> None:
    for workflow in [
        SMOKE_WORKFLOW,
        REAL_BOLA_WORKFLOW,
        REAL_BOLA_LLM_WORKFLOW,
        ZAP_WORKFLOW,
        LEGACY_MULTIAGENT_WORKFLOW,
    ]:
        assert workflow.exists()
