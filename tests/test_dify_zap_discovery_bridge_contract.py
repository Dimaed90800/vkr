"""Phase 11B ZAP discovery Dify bridge workflow contract tests."""
from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
ZAP_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-zap-discovery.yml"
REAL_BOLA_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
REAL_BOLA_LLM_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola-llm.yml"
LEGACY_MULTIAGENT_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _zap_text() -> str:
    return ZAP_WORKFLOW.read_text(encoding="utf-8")


def _zap_yaml() -> dict:
    return yaml.safe_load(_zap_text())


def _nodes_by_id() -> dict[str, dict]:
    return {
        node["id"]: node
        for node in _zap_yaml()["workflow"]["graph"]["nodes"]
    }


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def test_zap_discovery_workflow_exists() -> None:
    assert ZAP_WORKFLOW.exists()
    assert "wf-backend-bridge-zap-discovery" in _zap_text()


def test_zap_discovery_workflow_uses_zap_discovery_passive() -> None:
    text = _zap_text()
    assert '"tool_name": "zap_discovery_passive"' in text
    assert "Run ZAP Discovery Passive" in text


def test_zap_discovery_workflow_calls_campaign_create() -> None:
    assert "/v1/campaigns" in _zap_text()


def test_zap_discovery_workflow_calls_tools_runs_start() -> None:
    assert "/v1/tools/runs/start" in _zap_text()


def test_zap_discovery_workflow_calls_observations_normalize() -> None:
    text = _zap_text()
    assert "/v1/observations/normalize/" in text
    assert "{{#extract_tool_run.tool_run_id#}}" in _node_data("normalize_observations")["url"]


def test_zap_discovery_workflow_optionally_calls_observations_triage() -> None:
    text = _zap_text()
    assert "/v1/observations/triage/" in text
    assert "{{#summarize_observations.first_observation_id#}}" in _node_data("triage_observation")["url"]
    assert _node_data("has_observation")["type"] == "if-else"


def test_zap_discovery_workflow_does_not_call_judge_apply() -> None:
    assert "/v1/judge/apply" not in _zap_text()


def test_zap_discovery_workflow_does_not_call_evidence_or_findings() -> None:
    text = _zap_text()
    assert "/v1/evidence/" not in text
    assert "/v1/findings/" not in text


def test_zap_discovery_workflow_does_not_call_legacy_scheduler_or_wrappers() -> None:
    text = _zap_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text
    assert "/v1/tools/wrappers/execute" not in text


def test_zap_discovery_workflow_does_not_call_corpus_add() -> None:
    assert "/v1/corpus/add" not in _zap_text()


def test_zap_discovery_workflow_does_not_reference_active_scan() -> None:
    lowered = _zap_text().lower()
    assert "ascan" not in lowered
    assert "active_scan" not in lowered
    assert "active scan" not in lowered


def test_zap_discovery_payload_worker_class_discovery_inventory() -> None:
    assert '"worker_class": "discovery_inventory"' in _http_body("run_zap_discovery_passive")


def test_zap_discovery_payload_tool_name() -> None:
    assert '"tool_name": "zap_discovery_passive"' in _http_body("run_zap_discovery_passive")


def test_zap_discovery_payload_budget_max_requests_one() -> None:
    body = _http_body("run_zap_discovery_passive")
    replacements = {
        "{{#extract_campaign.campaign_id#}}": "cmp_test",
        "{{#normalize_inputs.task_id#}}": "task_test",
        "{{#normalize_inputs.target_url#}}": "http://target.local",
        "{{#normalize_inputs.zap_base_url#}}": "http://zap:8080",
        "{{#normalize_inputs.seed_urls_json#}}": "[]",
        "{{#normalize_inputs.use_spider_json#}}": "true",
        "{{#normalize_inputs.max_duration_sec#}}": "30",
        "{{#normalize_inputs.max_discovered_urls#}}": "100",
        "{{#normalize_inputs.max_alerts#}}": "100",
    }
    for before, after in replacements.items():
        body = body.replace(before, after)
    payload = json.loads(body)
    assert payload["execution_mode"] == "sync"
    assert payload["command"]["budget"]["max_requests"] == 1
    assert payload["command"]["budget"]["timeout_sec"] == 60


def test_zap_discovery_payload_contains_required_inputs() -> None:
    body = _http_body("run_zap_discovery_passive")
    for expected in [
        '"schema_version": "worker-command/v1"',
        '"strategy": "zap_discovery_passive"',
        '"operation_id": ""',
        '"seed_request_id": ""',
        '"target_url": "{{#normalize_inputs.target_url#}}"',
        '"zap_base_url": "{{#normalize_inputs.zap_base_url#}}"',
        '"seed_urls": {{#normalize_inputs.seed_urls_json#}}',
        '"use_spider": {{#normalize_inputs.use_spider_json#}}',
        '"use_ajax_spider": false',
        '"max_duration_sec": {{#normalize_inputs.max_duration_sec#}}',
        '"max_discovered_urls": {{#normalize_inputs.max_discovered_urls#}}',
        '"max_alerts": {{#normalize_inputs.max_alerts#}}',
        '"zap_discovery_completed"',
    ]:
        assert expected in body


def test_zap_discovery_observation_summary_prefers_zap_alert() -> None:
    code = _node_data("summarize_observations")["code"]
    assert "obs.get('type') == 'zap_alert'" in code
    assert "obs.get('type') == 'discovered_endpoint'" in code
    assert "selected = alerts[0] if alerts else (discovered[0] if discovered else {})" in code


def test_zap_discovery_workflow_has_no_observations_branch() -> None:
    text = _zap_text()
    assert "Has Observation?" in text
    assert "Answer No Observations" in text
    assert _node_data("answer_no_observations")["type"] == "answer"


def test_zap_discovery_workflow_has_partial_no_observations_message() -> None:
    answer = _node_data("answer_no_observations")["answer"]
    assert "ZAP produced partial result; no observations normalized." in answer
    assert "tool_result_status" in answer


def test_zap_discovery_workflow_compact_state_only() -> None:
    text = _zap_text()
    for forbidden in [
        "raw_json",
        "tool_result_json",
        "observation_json",
        "artifact_content",
        "raw alert evidence",
        "Authorization",
        "Cookie",
        "Bearer",
        "response_body",
        "request_body",
        "/v1/judge/apply",
        "/v1/evidence/",
        "/v1/findings/",
    ]:
        assert forbidden not in text
    for compact in [
        "campaign_id",
        "tool_run_id",
        "tool_result_status",
        "observations_count",
        "discovered_endpoints_count",
        "zap_alerts_count",
        "first_observation_id",
        "first_observation_type",
        "verification_plan_id",
    ]:
        assert compact in text


def test_existing_real_bola_workflows_still_exist() -> None:
    assert REAL_BOLA_WORKFLOW.exists()
    assert REAL_BOLA_LLM_WORKFLOW.exists()
    assert "wf-backend-bridge-real-bola" in REAL_BOLA_WORKFLOW.read_text(encoding="utf-8")
    assert "wf-backend-bridge-real-bola-llm" in REAL_BOLA_LLM_WORKFLOW.read_text(encoding="utf-8")


def test_legacy_multiagent_workflow_still_exists() -> None:
    assert LEGACY_MULTIAGENT_WORKFLOW.exists()
    legacy_text = LEGACY_MULTIAGENT_WORKFLOW.read_text(encoding="utf-8")
    assert "wf-multiagent-dast-tool-agents-judge" in legacy_text
