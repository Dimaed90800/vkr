"""Phase 9B real BOLA Dify bridge workflow contract tests."""
from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
REAL_BOLA_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
SYNTHETIC_SMOKE_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
LEGACY_MULTIAGENT_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _real_text() -> str:
    return REAL_BOLA_WORKFLOW.read_text(encoding="utf-8")


def _real_yaml() -> dict:
    return yaml.safe_load(_real_text())


def _nodes_by_id() -> dict[str, dict]:
    workflow = _real_yaml()["workflow"]
    return {node["id"]: node for node in workflow["graph"]["nodes"]}


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def test_real_bola_workflow_exists() -> None:
    assert REAL_BOLA_WORKFLOW.exists()
    assert "wf-backend-bridge-real-bola" in _real_text()


def test_real_bola_workflow_uses_bola_replay_probe() -> None:
    text = _real_text()
    assert '"tool_name": "bola_replay_probe"' in text
    assert "Run BOLA Replay Probe" in text


def test_real_bola_workflow_calls_tools_runs_start() -> None:
    assert "/v1/tools/runs/start" in _real_text()


def test_real_bola_workflow_calls_observations_normalize() -> None:
    assert "/v1/observations/normalize/" in _real_text()
    assert "{{#extract_tool_run.tool_run_id#}}" in _node_data("normalize_observations")["url"]


def test_real_bola_workflow_calls_judge_apply() -> None:
    assert "/v1/judge/apply" in _real_text()


def test_real_bola_workflow_lists_confirmed_findings() -> None:
    assert "/v1/findings/confirmed/" in _real_text()


def test_real_bola_workflow_does_not_call_synthetic_corpus_add() -> None:
    assert "/v1/corpus/add" not in _real_text()


def test_real_bola_workflow_does_not_call_corpus_cross_role_signals() -> None:
    assert "cross-role-signals" not in _real_text()


def test_real_bola_workflow_does_not_call_legacy_scheduler() -> None:
    text = _real_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text


def test_real_bola_workflow_does_not_call_legacy_wrappers_execute() -> None:
    assert "/v1/tools/wrappers/execute" not in _real_text()


def test_real_bola_workflow_payload_contains_required_bola_inputs() -> None:
    body = _http_body("run_bola_replay_probe")
    for expected in [
        '"execution_mode": "sync"',
        '"schema_version": "worker-command/v1"',
        '"worker_class": "access_control"',
        '"strategy": "prove_bola"',
        '"tool_name": "bola_replay_probe"',
        '"operation_id": "{{#normalize_inputs.operation_id#}}"',
        '"method": "GET"',
        '"object_url": "{{#normalize_inputs.object_url#}}"',
        '"attacker_own_object_url": "{{#normalize_inputs.attacker_own_object_url#}}"',
        '"collection_url": "{{#normalize_inputs.collection_url#}}"',
        '"path_template": "{{#normalize_inputs.path_template#}}"',
        '"collection_path_template": "{{#normalize_inputs.collection_path_template#}}"',
        '"collection_operation_id": "{{#normalize_inputs.collection_operation_id#}}"',
        '"object_id": "{{#normalize_inputs.object_id#}}"',
        '"attacker_own_object_id": "{{#normalize_inputs.attacker_own_object_id#}}"',
        '"owner_role": "{{#normalize_inputs.owner_role#}}"',
        '"attacker_role": "{{#normalize_inputs.attacker_role#}}"',
    ]:
        assert expected in body


def test_real_bola_workflow_budget_max_requests_at_least_five() -> None:
    body = _http_body("run_bola_replay_probe")
    static_body = body.replace("{{#extract_campaign.campaign_id#}}", "cmp_test")
    static_body = static_body.replace("{{#normalize_inputs.task_id#}}", "task_test")
    for variable in [
        "operation_id",
        "object_url",
        "attacker_own_object_url",
        "collection_url",
        "path_template",
        "collection_path_template",
        "collection_operation_id",
        "object_id",
        "attacker_own_object_id",
        "owner_role",
        "attacker_role",
    ]:
        static_body = static_body.replace(f"{{{{#normalize_inputs.{variable}#}}}}", variable)
    payload = json.loads(static_body)
    assert payload["command"]["budget"]["max_requests"] >= 5


def test_real_bola_workflow_uses_static_judge_verdict_payload() -> None:
    text = _real_text()
    static_judge_code = _node_data("static_judge_verdict")["code"]
    assert "Static Judge Verdict Payload" in text
    for required_field in [
        "schema_version",
        "judge-verdict/v1",
        "verdict",
        "confidence",
        "severity",
        "reason",
        "finding_candidate",
        "duplicate_of_finding_id",
        "judge_source",
        "judge_model",
    ]:
        assert required_field in static_judge_code
    apply_body = _http_body("apply_judge_verdict")
    assert '"verdict": {{#static_judge_verdict.judge_verdict_json#}}' in apply_body
    assert '"verdict": "{{#static_judge_verdict.judge_verdict_json#}}"' not in apply_body
    assert "type: llm" not in text


def test_real_bola_workflow_does_not_store_thick_intermediate_state_fields() -> None:
    text = _real_text()
    assert "tool_result_json" not in text
    assert "raw_json" not in text
    assert "observation_json" not in text
    assert "plan_json" not in text


def test_real_bola_workflow_has_no_signal_branch() -> None:
    text = _real_text()
    assert "has_cross_role_signal" in text
    assert "Answer No Signal" in text
    assert "No cross-role signal found / BOLA proof incomplete" in text
    assert _node_data("has_cross_role_signal")["type"] == "if-else"
    assert _node_data("answer_no_signal")["type"] == "answer"


def test_synthetic_smoke_workflow_still_exists() -> None:
    assert SYNTHETIC_SMOKE_WORKFLOW.exists()
    assert "wf-backend-bridge-smoke" in SYNTHETIC_SMOKE_WORKFLOW.read_text(encoding="utf-8")


def test_legacy_multiagent_workflow_unchanged_reference_not_modified() -> None:
    legacy_text = LEGACY_MULTIAGENT_WORKFLOW.read_text(encoding="utf-8")
    real_text = _real_text()
    assert LEGACY_MULTIAGENT_WORKFLOW.exists()
    assert "wf-multiagent-dast-tool-agents-judge" in legacy_text
    assert "/v1/schedule/update-queue" in legacy_text
    assert "/v1/schedule/next-task" in legacy_text
    assert "wf-multiagent-dast-tool-agents-judge" not in real_text
