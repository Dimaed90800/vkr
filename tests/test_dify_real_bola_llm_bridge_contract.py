"""Phase 10 real BOLA Dify bridge workflow with LLM Judge contract tests."""
from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
LLM_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola-llm.yml"
STATIC_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-real-bola.yml"
SMOKE_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
LEGACY_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"


def _text() -> str:
    return LLM_WORKFLOW.read_text(encoding="utf-8")


def _workflow() -> dict:
    return yaml.safe_load(_text())


def _nodes_by_id() -> dict[str, dict]:
    return {
        node["id"]: node
        for node in _workflow()["workflow"]["graph"]["nodes"]
    }


def _node_data(node_id: str) -> dict:
    return _nodes_by_id()[node_id]["data"]


def _http_body(node_id: str) -> str:
    return _node_data(node_id).get("body", {}).get("data", "")


def test_real_bola_llm_workflow_exists() -> None:
    assert LLM_WORKFLOW.exists()
    assert "wf-backend-bridge-real-bola-llm" in _text()


def test_real_bola_llm_workflow_contains_llm_node() -> None:
    nodes = _nodes_by_id()
    assert nodes["llm_judge"]["data"]["type"] == "llm"
    assert "LLM Judge" in _text()


def test_real_bola_llm_workflow_uses_bola_replay_probe() -> None:
    text = _text()
    assert "/v1/tools/runs/start" in text
    assert '"tool_name": "bola_replay_probe"' in text


def test_real_bola_llm_workflow_calls_judge_apply() -> None:
    assert "/v1/judge/apply" in _text()


def test_real_bola_llm_workflow_does_not_use_static_hardcoded_confirmed_verdict() -> None:
    text = _text()
    assert "Static Judge Verdict Payload" not in text
    assert "bridge-real-bola-static" not in text
    assert "'verdict': 'confirmed' if ready else 'rework'" not in text


def test_real_bola_llm_workflow_includes_strict_judge_verdict_payload_schema() -> None:
    llm_text = str(_node_data("llm_judge").get("prompt_template", ""))
    assert "JudgeVerdictPayload" in llm_text
    for field in [
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
        "confirmed|rejected|rework|duplicate|out_of_scope|inconclusive",
    ]:
        assert field in llm_text


def test_real_bola_llm_workflow_has_parse_validate_judge_verdict_node() -> None:
    parse = _node_data("parse_judge_verdict")
    code = parse["code"]
    assert parse["type"] == "code"
    assert "Parse/Validate Judge Verdict" in _text()
    assert "json.loads" in code
    assert "ALLOWED" in code
    assert "REQUIRED" in code
    assert "finding_candidate" in code


def test_real_bola_llm_workflow_has_invalid_json_fallback() -> None:
    code = _node_data("parse_judge_verdict")["code"]
    assert "invalid_llm_json" in code
    assert "LLM judge returned invalid JSON" in code
    assert "'verdict': 'inconclusive'" in code
    assert "'severity': 'info'" in code


def test_real_bola_llm_workflow_passes_verdict_as_object_not_string() -> None:
    body = _http_body("apply_judge_verdict")
    assert '"verdict": {{#parse_judge_verdict.judge_verdict_json#}}' in body
    assert '"verdict": "{{#parse_judge_verdict.judge_verdict_json#}}"' not in body


def test_real_bola_llm_workflow_uses_compact_evidence_summary() -> None:
    compact_code = _node_data("compact_evidence_for_judge")["code"]
    for field in [
        "campaign_id",
        "evidence_id",
        "observation_id",
        "verification_plan_id",
        "task_id",
        "operation_id",
        "endpoint",
        "method",
        "owasp_category",
        "vulnerability_class",
        "hypothesis",
        "judge_ready",
        "status",
        "missing_evidence",
        "confidence",
        "derived_signals",
        "has_baseline",
        "has_attack",
        "has_ownership_proof",
        "has_diff",
        "controls_count",
        "replay_steps_count",
        "artifact_refs_count",
        "baseline_ref",
        "attack_ref",
        "ownership_owner_collection_ref",
        "ownership_attacker_collection_ref",
        "control_refs",
        "replay_step_refs",
        "request_id",
        "role",
        "path_template",
        "status_code",
        "classification",
    ]:
        assert field in compact_code
    assert "judge_input_json" in compact_code


def test_real_bola_llm_workflow_does_not_pass_raw_headers_bodies_tokens_or_artifacts() -> None:
    text = _text()
    for forbidden in [
        "/v1/corpus/add",
        "cross-role-signals",
        "/v1/schedule/update-queue",
        "/v1/schedule/next-task",
        "/v1/tools/wrappers/execute",
        "Authorization",
        "Cookie",
        "bearer_token",
        "raw_body",
        "response_body",
        "artifact_content",
        "tool_result_json",
        "observation_json",
        "plan_json",
    ]:
        assert forbidden not in text


def test_static_real_bola_workflow_still_exists() -> None:
    assert STATIC_WORKFLOW.exists()
    assert "wf-backend-bridge-real-bola" in STATIC_WORKFLOW.read_text(encoding="utf-8")


def test_static_real_bola_workflow_still_has_static_judge() -> None:
    static_text = STATIC_WORKFLOW.read_text(encoding="utf-8")
    assert "Static Judge Verdict Payload" in static_text
    assert "type: llm" not in static_text


def test_legacy_multiagent_workflow_not_referenced_or_modified() -> None:
    legacy_text = LEGACY_WORKFLOW.read_text(encoding="utf-8")
    llm_text = _text()
    assert "wf-multiagent-dast-tool-agents-judge" in legacy_text
    assert "/v1/schedule/update-queue" in legacy_text
    assert "wf-multiagent-dast-tool-agents-judge" not in llm_text


def test_synthetic_smoke_workflow_still_exists() -> None:
    assert SMOKE_WORKFLOW.exists()
    assert "wf-backend-bridge-smoke" in SMOKE_WORKFLOW.read_text(encoding="utf-8")
