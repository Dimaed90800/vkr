from __future__ import annotations

import json

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.campaign import Campaign, CampaignLimits
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


def _create_campaign(campaign_id: str = "cmp_report_route") -> None:
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


def _client() -> TestClient:
    return TestClient(app)


def test_report_context_get_unknown_campaign_404() -> None:
    _reset_store()
    resp = _client().get("/v1/reports/cmp_missing/context")
    assert resp.status_code == 404
    assert resp.json()["error"] == "campaign_not_found"


def test_report_context_get_existing_campaign_200() -> None:
    _reset_store()
    _create_campaign()
    resp = _client().get("/v1/reports/cmp_report_route/context")
    assert resp.status_code == 200
    body = resp.json()
    assert body["schema_version"] == "report-context/v1"
    assert body["campaign"]["campaign_id"] == "cmp_report_route"
    assert body["data_quality"]["runtime_state_attached"] is False


def test_report_context_post_with_runtime_snapshot_attached_true() -> None:
    _reset_store()
    _create_campaign()
    payload = {
        "runtime_state_snapshot": {
            "iterations_run": 3,
            "max_iterations": 5,
            "executed_by_kind": {"security_header_validator": 1},
            "tool_failures_count": 0,
        },
    }
    resp = _client().post("/v1/reports/cmp_report_route/context", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["data_quality"]["runtime_state_attached"] is True
    assert body["executive_summary"]["iterations_run"] == 3
    assert body["worker_execution_summary"]["executed_by_kind"]["security_header_validator"] == 1


def test_report_context_post_sanitizer_regression() -> None:
    _reset_store()
    _create_campaign()
    payload = {
        "runtime_state_snapshot": {
            "executed_by_kind": {"cookie_flag_validator": 1},
            "ready_candidates_sample": [
                {
                    "kind": "cookie_flag_validator",
                    "cookie_name_hash": "deadbeef",
                    "safe_text": "Authorization: Bearer abc",
                    "headers": {"Authorization": "Bearer secret"},
                },
            ],
        },
    }
    resp = _client().post("/v1/reports/cmp_report_route/context", json=payload)
    assert resp.status_code == 200
    blob = json.dumps(resp.json(), ensure_ascii=False)
    assert "cookie_flag_validator" in blob
    assert "cookie_name_hash" in blob
    assert "Authorization" not in blob
    assert "Bearer " not in blob
