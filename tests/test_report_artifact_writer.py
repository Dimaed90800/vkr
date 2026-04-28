from __future__ import annotations

import json
from pathlib import Path

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


def _create_campaign(campaign_id: str = "cmp_report_artifacts") -> None:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://target.local",
        openapi_url="http://target.local/openapi.json",
        allowed_hosts=["target.local"],
        profile="safe",
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
        created_at="2026-04-28T00:00:00+00:00",
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))


def _client() -> TestClient:
    return TestClient(app)


def test_write_report_artifacts_creates_expected_files_and_summary() -> None:
    _reset_store()
    campaign_id = "cmp_report_artifacts_create"
    _create_campaign(campaign_id)
    memory_store.store_evidence_pack(
        "ev_1",
        campaign_id,
        "obs_1",
        "vp_1",
        {"evidence_id": "ev_1", "tool_name": "security_header_validator"},
    )
    memory_store.store_confirmed_finding(
        "f_1",
        campaign_id,
        "fp_1",
        {
            "finding_id": "f_1",
            "campaign_id": campaign_id,
            "evidence_id": "ev_1",
            "vulnerability_class": "security_header_misconfiguration",
            "endpoint": "/api/v1/vehicles",
            "method": "GET",
            "recommendation": "Set strict security headers.",
        },
    )
    resp = _client().post(
        f"/v1/reports/{campaign_id}/write-artifacts",
        json={"runtime_state_snapshot": {"iterations_run": 3, "max_iterations": 5}},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["confirmed_findings_count"] == 1
    for key in ("report_full_md", "report_confirmed_findings_md", "report_context_sanitized_json"):
        p = Path(body["paths"][key])
        assert p.exists()


def test_confirmed_report_contains_only_confirmed_findings_and_not_pending_or_diagnostics() -> None:
    _reset_store()
    campaign_id = "cmp_report_artifacts_confirmed_only"
    _create_campaign(campaign_id)
    memory_store.store_evidence_pack(
        "ev_2",
        campaign_id,
        "obs_2",
        "vp_2",
        {"evidence_id": "ev_2", "tool_name": "cors_validator"},
    )
    memory_store.store_confirmed_finding(
        "f_2",
        campaign_id,
        "fp_2",
        {
            "finding_id": "f_2",
            "campaign_id": campaign_id,
            "evidence_id": "ev_2",
            "vulnerability_class": "cors_misconfiguration",
            "endpoint": "/api/v1/accounts",
            "method": "GET",
            "recommendation": "Restrict allowed origins.",
        },
    )
    resp = _client().post(f"/v1/reports/{campaign_id}/write-artifacts", json={"runtime_state_snapshot": {}})
    assert resp.status_code == 200
    confirmed_text = Path(resp.json()["paths"]["report_confirmed_findings_md"]).read_text(encoding="utf-8")
    assert "f_2" in confirmed_text
    assert "pending_verification" not in confirmed_text
    assert "tool_failures" not in confirmed_text


def test_sanitized_context_has_no_secret_or_raw_object_fields() -> None:
    _reset_store()
    campaign_id = "cmp_report_artifacts_sanitized"
    _create_campaign(campaign_id)
    runtime = {
        "headers": {"Authorization": "Bearer super-secret"},
        "cookie": "session=abc",
        "request_body": {"password": "p@ss"},
        "raw_body": "{\"password\":\"p@ss\"}",
        "payload": {"token": "abc-token"},
        "object_id": "veh_12345",
        "raw_object_value": "veh_999",
    }
    resp = _client().post(f"/v1/reports/{campaign_id}/write-artifacts", json={"runtime_state_snapshot": runtime})
    assert resp.status_code == 200
    content = Path(resp.json()["paths"]["report_context_sanitized_json"]).read_text(encoding="utf-8")
    blob = json.loads(content)
    assert blob["schema_version"] == "report-context/v1"
    lowered = content.lower()
    for bad in ("super-secret", "veh_12345", "\"raw_object_value\"", "bearer ", "\"raw_body\""):
        assert bad not in lowered

    bad_keys_exact = {
        "password",
        "authorization",
        "cookie",
        "set-cookie",
        "request_body",
        "response_body",
        "raw_body",
        "object_id",
        "raw_object_value",
    }
    bad_value_parts = ("super-secret", "bearer ", "session=abc", "abc-token", "veh_12345")

    def _walk(value):
        if isinstance(value, dict):
                for k, v in value.items():
                    lk = str(k).lower()
                    assert lk not in bad_keys_exact
                    _walk(v)
        elif isinstance(value, list):
            for item in value:
                _walk(item)
        elif isinstance(value, str):
            lv = value.lower()
            assert not any(part in lv for part in bad_value_parts)

    _walk(blob)
