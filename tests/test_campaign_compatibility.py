"""Phase 1 — Campaign compatibility layer tests.

Validates that the new campaign model works without breaking
existing run_id/session logic or health endpoints.
"""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.campaign_service import CampaignService
from backend.storage.memory_store import memory_store


def _reset_memory_store() -> None:
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()
    memory_store.campaigns.clear()
    memory_store.campaign_by_run_id.clear()
    memory_store.campaign_by_session_id.clear()


def _fresh_client() -> TestClient:
    _reset_memory_store()
    return TestClient(app)


def test_campaign_create_returns_campaign_id() -> None:
    client = _fresh_client()
    response = client.post(
        "/v1/campaigns",
        json={
            "target_url": "http://localhost:8888",
            "openapi_url": "http://localhost:8888/openapi.json",
            "allowed_hosts": ["localhost"],
            "profile": "safe",
            "limits": {
                "max_requests": 500,
                "max_duration_sec": 900,
                "max_iterations": 30,
                "max_retries_per_task": 2,
            },
            "roles_json": [],
        },
    )
    assert response.status_code == 201
    payload = response.json()
    assert payload["campaign_id"].startswith("cmp_")
    assert payload["run_id"].startswith("run-")
    assert payload["status"] == "running"


def test_campaign_summary_contains_budget_and_counts() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns",
        json={
            "target_url": "http://localhost:8888",
            "openapi_url": "http://localhost:8888/openapi.json",
            "limits": {"max_requests": 200},
        },
    )
    assert create_response.status_code == 201
    created = create_response.json()
    campaign_id = created["campaign_id"]

    campaign_response = client.get(f"/v1/campaigns/{campaign_id}")
    assert campaign_response.status_code == 200
    campaign_payload = campaign_response.json()
    assert campaign_payload["campaign_id"] == campaign_id
    assert campaign_payload["run_id"] == created["run_id"]

    summary_response = client.get(f"/v1/campaigns/{campaign_id}/summary")
    assert summary_response.status_code == 200
    summary = summary_response.json()

    assert summary["campaign_id"] == campaign_id
    assert summary["run_id"] == created["run_id"]
    assert summary["status"] == "running"
    assert summary["target_url"] == "http://localhost:8888"
    assert "openapi_url" in summary
    assert "limits" in summary
    assert "budget" in summary
    assert "counts" in summary
    assert "stop_reason" in summary
    assert summary["stop_reason"] is None

    assert summary["limits"]["max_requests"] == 200
    assert "max_duration_sec" in summary["limits"]
    assert "max_iterations" in summary["limits"]
    assert "max_retries_per_task" in summary["limits"]

    assert "max_requests" in summary["budget"]
    assert "used_requests" in summary["budget"]
    assert "remaining_requests" in summary["budget"]
    assert "max_duration_sec" in summary["budget"]
    assert summary["budget"]["max_requests"] == 200
    assert summary["budget"]["used_requests"] == 0
    assert summary["budget"]["remaining_requests"] == 200

    assert "operations" in summary["counts"]
    assert "corpus_items" in summary["counts"]
    assert "pending_tasks" in summary["counts"]
    assert "confirmed_findings" in summary["counts"]
    assert "tool_runs" in summary["counts"]
    assert summary["counts"]["operations"] == 0
    assert summary["counts"]["corpus_items"] == 0
    assert summary["counts"]["pending_tasks"] == 0
    assert summary["counts"]["confirmed_findings"] == 0
    assert summary["counts"]["tool_runs"] == 0


def test_legacy_run_id_maps_to_campaign_id() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns",
        json={
            "target_url": "http://localhost:9999",
            "openapi_url": "http://localhost:9999/openapi.json",
        },
    )
    assert create_response.status_code == 201
    created = create_response.json()
    campaign_id = created["campaign_id"]
    run_id = created["run_id"]

    svc = CampaignService()
    assert svc.resolve_campaign_id(run_id) == campaign_id
    assert svc.resolve_run_id(campaign_id) == run_id


def test_campaign_summary_preserves_existing_run_state_if_present() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns",
        json={
            "target_url": "http://localhost:8888",
            "limits": {"max_requests": 100},
        },
    )
    assert create_response.status_code == 201
    campaign_id = create_response.json()["campaign_id"]

    memory_store.store_evidence(campaign_id, {"task_id": "t1", "content": {}})
    memory_store.store_finding(
        campaign_id, {"title": "BOLA", "severity": "high", "details": {}}
    )

    summary_response = client.get(f"/v1/campaigns/{campaign_id}/summary")
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["budget"]["used_requests"] == 1
    assert summary["budget"]["remaining_requests"] == 99
    assert summary["counts"]["confirmed_findings"] == 1


def test_campaign_create_does_not_break_health_endpoint() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns",
        json={"target_url": "http://localhost:8888"},
    )
    assert create_response.status_code == 201

    health_response = client.get("/health")
    assert health_response.status_code == 200
    payload = health_response.json()
    assert payload["status"] == "ok"
