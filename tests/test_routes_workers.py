"""Routes under /v1/workers (capabilities + command stubs)."""
from __future__ import annotations

from fastapi.testclient import TestClient


def _client() -> TestClient:
    from backend.main import app

    return TestClient(app)


def test_capabilities_returns_schema_version() -> None:
    r = _client().get("/v1/workers/capabilities")
    assert r.status_code == 200
    body = r.json()
    assert body["schema_version"] == "worker-capability-catalog/v1"
    assert "counts" in body
    tools = {w["tool_name"] for w in body["workers"] if w.get("tool_name")}
    assert "schemathesis_negative_test" in tools


def test_capabilities_contains_schemathesis_negative_test() -> None:
    r = _client().get("/v1/workers/capabilities")
    assert r.status_code == 200
    match = [w for w in r.json()["workers"] if w.get("tool_name") == "schemathesis_negative_test"]
    assert len(match) == 1
    assert match[0]["status"] == "implemented"


def test_capabilities_by_tool_name_ok() -> None:
    r = _client().get("/v1/workers/capabilities/zap_discovery_passive")
    assert r.status_code == 200
    assert r.json()["tool_name"] == "zap_discovery_passive"


def test_capabilities_unknown_tool_returns_404() -> None:
    r = _client().get("/v1/workers/capabilities/nonexistent_tool_zzzz")
    assert r.status_code == 404
    assert r.json().get("detail", {}).get("code") == "worker_capability_not_found"
