"""Phase 9A — http_replay_executor adapter tests."""
from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.http.safe_http_client import SafeHttpClient
from backend.services.tool_executor import ToolExecutor
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "corpus_items", "corpus_by_campaign", "resource_instances",
        "resources_by_campaign", "graphs_by_campaign", "commands",
        "commands_by_campaign", "command_fingerprints", "tool_runs",
        "tool_runs_by_campaign", "tool_results", "artifacts",
        "artifacts_by_run", "observations", "observations_by_campaign",
        "observations_by_tool_run", "verification_plans",
        "verification_plans_by_campaign",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_http_replay",
        target_url="http://crapi.local",
        allowed_hosts=["crapi.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
        roles_json=[
            {"name": "owner", "bearer_token": "owner-token"},
        ],
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _command(**overrides) -> WorkerCommand:
    defaults = {
        "campaign_id": "cmp_http_replay",
        "worker_class": "access_control",
        "strategy": "single_replay",
        "tool_name": "http_replay_executor",
        "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
        "inputs": {
            "method": "GET",
            "url": "http://crapi.local/api/v1/vehicles/veh_123",
            "path_template": "/api/v1/vehicles/{vehicleId}",
            "auth_profile": "owner",
            "body": {"password": "body-secret"},
        },
        "budget": CommandBudget(max_requests=3, timeout_sec=30),
    }
    defaults.update(overrides)
    return WorkerCommand(**defaults)


def test_http_replay_executor_stores_successful_exchange_in_corpus():
    _reset_store()
    _campaign()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer owner-token"
        return httpx.Response(200, json={"id": "veh_123", "secret": "response-secret"})

    result = ToolExecutor(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute_sync(_command())

    assert result.status == "finished"
    assert len(result.requests) == 1
    request_id = result.requests[0].request_id
    item = memory_store.get_corpus_item(request_id)
    assert item is not None
    assert item["source"] == "tool:http_replay_executor"
    assert item["source_tool_run_id"] == result.tool_run_id
    assert item["headers_redacted"]["Authorization"] == "<redacted>"
    assert item["body_redacted"]["password"] == "<redacted>"
    assert item["response_body_redacted"]["secret"] == "<redacted>"
    assert item["extracted_ids"]["vehicleId"] == ["veh_123"]


def test_http_replay_executor_blocked_host_returns_failed_without_corpus_item():
    _reset_store()
    _campaign()
    cmd = _command(inputs={
        "method": "GET",
        "url": "http://evil.local/api/v1/vehicles/veh_123",
        "path_template": "/api/v1/vehicles/{vehicleId}",
        "auth_profile": "owner",
    })

    result = ToolExecutor(
        http_client=SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    ).execute_sync(cmd)

    assert result.status == "failed"
    assert result.errors[0].error_type == "validation_failed"
    assert memory_store.list_corpus_by_campaign("cmp_http_replay") == []


def test_http_replay_executor_missing_auth_profile_returns_controlled_error():
    _reset_store()
    _campaign()
    cmd = _command(inputs={
        "method": "GET",
        "url": "http://crapi.local/api/v1/vehicles/veh_123",
        "path_template": "/api/v1/vehicles/{vehicleId}",
        "auth_profile": "ghost",
    })

    result = ToolExecutor(
        http_client=SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))
    ).execute_sync(cmd)

    assert result.status == "failed"
    assert result.errors[0].error_type == "validation_failed"


def test_http_replay_executor_artifact_does_not_contain_raw_secret():
    _reset_store()
    _campaign()
    result = ToolExecutor(
        http_client=SafeHttpClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "veh_123"}))
        )
    ).execute_sync(_command())

    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    serialized = json.dumps(artifact)
    assert "owner-token" not in serialized
    assert "body-secret" not in serialized


def test_http_replay_executor_stores_sanitized_url_in_result_artifact_and_corpus():
    _reset_store()
    _campaign()
    cmd = _command(inputs={
        "method": "GET",
        "url": "http://user:pass@crapi.local/api/v1/vehicles/veh_123?token=abc&id=123",
        "path_template": "/api/v1/vehicles/{vehicleId}",
        "auth_profile": "owner",
    })

    result = ToolExecutor(
        http_client=SafeHttpClient(
            transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "veh_123"}))
        )
    ).execute_sync(cmd)

    assert result.status == "finished"
    assert "user:pass@" not in result.requests[0].url
    assert "token=abc" not in result.requests[0].url
    item = memory_store.get_corpus_item(result.requests[0].request_id)
    assert item is not None
    assert "user:pass@" not in item["url"]
    assert "token=abc" not in item["url"]
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = json.dumps(artifact)
    assert "user:pass@" not in payload
    assert "token=abc" not in payload
