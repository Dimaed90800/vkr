from __future__ import annotations

import json

import httpx
from unittest.mock import patch

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.undocumented_endpoint_validator_adapter import (
    UndocumentedEndpointValidatorAdapter,
)
from backend.services.http.safe_http_client import SafeHttpClient, SafeHttpError
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_undoc",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _command(**input_overrides) -> WorkerCommand:
    payload = {
        "campaign_id": "cmp_undoc",
        "worker_class": "discovery_inventory",
        "strategy": "validate_undocumented_endpoint",
        "tool_name": "undocumented_endpoint_validator",
        "inputs": {
            "target_url": "http://target.local",
            "request_url": "http://target.local/api/hidden?token=abc",
            "method": "GET",
            "path": "/api/hidden",
            "source_observation_id": "obs_disc_1",
            "validation_mode": "one_shot_undocumented_endpoint_check",
            "max_response_bytes": 262144,
        },
        "budget": CommandBudget(max_requests=1, timeout_sec=15),
    }
    payload["inputs"].update(input_overrides)
    return WorkerCommand(**payload)


def test_undocumented_endpoint_validator_emits_signal_for_non_404() -> None:
    _reset_store()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    adapter = UndocumentedEndpointValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler)),
    )
    result = adapter.execute(_command(), _campaign(), "toolrun_undoc")
    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations] == ["undocumented_endpoint_signal"]
    details = result.observations[0].details
    assert details["path"] == "/api/hidden"
    assert details["status_code"] == 200
    assert details["openapi_match"] is False
    blob = json.dumps(result.model_dump(mode="json")).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=abc", "request_body", "response_body", "raw_body", "headers", "bearer "):
        assert bad not in blob


def test_undocumented_endpoint_validator_404_returns_no_observations() -> None:
    _reset_store()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404, json={"error": "not found"})

    adapter = UndocumentedEndpointValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler)),
    )
    result = adapter.execute(_command(), _campaign(), "toolrun_undoc_404")
    assert result.status == "finished"
    assert result.observations == []
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    content = json.loads(str(artifact.get("content") or "{}"))
    assert content.get("result") == "not_found"


def test_undocumented_validator_response_too_large_with_non_404_still_emits_signal() -> None:
    _reset_store()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            text='{"token":"abc","note":"Authorization: Bearer supersecret"}',
        )

    adapter = UndocumentedEndpointValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler)),
    )
    result = adapter.execute(
        _command(max_response_bytes=8),
        _campaign(),
        "toolrun_undoc_too_large_non404",
    )
    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations] == ["undocumented_endpoint_signal"]
    details = result.observations[0].details
    assert details["status_code"] == 200
    assert details["response_truncated"] is True
    assert "response_too_large_metadata_only" in details.get("reason_codes", [])
    blob = json.dumps(
        {"result": result.model_dump(mode="json"), "artifact": memory_store.get_artifact(result.artifacts[0].artifact_id)},
        sort_keys=True,
    ).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=abc", "request_body", "response_body", "raw_body", "headers", "bearer ", "supersecret"):
        assert bad not in blob


def test_undocumented_validator_response_too_large_with_404_returns_no_observations_finished() -> None:
    _reset_store()

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            404,
            headers={"Content-Type": "application/json"},
            text='{"error":"not found","cookie":"session=abc123"}',
        )

    adapter = UndocumentedEndpointValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler)),
    )
    result = adapter.execute(
        _command(max_response_bytes=8),
        _campaign(),
        "toolrun_undoc_too_large_404",
    )
    assert result.status == "finished"
    assert result.observations == []
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    content = json.loads(str(artifact.get("content") or "{}"))
    assert content.get("result") == "not_found"
    assert content.get("reason_codes") == ["response_too_large_404"]
    blob = json.dumps(
        {"result": result.model_dump(mode="json"), "artifact": artifact},
        sort_keys=True,
    ).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=abc", "request_body", "response_body", "raw_body", "headers", "bearer ", "abc123"):
        assert bad not in blob


def test_undocumented_validator_response_too_large_recovers_status_from_error_details_non404() -> None:
    _reset_store()
    adapter = UndocumentedEndpointValidatorAdapter()
    safe_error = SafeHttpError(
        code="response_too_large",
        message="HTTP response exceeded max_response_bytes.",
        details={"status_code": 201, "max_response_bytes": 8},
    )

    class _Result:
        method = "GET"
        url = "http://target.local/api/hidden?token=abc"
        status_code = 0
        error = safe_error

    with patch.object(adapter._http, "request", return_value=_Result()):
        result = adapter.execute(_command(max_response_bytes=8), _campaign(), "toolrun_undoc_details_201")

    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations] == ["undocumented_endpoint_signal"]
    details = result.observations[0].details
    assert details["status_code"] == 201
    assert details["response_truncated"] is True
    assert "response_too_large_metadata_only" in details.get("reason_codes", [])


def test_undocumented_validator_response_too_large_recovers_status_from_error_metadata_404() -> None:
    _reset_store()
    adapter = UndocumentedEndpointValidatorAdapter()
    safe_error = SafeHttpError(
        code="response_too_large",
        message="HTTP response exceeded max_response_bytes.",
        details={},
    )
    setattr(safe_error, "metadata", {"status_code": 404})

    class _Result:
        method = "GET"
        url = "http://target.local/api/hidden?token=abc"
        status_code = 0
        error = safe_error

    with patch.object(adapter._http, "request", return_value=_Result()):
        result = adapter.execute(_command(max_response_bytes=8), _campaign(), "toolrun_undoc_metadata_404")

    assert result.status == "finished"
    assert result.observations == []
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    content = json.loads(str(artifact.get("content") or "{}"))
    assert content.get("result") == "not_found"
    assert content.get("reason_codes") == ["response_too_large_404"]
