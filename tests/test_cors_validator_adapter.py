"""Phase 19A-1 - cors validator adapter tests."""
from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.cors_validator_adapter import CorsValidatorAdapter
from backend.services.http.safe_http_client import SafeHttpClient


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_cors",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _command(**input_overrides) -> WorkerCommand:
    inputs = {
        "target_url": "http://target.local",
        "request_url": "http://target.local/api/v1/users?token=abc",
        "operation_id": "op_GET_/api/v1/users",
        "path_template": "/api/v1/users",
        "method": "GET",
        "origin_probe": "https://evil.example.invalid",
        "validation_mode": "single_replay_cors_check",
        "max_response_bytes": 262144,
    }
    inputs.update(input_overrides)
    return WorkerCommand(
        campaign_id="cmp_cors",
        worker_class="misconfiguration",
        strategy="validate_cors_policy",
        tool_name="cors_validator",
        operation_id=str(inputs.get("operation_id") or ""),
        inputs=inputs,
        budget=CommandBudget(max_requests=2, timeout_sec=15),
    )


def _adapter(headers: dict[str, str], *, status_code: int = 200) -> CorsValidatorAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text="secret-body")

    return CorsValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )


def test_wildcard_with_credentials_emits_validated_cors_issue() -> None:
    result = _adapter({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
    }).execute(_command(), _campaign(), "toolrun_cors")
    assert result.status == "finished"
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.observation_type == "validated_cors_issue"
    assert "cors_wildcard_with_credentials" in (obs.details.get("issue_codes") or [])


def test_reflected_origin_with_credentials_emits_validated_cors_issue() -> None:
    result = _adapter({
        "Access-Control-Allow-Origin": "https://evil.example.invalid",
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin",
    }).execute(_command(), _campaign(), "toolrun_cors")
    assert result.status == "finished"
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.observation_type == "validated_cors_issue"
    assert "cors_origin_reflection_with_credentials" in (obs.details.get("issue_codes") or [])


def test_safe_cors_policy_emits_no_observations() -> None:
    result = _adapter({
        "Access-Control-Allow-Origin": "https://app.example.com",
    }).execute(_command(), _campaign(), "toolrun_cors")
    assert result.status == "finished"
    assert result.observations == []


def test_weak_only_issue_emits_no_observations_in_mvp() -> None:
    result = _adapter({
        "Access-Control-Allow-Origin": "https://evil.example.invalid",
    }).execute(_command(), _campaign(), "toolrun_cors")
    assert result.status == "finished"
    assert result.observations == []


def test_details_have_no_raw_leakage_markers() -> None:
    result = _adapter({
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Credentials": "true",
        "Set-Cookie": "session=abc123; HttpOnly",
    }).execute(_command(), _campaign(), "toolrun_cors")
    assert result.status == "finished"
    assert result.observations
    blob = json.dumps(result.observations[0].details, sort_keys=True).lower()
    for bad in (
        "authorization",
        "cookie",
        "set-cookie",
        "request_body",
        "response_body",
        "headers",
        "bearer ",
        "token=",
        "abc123",
    ):
        assert bad not in blob
