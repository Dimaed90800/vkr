"""Phase API8-2 - cookie flag validator adapter tests."""
from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.cookie_flag_validator_adapter import CookieFlagValidatorAdapter
from backend.services.http.safe_http_client import SafeHttpClient


def _campaign(target_url: str = "https://target.local") -> Campaign:
    return Campaign(
        campaign_id="cmp_cookie",
        target_url=target_url,
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _command(**input_overrides) -> WorkerCommand:
    inputs = {
        "target_url": "https://target.local",
        "request_url": "https://target.local/api/v1/session?token=abc",
        "operation_id": "op_GET_/api/v1/session",
        "path_template": "/api/v1/session",
        "method": "GET",
        "validation_mode": "baseline_cookie_flag_check",
        "max_response_bytes": 262144,
    }
    inputs.update(input_overrides)
    return WorkerCommand(
        campaign_id="cmp_cookie",
        worker_class="misconfiguration",
        strategy="validate_cookie_flags",
        tool_name="cookie_flag_validator",
        operation_id=str(inputs.get("operation_id") or ""),
        inputs=inputs,
        budget=CommandBudget(max_requests=1, timeout_sec=15),
    )


def _adapter(headers: list[tuple[str, str]] | dict[str, str], *, status_code: int = 200) -> CookieFlagValidatorAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text="secret-body")

    return CookieFlagValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )


def test_missing_httponly_emits_validated_cookie_flag_issue() -> None:
    result = _adapter([
        ("Set-Cookie", "sessionid=abc123; Secure; SameSite=Lax"),
    ]).execute(_command(), _campaign(), "toolrun_cookie")
    assert result.status == "finished"
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.observation_type == "validated_cookie_flag_issue"
    assert "missing_httponly" in (obs.details.get("issue_codes") or [])


def test_missing_secure_emits_only_for_https() -> None:
    https_result = _adapter([
        ("Set-Cookie", "sessionid=abc123; HttpOnly; SameSite=Lax"),
    ]).execute(_command(), _campaign("https://target.local"), "toolrun_cookie_https")
    http_result = _adapter([
        ("Set-Cookie", "sessionid=abc123; HttpOnly; SameSite=Lax"),
    ]).execute(
        _command(target_url="http://target.local", request_url="http://target.local/api/v1/session"),
        _campaign("http://target.local"),
        "toolrun_cookie_http",
    )
    assert "missing_secure" in (https_result.observations[0].details.get("issue_codes") or [])
    assert http_result.observations == []


def test_samesite_none_without_secure_emits_issue() -> None:
    result = _adapter([
        ("Set-Cookie", "prefs=dark; HttpOnly; SameSite=None"),
    ]).execute(_command(), _campaign(), "toolrun_cookie")
    assert result.status == "finished"
    assert len(result.observations) == 1
    assert "samesite_none_without_secure" in (result.observations[0].details.get("issue_codes") or [])


def test_missing_samesite_only_emits_no_observations_in_mvp() -> None:
    result = _adapter([
        ("Set-Cookie", "prefs=dark; HttpOnly; Secure"),
    ]).execute(_command(), _campaign(), "toolrun_cookie")
    assert result.status == "finished"
    assert result.observations == []


def test_no_set_cookie_emits_no_observations() -> None:
    result = _adapter({"Content-Type": "application/json"}).execute(_command(), _campaign(), "toolrun_cookie")
    assert result.status == "finished"
    assert result.observations == []
    assert result.artifacts and result.artifacts[0].artifact_type == "cookie_flag_probe_summary"


def test_cookie_validator_details_and_artifacts_have_no_raw_leakage() -> None:
    result = _adapter([
        ("Set-Cookie", "sessionid=abc123; SameSite=None"),
        ("Set-Cookie", "Authorization=Bearer secret; Secure"),
    ]).execute(_command(), _campaign(), "toolrun_cookie")
    assert result.status == "finished"
    assert result.observations
    blob = json.dumps(
        {
            "details": result.observations[0].details,
            "artifact_type": result.artifacts[0].artifact_type,
        },
        sort_keys=True,
    ).lower()
    for bad in (
        "set-cookie",
        "abc123",
        "sessionid",
        "authorization",
        "request_body",
        "response_body",
        "headers",
        "bearer ",
        "token=",
    ):
        assert bad not in blob
