"""Phase 13B - security header validator adapter tests."""
from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.security_header_validator_adapter import SecurityHeaderValidatorAdapter
from backend.services.http.safe_http_client import SafeHttpClient
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
        "verification_plans_by_campaign", "evidence_packs",
        "evidence_packs_by_campaign", "evidence_packs_by_observation",
        "evidence_packs_by_verification_plan", "judge_decisions",
        "judge_decisions_by_campaign", "judge_decisions_by_evidence",
        "confirmed_findings", "confirmed_findings_by_campaign",
        "findings_by_fingerprint", "evidence_pack_apply_meta",
        "observation_apply_meta",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _campaign(
    campaign_id: str = "cmp_header",
    *,
    target_url: str = "http://target.local",
    allowed_hosts: list[str] | None = None,
) -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url=target_url,
        allowed_hosts=allowed_hosts or ["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _command(**input_overrides) -> WorkerCommand:
    inputs = {
        "request_url": "http://target.local/frame?token=abc",
        "target_url": "http://target.local/frame?token=abc",
        "method": "GET",
        "header_name": "X-Frame-Options",
        "alert_name": "X-Frame-Options Header Not Set",
        "auth_profile": "",
        "operation_id": "op_GET_/frame",
        "path_template": "/frame",
        "source_observation_id": "obs_zap_1",
        "max_response_bytes": 262144,
    }
    inputs.update(input_overrides)
    return WorkerCommand(
        campaign_id="cmp_header",
        worker_class="misconfiguration",
        strategy="validate_security_header",
        tool_name="security_header_validator",
        operation_id=str(inputs.get("operation_id") or ""),
        inputs=inputs,
        budget=CommandBudget(max_requests=1, timeout_sec=15),
    )


def _adapter_with_headers(headers: dict[str, str], *, status_code: int = 200) -> SecurityHeaderValidatorAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code, headers=headers, text="secret-body")

    return SecurityHeaderValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )


def test_x_frame_options_missing_emits_validated_issue():
    _reset_store()
    campaign = _campaign()

    result = _adapter_with_headers({}).execute(_command(), campaign, "toolrun_header")

    assert result.status == "finished"
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.observation_type == "validated_security_header_issue"
    assert obs.details["header_name"] == "X-Frame-Options"
    assert obs.details["actual_state"] == "missing"
    assert obs.details["url"] == "http://target.local/frame?token=%3Credacted%3E"


def test_x_frame_options_sameorigin_no_observation():
    _reset_store()
    campaign = _campaign()

    result = _adapter_with_headers({"X-Frame-Options": "SAMEORIGIN"}).execute(
        _command(),
        campaign,
        "toolrun_header",
    )

    assert result.status == "finished"
    assert result.observations == []


def test_x_content_type_options_wrong_value_emits_issue():
    _reset_store()
    campaign = _campaign()
    cmd = _command(
        header_name="X-Content-Type-Options",
        alert_name="X-Content-Type-Options Header Missing",
    )

    result = _adapter_with_headers({"X-Content-Type-Options": "invalid"}).execute(
        cmd,
        campaign,
        "toolrun_header",
    )

    assert result.status == "finished"
    assert len(result.observations) == 1
    assert result.observations[0].details["actual_state"] == "unsafe_value"
    assert result.observations[0].details["actual_value_redacted"] == "invalid"


def test_content_security_policy_missing_emits_issue():
    _reset_store()
    campaign = _campaign()
    cmd = _command(
        header_name="Content-Security-Policy",
        alert_name="Content Security Policy (CSP) Header Not Set",
    )

    result = _adapter_with_headers({}).execute(cmd, campaign, "toolrun_header")

    assert result.status == "finished"
    assert len(result.observations) == 1
    assert result.observations[0].details["actual_state"] == "missing"


def test_hsts_missing_on_https_emits_issue():
    _reset_store()
    campaign = _campaign(
        target_url="https://target.local",
        allowed_hosts=["target.local"],
    )
    cmd = _command(
        request_url="https://target.local/secure",
        target_url="https://target.local/secure",
        header_name="Strict-Transport-Security",
        alert_name="Strict-Transport-Security Header Not Set",
        path_template="/secure",
    )

    result = _adapter_with_headers({}).execute(cmd, campaign, "toolrun_header")

    assert result.status == "finished"
    assert len(result.observations) == 1
    assert result.observations[0].details["actual_state"] == "missing"


def test_hsts_missing_on_http_no_observation():
    _reset_store()
    campaign = _campaign()
    cmd = _command(
        header_name="Strict-Transport-Security",
        alert_name="Strict-Transport-Security Header Not Set",
    )

    result = _adapter_with_headers({}).execute(cmd, campaign, "toolrun_header")

    assert result.status == "finished"
    assert result.observations == []
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = json.loads(artifact["content"])
    assert payload["diagnostic_reason"] == "hsts_not_applicable_to_http"


def test_out_of_scope_url_fails_before_request():
    _reset_store()
    campaign = _campaign()
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200)

    adapter = SecurityHeaderValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    cmd = _command(
        request_url="http://evil.local/frame",
        target_url="http://evil.local/frame",
    )

    result = adapter.execute(cmd, campaign, "toolrun_header")

    assert result.status == "failed"
    assert result.errors[0].error_type == "host_not_allowed"
    assert called["count"] == 0


def test_unsupported_header_returns_failed_controlled_error():
    _reset_store()
    campaign = _campaign()
    cmd = _command(
        header_name="X-Powered-By",
        alert_name="X-Powered-By Header Exposed",
    )

    result = _adapter_with_headers({}).execute(cmd, campaign, "toolrun_header")

    assert result.status == "failed"
    assert result.errors[0].error_type == "unsupported_security_header"


def test_supported_header_with_wrong_alert_name_returns_unsupported_alert_mapping_without_request():
    _reset_store()
    campaign = _campaign()
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200)

    adapter = SecurityHeaderValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    cmd = _command(
        header_name="X-Frame-Options",
        alert_name="Wrong Alert Name",
    )

    result = adapter.execute(cmd, campaign, "toolrun_header")

    assert result.status == "failed"
    assert result.errors[0].error_type == "unsupported_alert_mapping"
    assert result.observations == []
    assert called["count"] == 0


def test_supported_header_with_empty_alert_name_returns_unsupported_alert_mapping_without_request():
    _reset_store()
    campaign = _campaign()
    called = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        called["count"] += 1
        return httpx.Response(200)

    adapter = SecurityHeaderValidatorAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    cmd = _command(
        header_name="X-Frame-Options",
        alert_name="",
    )

    result = adapter.execute(cmd, campaign, "toolrun_header")

    assert result.status == "failed"
    assert result.errors[0].error_type == "unsupported_alert_mapping"
    assert result.observations == []
    assert called["count"] == 0


def test_artifact_redacts_url_userinfo_and_query():
    _reset_store()
    campaign = _campaign()
    cmd = _command(
        request_url="http://user:pass@target.local/frame?token=abc&x=1",
        target_url="http://user:pass@target.local/frame?token=abc&x=1",
    )

    result = _adapter_with_headers({}).execute(cmd, campaign, "toolrun_header")

    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = artifact["content"]
    assert "user:pass@" not in payload
    assert "token=abc" not in payload
    assert "x=1" not in payload
    assert "%3Credacted%3E" in payload


def test_no_raw_headers_or_body_in_artifacts():
    _reset_store()
    campaign = _campaign()
    result = _adapter_with_headers({
        "Set-Cookie": "session=secret",
        "X-Frame-Options": "ALLOW-FROM https://evil.test",
    }).execute(_command(), campaign, "toolrun_header")

    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    assert artifact is not None
    payload = artifact["content"]
    assert "Set-Cookie" not in payload
    assert "session=secret" not in payload
    assert "secret-body" not in payload
    assert "Authorization" not in payload


def test_adapter_does_not_create_evidence_judge_finding():
    _reset_store()
    campaign = _campaign()

    result = _adapter_with_headers({}).execute(_command(), campaign, "toolrun_header")

    assert result.status == "finished"
    assert memory_store.evidence_packs == {}
    assert memory_store.judge_decisions == {}
    assert memory_store.confirmed_findings == {}
    assert memory_store.evidence_records == []
    assert memory_store.findings == []
