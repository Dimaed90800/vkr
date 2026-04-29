from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.ssrf_probe_adapter import SsrfProbeAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.http.safe_http_client import SafeHttpClient
from backend.services.ssrf_callback_store import SsrfCallbackStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns",
        "auth_profiles",
        "auth_profiles_by_campaign",
        "runtime_token_secrets",
        "runtime_ssrf_callbacks",
        "runtime_ssrf_callbacks_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_ssrf_probe",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _cmd(
    *,
    auth_mode: str,
    auth_profile_id: str = "",
    request_draft: dict | None = None,
    required_body_fields: list[str] | None = None,
    allowed_body_fields: list[str] | None = None,
    body_field_summaries: list[dict] | None = None,
) -> WorkerCommand:
    inputs = {
        "validation_mode": "ssrf_callback_probe",
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path": "/api/hooks",
        "field_name": "callback_url",
        "field_path": "$.callback_url",
        "auth_mode": auth_mode,
        "auth_profile_id": auth_profile_id,
        "role_hint": "owner" if auth_profile_id else "",
    }
    if request_draft is not None:
        inputs["request_draft"] = request_draft
    if required_body_fields is not None:
        inputs["required_body_fields"] = required_body_fields
    if allowed_body_fields is not None:
        inputs["allowed_body_fields"] = allowed_body_fields
    if body_field_summaries is not None:
        inputs["body_field_summaries"] = body_field_summaries
        inputs["schema_summary_source"] = "api_graph"
    return WorkerCommand(
        campaign_id="cmp_ssrf_probe",
        worker_class="ssrf_external",
        strategy="callback_ssrf_probe",
        tool_name="ssrf_probe",
        inputs=inputs,
        budget=CommandBudget(max_requests=1, timeout_sec=15),
    )


def test_callback_received_emits_high_evidence_without_leaking_secrets() -> None:
    _reset_store()
    campaign = _campaign()

    owner = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_ssrf_probe",
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )

    calls = {"count": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["count"] += 1
        assert request.headers.get("authorization") == "Bearer owner-token"
        # Record callback for the correlation_id registered before the request.
        cid = next(iter(memory_store.runtime_ssrf_callbacks.keys()))
        SsrfCallbackStore().record_callback(
            correlation_id=cid,
            method="GET",
            path=f"/v1/callbacks/ssrf/{cid}",
            user_agent="unit-test",
            source_ip="10.0.0.10",
            headers_count=3,
        )
        return httpx.Response(200, json={"ok": True})

    result = SsrfProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(auth_mode="authenticated", auth_profile_id=owner.auth_profile_id), campaign, "toolrun_ssrf_1")

    det = result.observations[0].details
    assert det["result"] == "callback_received"
    assert det["callback_received"] is True
    assert det["evidence_strength"] == "high"
    assert calls["count"] == 1

    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("owner-token", "authorization", "cookie", "password", "raw_body", "response_body", "bearer "):
        assert bad not in blob


def test_no_callback_observed_is_diagnostic() -> None:
    _reset_store()
    campaign = _campaign()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    result = SsrfProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(auth_mode="unauthenticated"), campaign, "toolrun_ssrf_2")
    det = result.observations[0].details
    assert det["result"] == "no_callback_observed"
    assert det["callback_received"] is False
    assert det["evidence_strength"] == "low"


def test_target_non_2xx_still_high_if_callback_received() -> None:
    _reset_store()
    campaign = _campaign()

    def handler(_: httpx.Request) -> httpx.Response:
        cid = next(iter(memory_store.runtime_ssrf_callbacks.keys()))
        SsrfCallbackStore().record_callback(
            correlation_id=cid,
            method="POST",
            path=f"/v1/callbacks/ssrf/{cid}",
            user_agent="unit-test",
            source_ip="10.0.0.10",
            headers_count=3,
        )
        return httpx.Response(500, json={"error": "boom"})

    result = SsrfProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(auth_mode="unauthenticated"), campaign, "toolrun_ssrf_3")
    det = result.observations[0].details
    assert det["callback_received"] is True
    assert det["evidence_strength"] == "high"
    assert "target_non_2xx" in det["reason_codes"]


def test_valid_llm_request_draft_is_used_and_placeholder_replaced() -> None:
    _reset_store()
    campaign = _campaign()
    seen = {"body": None}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode("utf-8"))
        cid = next(iter(memory_store.runtime_ssrf_callbacks.keys()))
        SsrfCallbackStore().record_callback(
            correlation_id=cid, method="GET", path=f"/v1/callbacks/ssrf/{cid}"
        )
        return httpx.Response(200, json={"ok": True})

    draft = {
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path_template": "/api/hooks",
        "content_type": "application/json",
        "body_json": {"callback_url": "{{SSRF_CALLBACK_URL}}", "name": "test", "count": 1, "active": True},
        "query_params": {},
        "headers": {"Content-Type": "application/json"},
        "placeholders_used": ["SSRF_CALLBACK_URL"],
        "confidence": "medium",
        "composer": "llm",
        "reason_codes": ["llm_payload_composed"],
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(auth_mode="unauthenticated", request_draft=draft), campaign, "toolrun_ssrf_llm_1"
    )
    det = result.observations[0].details
    assert det["request_composer"] == "llm"
    assert det["request_draft_validated"] is True
    assert det["payload_synthesis_result"] == "llm_composed"
    assert isinstance(seen["body"], dict) and seen["body"]["callback_url"].startswith("http://")


def test_invalid_llm_request_draft_falls_back_safely() -> None:
    _reset_store()
    campaign = _campaign()
    seen = {"body": None}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    bad_draft = {
        "operation_id": "op_POST_/api/other",
        "method": "GET",
        "path_template": "/api/other",
        "content_type": "application/json",
        "body_json": {"callback_url": "http://localhost/x"},
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(auth_mode="unauthenticated", request_draft=bad_draft), campaign, "toolrun_ssrf_llm_2"
    )
    det = result.observations[0].details
    assert det["request_composer"] == "llm"
    assert det["request_draft_validated"] is False
    assert "draft_rejected" in det["payload_synthesis_result"]
    assert isinstance(seen["body"], dict)
    assert "callback_url" in seen["body"]  # deterministic fallback payload


def test_llm_draft_with_forbidden_secret_fields_is_rejected() -> None:
    _reset_store()
    campaign = _campaign()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    bad_draft = {
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path_template": "/api/hooks",
        "content_type": "application/json",
        "body_json": {"callback_url": "{{SSRF_CALLBACK_URL}}", "token": "secret"},
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(auth_mode="unauthenticated", request_draft=bad_draft), campaign, "toolrun_ssrf_llm_4"
    )
    det = result.observations[0].details
    assert det["request_draft_validated"] is False
    assert "draft_rejected" in det["payload_synthesis_result"]


def test_llm_draft_without_placeholder_is_rejected() -> None:
    _reset_store()
    campaign = _campaign()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    bad_draft = {
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path_template": "/api/hooks",
        "content_type": "application/json",
        "body_json": {"callback_url": "https://example.com/hook"},
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(auth_mode="unauthenticated", request_draft=bad_draft), campaign, "toolrun_ssrf_llm_5"
    )
    det = result.observations[0].details
    assert det["request_draft_validated"] is False
    assert "fallback" in det["payload_synthesis_result"]


def test_ssrf_probe_schema_synthesis_fills_required_fields() -> None:
    _reset_store()
    campaign = _campaign()
    seen = {"body": None}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(200, json={"ok": True})

    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(
            auth_mode="unauthenticated",
            required_body_fields=["callback_url", "problem_details", "number_of_repeats", "repeat_request_if_failed"],
            allowed_body_fields=["callback_url", "problem_details", "number_of_repeats", "repeat_request_if_failed"],
            body_field_summaries=[
                {"name": "callback_url", "schema_type": "string"},
                {"name": "problem_details", "schema_type": "string"},
                {"name": "number_of_repeats", "schema_type": "integer"},
                {"name": "repeat_request_if_failed", "schema_type": "boolean"},
            ],
        ),
        campaign,
        "toolrun_ssrf_schema_1",
    )
    body = seen["body"]
    assert isinstance(body, dict)
    assert body["callback_url"].startswith("http://")
    assert body["problem_details"] == "test"
    assert body["number_of_repeats"] == 1
    assert body["repeat_request_if_failed"] is True
    det = result.observations[0].details
    assert det["payload_synthesis_result"] == "schema_synthesized"


def test_ssrf_probe_schema_synthesis_skips_secret_like_required_field() -> None:
    _reset_store()
    campaign = _campaign()
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))).execute(
        _cmd(
            auth_mode="unauthenticated",
            required_body_fields=["callback_url", "password"],
            allowed_body_fields=["callback_url", "password"],
            body_field_summaries=[
                {"name": "callback_url", "schema_type": "string"},
                {"name": "password", "schema_type": "string"},
            ],
        ),
        campaign,
        "toolrun_ssrf_schema_2",
    )
    det = result.observations[0].details
    assert det["missing_required_fields_count"] >= 1


def test_ssrf_probe_always_emits_result_observation_on_400() -> None:
    _reset_store()
    campaign = _campaign()
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(lambda _: httpx.Response(400)))).execute(
        _cmd(auth_mode="unauthenticated"),
        campaign,
        "toolrun_ssrf_400",
    )
    assert result.observations
    det = result.observations[0].details
    assert det["result"] in {"target_4xx", "target_non_2xx", "no_callback_observed"}
    assert det["target_status_code"] == 400


def test_ssrf_probe_always_emits_result_observation_on_probe_error() -> None:
    _reset_store()
    campaign = _campaign()

    def _boom(_: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout")

    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(_boom))).execute(
        _cmd(auth_mode="unauthenticated"),
        campaign,
        "toolrun_ssrf_err",
    )
    assert result.observations
    det = result.observations[0].details
    assert det["result"] == "probe_error"
    assert "payload_synthesis_result" in det


def test_llm_request_draft_with_unknown_body_field_rejected() -> None:
    _reset_store()
    campaign = _campaign()
    draft = {
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path_template": "/api/hooks",
        "content_type": "application/json",
        "body_json": {"callback_url": "{{SSRF_CALLBACK_URL}}", "unknown": "x"},
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(lambda _: httpx.Response(200)))).execute(
        _cmd(
            auth_mode="unauthenticated",
            request_draft=draft,
            required_body_fields=["callback_url"],
            allowed_body_fields=["callback_url"],
            body_field_summaries=[{"name": "callback_url", "schema_type": "string"}],
        ),
        campaign,
        "toolrun_ssrf_schema_3",
    )
    det = result.observations[0].details
    assert det["request_draft_validated"] is False
    assert det["rejected_fields_count"] >= 1


def test_llm_draft_does_not_leak_body_or_headers_in_toolresult() -> None:
    _reset_store()
    campaign = _campaign()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"ok": True})

    draft = {
        "operation_id": "op_POST_/api/hooks",
        "method": "POST",
        "path_template": "/api/hooks",
        "content_type": "application/json",
        "body_json": {"callback_url": "{{SSRF_CALLBACK_URL}}", "name": "test"},
        "headers": {"Content-Type": "application/json"},
    }
    result = SsrfProbeAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(
        _cmd(auth_mode="unauthenticated", request_draft=draft), campaign, "toolrun_ssrf_llm_3"
    )
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("body_json", "authorization", "cookie", "token", "password", "raw_headers", "raw_body"):
        assert bad not in blob
