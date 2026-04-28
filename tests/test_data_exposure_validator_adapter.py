from __future__ import annotations

import json
import re

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.data_exposure_validator_adapter import DataExposureValidatorAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.http.safe_http_client import SafeHttpClient
from backend.storage.memory_store import memory_store


def _reset() -> None:
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()
    memory_store.auth_profiles.clear()
    memory_store.auth_profiles_by_campaign.clear()
    memory_store.runtime_token_secrets.clear()
    memory_store.runtime_credential_secrets.clear()
    memory_store.runtime_response_json_secrets.clear()


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_dex",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _cmd(**kw) -> WorkerCommand:
    base = {
        "target_url": "http://target.local",
        "request_url": "http://target.local/api/profile",
        "operation_id": "op_GET_/api/profile",
        "path_template": "/api/profile",
        "method": "GET",
        "validation_mode": "response_field_inventory_check",
        "max_response_bytes": 262144,
        "max_depth": 6,
        "max_fields": 200,
    }
    base.update(kw)
    return WorkerCommand(
        campaign_id="cmp_dex",
        worker_class="access_control",
        strategy="validate_response_field_exposure",
        tool_name="data_exposure_validator",
        operation_id=str(base.get("operation_id") or ""),
        inputs=base,
        budget=CommandBudget(max_requests=1, timeout_sec=15),
    )


def _adapter(body: str, status: int = 200, content_type: str = "application/json") -> DataExposureValidatorAdapter:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, headers={"Content-Type": content_type}, text=body)

    return DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))


def test_data_exposure_emits_inventory_and_signal_for_sensitive_fields() -> None:
    _reset()
    body = json.dumps({"email": "x@y.z", "role": "admin", "vehicleId": "v1", "public": 1})
    r = _adapter(body).execute(_cmd(), _campaign(), "tr1")
    assert r.status == "finished"
    types = [o.observation_type for o in r.observations]
    assert types == ["response_field_inventory", "data_exposure_signal", "data_exposure_probe_result"]
    inv = r.observations[0].details
    assert inv.get("field_count") == 4
    assert inv.get("sensitive_field_count") == 3
    sig = r.observations[1].details
    assert sig.get("sensitive_field_count") == 3
    assert "identity" in (sig.get("sensitive_categories") or [])
    probe = r.observations[2].details
    assert probe.get("result") == "sensitive_fields_found"
    assert probe.get("field_count") == 4
    assert probe.get("sensitive_field_count") == 3


def test_data_exposure_inventory_only_for_public_fields() -> None:
    _reset()
    body = json.dumps({"public": 1, "count": 2, "label": "ok"})
    r = _adapter(body).execute(_cmd(), _campaign(), "tr2")
    assert [o.observation_type for o in r.observations] == ["response_field_inventory", "data_exposure_probe_result"]
    assert r.observations[0].details.get("sensitive_field_count") == 0
    assert r.observations[1].details.get("result") == "fields_extracted"


def test_data_exposure_non_json_emits_probe_only() -> None:
    _reset()
    r = _adapter("<html></html>", content_type="text/html").execute(_cmd(), _campaign(), "tr3")
    assert r.status == "finished"
    assert len(r.observations) == 1
    assert r.observations[0].observation_type == "data_exposure_probe_result"
    det = r.observations[0].details
    assert det.get("result") == "non_json_response"
    assert det.get("status_code") == 200
    assert "text/html" in str(det.get("content_type") or "")
    art = memory_store.get_artifact(r.artifacts[0].artifact_id)
    c = json.loads(str(art.get("content") or "{}"))
    assert c.get("result") == "non_json_response"


def test_data_exposure_non_200_emits_probe_only() -> None:
    _reset()
    r = _adapter("{}", status=404).execute(_cmd(), _campaign(), "tr4")
    assert r.status == "finished"
    assert len(r.observations) == 1
    assert r.observations[0].observation_type == "data_exposure_probe_result"
    assert r.observations[0].details.get("result") == "non_200_response"
    assert r.observations[0].details.get("status_code") == 404
    art = memory_store.get_artifact(r.artifacts[0].artifact_id)
    c = json.loads(str(art.get("content") or "{}"))
    assert c.get("result") == "non_200_response"


def test_data_exposure_json_parse_failed_emits_probe() -> None:
    _reset()
    r = _adapter('{"a":', content_type="application/json").execute(_cmd(), _campaign(), "tr_parse")
    assert r.status == "finished"
    assert len(r.observations) == 1
    det = r.observations[0].details
    assert det.get("result") == "json_parse_failed"
    assert det.get("reason_codes") == ["json_parse_failed"]
    art = memory_store.get_artifact(r.artifacts[0].artifact_id)
    c = json.loads(str(art.get("content") or "{}"))
    assert c.get("result") == "json_parse_failed"


def test_data_exposure_empty_body_emits_empty_response_probe() -> None:
    _reset()
    r = _adapter("", content_type="application/json").execute(_cmd(), _campaign(), "tr_empty")
    assert r.status == "finished"
    assert len(r.observations) == 1
    assert r.observations[0].details.get("result") == "empty_response"


def test_data_exposure_respects_max_depth() -> None:
    _reset()
    body = json.dumps({"a": {"b": {"c": {"d": {"e": {"f": 1}}}}}})
    r = _adapter(body).execute(
        _cmd(max_depth=2, request_url="http://target.local/api/x", path_template="/api/x", operation_id="op_x"),
        _campaign(),
        "tr5",
    )
    inv = r.observations[0].details
    assert inv.get("field_count", 0) < 3
    assert r.observations[-1].observation_type == "data_exposure_probe_result"


def test_data_exposure_respects_max_fields() -> None:
    _reset()
    big = {f"k{i}": i for i in range(50)}
    body = json.dumps(big)
    r = _adapter(body).execute(
        _cmd(max_fields=5, request_url="http://target.local/api/big", path_template="/api/big", operation_id="op_big"),
        _campaign(),
        "tr6",
    )
    assert r.observations[0].details.get("field_count") == 5
    assert r.observations[-1].observation_type == "data_exposure_probe_result"


def test_data_exposure_no_raw_leakage() -> None:
    _reset()
    body = json.dumps({"email": "secret@x.com", "note": "x"})
    r = _adapter(body).execute(_cmd(), _campaign(), "tr7")
    blob = json.dumps(r.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("secret@x.com", "request_body", "response_body", "set-cookie"):
        assert bad not in blob
    probe = next(o for o in r.observations if o.observation_type == "data_exposure_probe_result")
    pb = json.dumps(probe.details, sort_keys=True).lower()
    assert "secret@x.com" not in pb
    assert "field_names_sample" not in probe.details
    assert "sensitive_fields" not in probe.details


def test_authenticated_data_exposure_adds_authorization_internally_and_emits_safe_auth_metadata() -> None:
    _reset()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_dex",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token-123",
        created_by="test_account_materializer",
        metadata={"token_field_path": "$.token"},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer owner-token-123"
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text=json.dumps({"email": "x@y.z", "public": 1}))

    adapter = DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    r = adapter.execute(
        _cmd(auth_mode="authenticated", auth_profile_id=profile.auth_profile_id),
        _campaign(),
        "tr_auth_1",
    )
    assert r.status == "finished"
    inv = r.observations[0].details
    probe = r.observations[-1].details
    assert inv.get("auth_mode") == "authenticated"
    assert inv.get("auth_profile_id") == profile.auth_profile_id
    assert inv.get("role_hint") == "owner"
    assert probe.get("auth_mode") == "authenticated"
    assert probe.get("auth_profile_id") == profile.auth_profile_id


def test_authenticated_data_exposure_no_raw_authorization_or_token_leakage() -> None:
    _reset()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_dex",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token-secret",
        created_by="test_account_materializer",
        metadata={"token_field_path": "$.access_token"},
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"Content-Type": "application/json"}, text=json.dumps({"email": "secret@x.com"}))

    adapter = DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    r = adapter.execute(
        _cmd(auth_mode="authenticated", auth_profile_id=profile.auth_profile_id),
        _campaign(),
        "tr_auth_2",
    )
    blob = json.dumps(r.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("owner-token-secret", "bearer ", "set-cookie"):
        assert bad not in blob
    assert re.search(r'\"authorization\"\s*:', blob) is None
    assert re.search(r'\"cookie\"\s*:', blob) is None
    art = memory_store.get_artifact(r.artifacts[0].artifact_id)
    art_blob = json.dumps(art, sort_keys=True).lower()
    for bad in ("owner-token-secret", "bearer "):
        assert bad not in art_blob
    assert re.search(r'\"authorization\"\s*:', art_blob) is None


def test_authenticated_data_exposure_missing_auth_profile_returns_safe_failure() -> None:
    _reset()
    r = _adapter("{}").execute(
        _cmd(auth_mode="authenticated", auth_profile_id=""),
        _campaign(),
        "tr_auth_missing",
    )
    assert r.status == "failed"
    assert r.errors[0].error_type == "auth_profile_missing"


def test_data_exposure_redirect_not_allowed_returns_finished_probe_not_failed() -> None:
    _reset()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_dex",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token-123",
        created_by="test_account_materializer",
        metadata={},
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "/api/profile-final", "Content-Type": "text/plain"})

    adapter = DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    r = adapter.execute(
        _cmd(auth_mode="authenticated", auth_profile_id=profile.auth_profile_id, follow_same_origin_redirects=False, max_redirects=0),
        _campaign(),
        "tr_redirect_probe",
    )
    assert r.status == "finished"
    assert [o.observation_type for o in r.observations] == ["data_exposure_probe_result"]
    det = r.observations[0].details
    assert det.get("result") == "redirect_response"
    assert det.get("status_code") == 302
    assert det.get("auth_mode") == "authenticated"
    assert det.get("auth_profile_id") == profile.auth_profile_id
    assert "redirect_response" in (det.get("reason_codes") or [])
    assert "redirect_not_followed" in (det.get("reason_codes") or [])


def test_data_exposure_same_origin_redirect_followed_to_json_inventory() -> None:
    _reset()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_dex",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token-123",
        created_by="test_account_materializer",
        metadata={},
    )

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/profile":
            return httpx.Response(302, headers={"Location": "/api/profile-final"})
        assert request.headers.get("Authorization") == "Bearer owner-token-123"
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            text=json.dumps({"email": "x@y.z", "vehicleid": "veh-123"}),
        )

    adapter = DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    r = adapter.execute(
        _cmd(auth_mode="authenticated", auth_profile_id=profile.auth_profile_id, follow_same_origin_redirects=True, max_redirects=2),
        _campaign(),
        "tr_redirect_follow",
    )
    assert r.status == "finished"
    assert [o.observation_type for o in r.observations] == [
        "response_field_inventory",
        "data_exposure_signal",
        "data_exposure_probe_result",
    ]
    probe = r.observations[-1].details
    assert probe.get("result") == "sensitive_fields_found"


def test_data_exposure_cross_host_redirect_returns_safe_probe_not_failed() -> None:
    _reset()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_dex",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token-123",
        created_by="test_account_materializer",
        metadata={},
    )

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://evil.local/next?token=secret"})

    adapter = DataExposureValidatorAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    r = adapter.execute(
        _cmd(auth_mode="authenticated", auth_profile_id=profile.auth_profile_id, follow_same_origin_redirects=True, max_redirects=2),
        _campaign(),
        "tr_redirect_cross_host",
    )
    assert r.status == "finished"
    assert [o.observation_type for o in r.observations] == ["data_exposure_probe_result"]
    det = r.observations[0].details
    assert det.get("result") == "redirect_response"
    assert det.get("auth_profile_id") == profile.auth_profile_id
    assert "redirect_host_not_allowed" in (det.get("reason_codes") or [])
    blob = json.dumps(r.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("owner-token-123", "bearer ", "evil.local/next?token=secret", "\"authorization\":", "\"cookie\":"):
        assert bad not in blob
