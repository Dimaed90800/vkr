from __future__ import annotations

import json

from backend.services.ssrf_callback_store import SsrfCallbackStore, get_effective_ssrf_callback_state
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "runtime_ssrf_callbacks",
        "runtime_ssrf_callbacks_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def test_register_probe_and_status_are_safe() -> None:
    _reset_store()
    store = SsrfCallbackStore()
    store.register_probe(
        campaign_id="cmp_1",
        operation_id="op_POST_/api/hooks",
        field_name="callback_url",
        field_path="$.callback_url",
        correlation_id="ssrf_123",
        auth_mode="authenticated",
        auth_profile_id="authprof_owner_1",
        role_hint="owner",
    )
    status = store.get_status("ssrf_123")
    assert status["correlation_id"] == "ssrf_123"
    assert status["received"] is False
    assert status["campaign_id"] == "cmp_1"
    assert status["operation_id"] == "op_POST_/api/hooks"
    assert status["field_name"] == "callback_url"
    assert status["field_path"] == "$.callback_url"
    assert status["auth_mode"] == "authenticated"
    assert status["auth_profile_id"] == "authprof_owner_1"
    assert status["role_hint"] == "owner"

    blob = json.dumps(memory_store.runtime_ssrf_callbacks["ssrf_123"], sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "password", "raw_body", "raw_headers"):
        assert bad not in blob


def test_record_callback_marks_received_without_storing_raw_headers() -> None:
    _reset_store()
    store = SsrfCallbackStore()
    store.register_probe(
        campaign_id="cmp_1",
        operation_id="op_POST_/api/hooks",
        field_name="callback_url",
        field_path="$.callback_url",
        correlation_id="ssrf_abc",
    )
    store.record_callback(
        correlation_id="ssrf_abc",
        method="GET",
        path="/v1/callbacks/ssrf/ssrf_abc",
        user_agent="curl/8.0 (x)\n",
        source_ip="10.0.0.5",
        headers_count=12,
    )
    status = store.get_status("ssrf_abc")
    assert status["received"] is True
    assert status["callback_method"] == "GET"
    assert status["headers_count"] == 12
    rec = memory_store.runtime_ssrf_callbacks["ssrf_abc"]
    assert rec.get("source_ip_hash")
    assert rec.get("user_agent_sanitized").startswith("curl/8.0")


def test_effective_state_reconciles_late_callback() -> None:
    _reset_store()
    store = SsrfCallbackStore()
    store.register_probe(
        campaign_id="cmp_1",
        operation_id="op_POST_/api/hooks",
        field_name="callback_url",
        field_path="$.callback_url",
        correlation_id="ssrf_late",
    )
    store.record_callback(
        correlation_id="ssrf_late",
        method="GET",
        path="/v1/callbacks/ssrf/ssrf_late",
        headers_count=7,
    )
    state = get_effective_ssrf_callback_state({
        "details": {"correlation_id": "ssrf_late", "callback_received": False}
    })
    assert state["callback_received_effective"] is True
    assert state["late_callback_reconciled"] is True
    assert state["callback_store_received"] is True
    assert "controlled_callback_received" in state["reason_codes"]
