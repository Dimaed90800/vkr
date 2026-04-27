"""Phase 17B-1 — InjectionTestAdapter unit tests."""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.injection_test_adapter import InjectionTestAdapter
from backend.storage.memory_store import memory_store


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_inj",
        target_url="http://testapp.local/",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
    )


def _cmd(**kwargs) -> WorkerCommand:
    base = dict(
        campaign_id="cmp_inj",
        worker_class="contract_fuzzing",
        strategy="injection_probe",
        tool_name="injection_test",
        operation_id="op_GET_/x",
        inputs={
            "target_url": "http://testapp.local",
            "payload_families": ["sql_like"],
            "max_payloads_per_param": 1,
        },
        budget=CommandBudget(max_requests=5, timeout_sec=20),
    )
    base.update(kwargs)
    return WorkerCommand(**base)


def _summary_artifact_payload(result) -> dict:
    assert result.artifacts, "expected injection_probe_summary artifact"
    aid = result.artifacts[0].artifact_id
    row = memory_store.get_artifact(aid)
    assert row is not None
    assert row.get("artifact_type") == "injection_probe_summary"
    raw = row.get("content") or "{}"
    import json

    return json.loads(raw)


def test_injection_test_adapter_finished_without_signals() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 200,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "unchanged",
        "_attack_body_text": "",
    }]
    ad = InjectionTestAdapter(synthetic_outcomes=syn)
    r = ad.execute(_cmd(), _campaign(), "toolrun_inj1")
    assert r.status == "finished"
    assert r.observations == []
    payload = _summary_artifact_payload(r)
    assert payload["result"] == "no_signal"
    assert payload["probes_attempted"] == 1
    assert payload["signals_found"] == []
    assert payload["parameters_tested"] == ["inj_probe"]


def test_injection_test_adapter_partial_with_server_error_signal() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 502,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "new_5xx",
        "_attack_body_text": "",
    }]
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(_cmd(), _campaign(), "tr2")
    assert r.status == "partial"
    assert len(r.observations) == 1
    assert r.observations[0].observation_type == "injection_signal"
    assert "server_error_on_payload" in r.observations[0].details["signal_types"]
    assert r.observations[0].confidence == 0.6
    payload = _summary_artifact_payload(r)
    assert payload["result"] == "signals_detected"
    assert "server_error_on_payload" in payload["signals_found"]


def test_injection_test_adapter_partial_with_reflected_marker_signal() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 200,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "medium",
        "marker_reflected": True,
        "error_pattern_class": "none",
        "response_delta_class": "response_size_changed",
        "_attack_body_text": "echo xss_probe_1337",
    }]
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "payload_families": ["xss_reflection_marker"],
        "max_payloads_per_param": 1,
    })
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(cmd, _campaign(), "tr3")
    assert r.status == "partial"
    assert r.observations[0].details["signal_types"] == ["reflected_marker"]
    assert r.observations[0].confidence == 0.75


def test_injection_test_adapter_rejects_unknown_payload_family() -> None:
    cmd = _cmd(
        inputs={
            "target_url": "http://testapp.local",
            "payload_families": ["not_a_real_family"],
        },
    )
    r = InjectionTestAdapter().execute(cmd, _campaign(), "tr4")
    assert r.status == "failed"
    assert r.errors[0].error_type == "unknown_payload_family"


def test_injection_test_adapter_does_not_emit_raw_payload_body_headers() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 500,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "new_5xx",
        "_attack_body_text": "",
    }]
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(_cmd(), _campaign(), "tr5")
    d = r.observations[0].details
    for bad in ("response_body", "response_headers", "raw_payload", "authorization"):
        assert bad not in d
    assert d.get("payload_label") not in ("'", '"', "' OR '1'='1")
    assert d["payload_label"].startswith("sql_")
    payload = _summary_artifact_payload(r)
    blob = str(payload).lower()
    for bad in (
        "' or '1'='1",
        "response_body",
        "response_headers",
        "authorization",
        "cookie",
        "bearer ",
        "token=",
    ):
        assert bad not in blob


def test_injection_adapter_finished_no_signal_has_diagnostic_summary() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 200,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "unchanged",
        "_attack_body_text": "",
    }]
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(_cmd(), _campaign(), "tr_no_sig_diag")
    assert r.status == "finished"
    assert r.observations == []
    payload = _summary_artifact_payload(r)
    assert payload["artifact_type"] == "injection_probe_summary"
    assert payload["result"] == "no_signal"
    assert payload["signals_found"] == []
    assert payload["probes_attempted"] > 0
    assert "inj_probe" in payload["parameters_tested"]


def test_injection_adapter_partial_signal_has_diagnostic_summary() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 500,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "new_5xx",
        "_attack_body_text": "",
    }]
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(_cmd(), _campaign(), "tr_sig_diag")
    assert r.status == "partial"
    assert r.observations and r.observations[0].observation_type == "injection_signal"
    payload = _summary_artifact_payload(r)
    assert payload["result"] == "signals_detected"
    assert "server_error_on_payload" in payload["signals_found"]


def test_injection_adapter_summary_does_not_include_raw_payload_body_headers() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 200,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "unchanged",
        "_attack_body_text": "simulated response body",
    }]
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(_cmd(), _campaign(), "tr_no_leak")
    payload = _summary_artifact_payload(r)
    blob = str(payload).lower()
    for bad in ("' or '1'='1", "authorization", "cookie", "bearer ", "response_body", "headers"):
        assert bad not in blob


def test_injection_adapter_skipped_nosql_family_reported() -> None:
    syn = [{
        "baseline_status": 200,
        "attack_status": 200,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "unchanged",
        "_attack_body_text": "",
    }]
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "payload_families": ["nosql_like", "sql_like"],
        "max_payloads_per_param": 1,
    })
    r = InjectionTestAdapter(synthetic_outcomes=syn).execute(cmd, _campaign(), "tr_skip_nosql")
    assert r.status == "finished"
    payload = _summary_artifact_payload(r)
    assert "nosql_like" in payload.get("skipped_payload_families", [])
    reasons = " ".join(payload.get("skipped_reasons", []))
    assert "nosql_like" in reasons.lower()

