from __future__ import annotations

import json

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.ssrf_candidate_detector_adapter import SsrfCandidateDetectorAdapter
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()


def _campaign() -> Campaign:
    return Campaign(
        campaign_id="cmp_ssrf",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )


def _command(candidate_fields: list[dict[str, object]]) -> WorkerCommand:
    return WorkerCommand(
        campaign_id="cmp_ssrf",
        worker_class="input_validation",
        strategy="detect_ssrf_candidate_fields",
        tool_name="ssrf_candidate_detector",
        operation_id="op_POST_/workshop/api/mechanic/receive_report",
        inputs={
            "target_url": "http://target.local",
            "operation_id": "op_POST_/workshop/api/mechanic/receive_report",
            "path_template": "/workshop/api/mechanic/receive_report",
            "method": "POST",
            "validation_mode": "ssrf_candidate_detection",
            "candidate_fields": candidate_fields,
        },
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )


def test_ssrf_candidate_detector_mechanic_api_field_emits_signal() -> None:
    _reset_store()
    result = SsrfCandidateDetectorAdapter().execute(
        _command([
            {
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_type": "string",
                "schema_format": "uri",
                "confidence": "high",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            }
        ]),
        _campaign(),
        "toolrun_ssrf_1",
    )
    assert result.status == "finished"
    assert [obs.observation_type for obs in result.observations] == ["ssrf_candidate_signal"]
    details = result.observations[0].details
    assert details["field_name"] == "mechanic_api"
    assert details["field_path"] == "$.mechanic_api"
    assert details["validation_mode"] == "ssrf_candidate_detection"


def test_ssrf_candidate_detector_nested_callback_field_path_preserved() -> None:
    _reset_store()
    result = SsrfCandidateDetectorAdapter().execute(
        _command([
            {
                "field_name": "callback_url",
                "field_path": "$.job.callback_url",
                "schema_type": "string",
                "schema_format": "uri",
                "confidence": "high",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            }
        ]),
        _campaign(),
        "toolrun_ssrf_2",
    )
    assert result.status == "finished"
    assert result.observations[0].details["field_path"] == "$.job.callback_url"


def test_ssrf_candidate_detector_non_url_fields_emit_no_signal() -> None:
    _reset_store()
    result = SsrfCandidateDetectorAdapter().execute(
        _command([]),
        _campaign(),
        "toolrun_ssrf_3",
    )
    assert result.status == "finished"
    assert result.observations == []


def test_ssrf_candidate_detector_caps_to_twenty_fields() -> None:
    _reset_store()
    fields = [
        {
            "field_name": f"callback_url_{idx}",
            "field_path": f"$.callback_url_{idx}",
            "schema_type": "string",
            "schema_format": "uri",
            "confidence": "high",
            "reason_codes": ["url_like_field_name", "schema_format_uri"],
        }
        for idx in range(25)
    ]
    result = SsrfCandidateDetectorAdapter().execute(_command(fields), _campaign(), "toolrun_ssrf_4")
    assert len(result.observations) == 20


def test_ssrf_candidate_detector_has_no_raw_value_or_token_leakage() -> None:
    _reset_store()
    result = SsrfCandidateDetectorAdapter().execute(
        _command([
            {
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_type": "string",
                "schema_format": "uri",
                "confidence": "high",
                "reason_codes": ["url_like_field_name", "schema_format_uri"],
            }
        ]),
        _campaign(),
        "toolrun_ssrf_5",
    )
    artifact = memory_store.get_artifact(result.artifacts[0].artifact_id)
    blob = json.dumps({"result": result.model_dump(mode="json"), "artifact": artifact}, sort_keys=True).lower()
    for bad in (
        "authorization",
        "cookie",
        "set-cookie",
        "bearer ",
        "token=",
        "request_body",
        "response_body",
        "raw_body",
        "headers",
    ):
        assert bad not in blob
