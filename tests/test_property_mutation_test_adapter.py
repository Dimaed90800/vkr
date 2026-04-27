from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits, CampaignStatus
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.property_mutation_test_adapter import PropertyMutationTestAdapter
from backend.services.command_validator import CommandValidator
from backend.services.mass_assignment_field_classifier import (
    is_mass_assignment_sensitive_field,
    select_mass_assignment_fields,
)
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.campaigns.clear()
    memory_store.campaign_by_run_id.clear()
    memory_store.campaign_by_session_id.clear()
    memory_store.corpus_items.clear()
    memory_store.corpus_by_campaign.clear()
    memory_store.resource_instances.clear()
    memory_store.resources_by_campaign.clear()
    memory_store.graphs_by_campaign.clear()
    memory_store.commands.clear()
    memory_store.commands_by_campaign.clear()
    memory_store.command_fingerprints.clear()
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()


def _campaign(campaign_id: str = "cmp_ma") -> Campaign:
    c = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        status=CampaignStatus.running,
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign_id, c.model_dump(mode="json"))
    return c


def _cmd(**overrides) -> WorkerCommand:
    base = dict(
        campaign_id="cmp_ma",
        worker_class="access_control",
        strategy="property_mutation_probe",
        tool_name="property_mutation_test",
        operation_id="op_PATCH_/users/{id}",
        inputs={
            "target_url": "http://testapp.local",
            "operation_id": "op_PATCH_/users/{id}",
            "mutation_policy": "diagnostic_only",
            "diagnostic_only": True,
            "max_mutations": 1,
        },
        budget=CommandBudget(max_requests=0, timeout_sec=30),
        success_criteria=["property_mutation_probe_completed"],
    )
    base.update(overrides)
    return WorkerCommand(**base)


def _summary_payload(result) -> dict:
    assert result.artifacts, "expected mass_assignment_probe_summary artifact"
    aid = result.artifacts[0].artifact_id
    row = memory_store.get_artifact(aid)
    assert row is not None
    assert row.get("artifact_type") == "mass_assignment_probe_summary"
    return json.loads(row.get("content") or "{}")


def test_property_mutation_adapter_diagnostic_with_sensitive_fields_and_seed() -> None:
    _reset_store()
    campaign = _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
        "seed_request_id": "req_seed_1",
        "sensitive_fields": ["isAdmin", "owner_id"],
    })
    result = PropertyMutationTestAdapter().execute(cmd, campaign, "toolrun_ma_1")
    assert result.status == "finished"
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.observation_type == "mass_assignment_signal"
    assert obs.confidence == 0.55
    assert obs.details.get("runtime_effect_proven") is False
    payload = _summary_payload(result)
    assert payload["result"] == "diagnostic_ready"
    assert payload["seed_request_id_present"] is True
    assert "isAdmin" in payload["fields_selected"]
    assert "owner_id" in payload["fields_selected"]
    assert "ready_for_safe_probe_context" in payload["reason_codes"]


def test_property_mutation_adapter_missing_seed_needs_context() -> None:
    _reset_store()
    campaign = _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
        "sensitive_fields": ["admin"],
    })
    result = PropertyMutationTestAdapter().execute(cmd, campaign, "toolrun_ma_2")
    assert result.observations == []
    payload = _summary_payload(result)
    assert payload["result"] == "needs_verification_context"
    assert "missing_seed_request" in payload["reason_codes"]


def test_property_mutation_adapter_no_sensitive_fields() -> None:
    _reset_store()
    campaign = _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
        "sensitive_fields": ["displayName", "description"],
    })
    result = PropertyMutationTestAdapter().execute(cmd, campaign, "toolrun_ma_3")
    assert result.observations == []
    payload = _summary_payload(result)
    assert payload["result"] == "no_sensitive_fields"
    assert "no_writable_sensitive_fields" in payload["reason_codes"]


def test_mass_assignment_field_classifier_expected_selection() -> None:
    selection = select_mass_assignment_fields(
        ["isAdmin", "role", "ownerId", "permissions", "content", "description"],
    )
    assert "isAdmin" in selection.selected
    assert "role" in selection.selected
    assert "ownerId" in selection.selected
    assert "permissions" in selection.selected
    assert "content" in selection.skipped
    assert "description" in selection.skipped
    assert is_mass_assignment_sensitive_field("isAdmin") is True
    assert is_mass_assignment_sensitive_field("content") is False


def test_property_mutation_summary_no_raw_body_headers_tokens() -> None:
    _reset_store()
    campaign = _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
        "seed_request_id": "req_seed_2",
        "sensitive_fields": ["admin", "profile.description"],
    })
    result = PropertyMutationTestAdapter().execute(cmd, campaign, "toolrun_ma_4")
    assert len(result.observations) == 1
    obs_blob = str(result.observations[0].details).lower()
    payload = _summary_payload(result)
    blob = str(payload).lower()
    for bad in ("authorization", "cookie", "bearer ", "token=", "response_body", "headers"):
        assert bad not in blob
        assert bad not in obs_blob


def test_property_mutation_requires_diagnostic_only() -> None:
    _reset_store()
    _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "live_probe",
        "diagnostic_only": False,
        "max_mutations": 1,
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = {e.code for e in result.errors}
    assert "invalid_mutation_policy" in codes
    assert "mutation_requires_diagnostic_only" in codes


def test_property_mutation_rejects_target_url_mismatch() -> None:
    _reset_store()
    _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://evil.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    assert any(e.code == "property_mutation_target_mismatch" for e in result.errors)


def test_property_mutation_rejects_max_mutations_exceeded() -> None:
    _reset_store()
    _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 5,
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    assert any(e.code == "max_mutations_exceeded" for e in result.errors)


def test_property_mutation_rejects_disallowed_input_key() -> None:
    _reset_store()
    _campaign()
    cmd = _cmd(inputs={
        "target_url": "http://testapp.local",
        "operation_id": "op_PATCH_/users/{id}",
        "mutation_policy": "diagnostic_only",
        "diagnostic_only": True,
        "max_mutations": 1,
        "raw_url": "http://evil.local",
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    assert any(e.code == "disallowed_property_mutation_input" for e in result.errors)
