"""Phase 4 — WorkerCommand + CommandValidator tests.

26 tests covering:
- WorkerCommand model normalization and auto-generation
- CommandValidator checks (tool, budget, hosts, seed, auth, fingerprint, operation_id)
- Route-level validate / submit endpoints
"""
from __future__ import annotations

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits, CampaignStatus
from backend.models.worker_command import (
    ALLOWED_TOOLS_BY_WORKER_CLASS,
    CommandBudget,
    ValidationResult,
    WorkerCommand,
    normalize_worker_class,
)
from backend.services.command_validator import CommandValidator
from backend.storage.memory_store import MemoryStore, memory_store


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


def _create_campaign(
    campaign_id: str = "cmp_test1",
    allowed_hosts: list[str] | None = None,
    roles_json: list[dict] | None = None,
    max_requests: int = 1000,
    max_duration_sec: int = 1800,
    status: CampaignStatus = CampaignStatus.running,
    openapi_url: str | None = None,
) -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        openapi_url=openapi_url,
        allowed_hosts=allowed_hosts or ["testapp.local"],
        roles_json=roles_json or [],
        limits=CampaignLimits(max_requests=max_requests, max_duration_sec=max_duration_sec),
        status=status,
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _base_command(**overrides) -> WorkerCommand:
    defaults = dict(
        campaign_id="cmp_test1",
        worker_class="access_control",
        strategy="role_swap_object_access",
        tool_name="custom_request_executor",
    )
    defaults.update(overrides)
    return WorkerCommand(**defaults)


def _add_corpus_item(
    request_id: str, campaign_id: str, method: str = "GET", path: str = "/api/users/1"
) -> None:
    memory_store.store_corpus_item(request_id, campaign_id, {
        "request_id": request_id,
        "campaign_id": campaign_id,
        "method": method,
        "path_template": path,
        "url": f"http://testapp.local{path}",
        "status_code": 200,
        "classification": "successful_seed",
        "auth_profile": "user_a",
        "extracted_ids": {},
        "redacted_headers": {},
        "request_headers": {},
        "request_body": "",
        "response_headers": {},
        "response_body": "",
        "operation_id": "",
        "created_at": "",
    })


# ─── Unit tests for CommandValidator ───────────────────────────────


def test_worker_command_validates_allowed_tool():
    _reset_store()
    _create_campaign()
    cmd = _base_command(tool_name="custom_request_executor")
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert len(result.errors) == 0


def test_worker_command_rejects_out_of_scope_host():
    _reset_store()
    _create_campaign(allowed_hosts=["testapp.local"])
    cmd = _base_command(inputs={"url": "https://evil.com/api/hack"})
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "host_not_allowed" in codes


def test_worker_command_allows_relative_url():
    _reset_store()
    _create_campaign(allowed_hosts=["testapp.local"])
    cmd = _base_command(inputs={"url": "/api/users/123"})
    result = CommandValidator().validate(cmd)
    assert result.valid is True


def test_worker_command_rejects_nested_out_of_scope_url():
    _reset_store()
    _create_campaign(allowed_hosts=["testapp.local"])
    cmd = _base_command(inputs={
        "callback": {
            "url": "https://evil.example/callback",
        },
        "targets": ["/api/users/1", {"next": "https://evil.example/next"}],
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    host_errors = [e for e in result.errors if e.code == "host_not_allowed"]
    assert host_errors
    keys = [str(e.details.get("key", "")) for e in host_errors if isinstance(e.details, dict)]
    assert any(key.startswith("inputs.callback.url") for key in keys)


def test_worker_command_allows_nested_relative_urls():
    _reset_store()
    _create_campaign(allowed_hosts=["testapp.local"])
    cmd = _base_command(inputs={
        "callback": {"url": "/api/callback/123"},
        "batch": ["/api/users/1", {"next": "/api/users/2"}],
    })
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert not any(e.code == "host_not_allowed" for e in result.errors)


def test_worker_command_rejects_unknown_tool():
    _reset_store()
    _create_campaign()
    cmd = _base_command(tool_name="imaginary_tool_xyz")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "unknown_tool" in codes


def test_worker_command_rejects_tool_not_in_class():
    _reset_store()
    _create_campaign()
    cmd = _base_command(worker_class="access_control", tool_name="nuclei")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "tool_not_allowed_for_worker_class" in codes


def test_worker_command_rejects_budget_excess():
    _reset_store()
    _create_campaign(max_requests=100)
    cmd = _base_command(budget=CommandBudget(max_requests=200, timeout_sec=60))
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "budget_exceeds_campaign_limit" in codes


def test_worker_command_uses_seed_request():
    _reset_store()
    _create_campaign()
    _add_corpus_item("req_seed1", "cmp_test1")
    cmd = _base_command(seed_request_id="req_seed1")
    result = CommandValidator().validate(cmd)
    assert result.valid is True


def test_worker_command_rejects_missing_seed_request():
    _reset_store()
    _create_campaign()
    cmd = _base_command(seed_request_id="req_nonexistent")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "seed_request_not_found" in codes


def test_worker_command_rejects_seed_from_other_campaign():
    _reset_store()
    _create_campaign(campaign_id="cmp_test1")
    _create_campaign(campaign_id="cmp_other")
    _add_corpus_item("req_other1", "cmp_other")
    cmd = _base_command(campaign_id="cmp_test1", seed_request_id="req_other1")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "seed_request_wrong_campaign" in codes


def test_worker_command_rejects_missing_campaign():
    _reset_store()
    cmd = _base_command(campaign_id="cmp_nonexistent")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "campaign_not_found" in codes


def test_worker_command_normalizes_legacy_class_authorization():
    _reset_store()
    _create_campaign()
    cmd = _base_command(worker_class="authorization")
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert result.normalized_worker_class == "access_control"


def test_worker_command_normalizes_legacy_class_injection():
    _reset_store()
    _create_campaign()
    cmd = _base_command(
        worker_class="injection",
        tool_name="schemathesis_negative_test",
        strategy="negative_schema_test",
    )
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert result.normalized_worker_class == "contract_fuzzing"


def test_worker_command_normalizes_legacy_class_business_logic():
    _reset_store()
    _create_campaign()
    cmd = _base_command(
        worker_class="business_logic",
        tool_name="restler_fuzz",
        strategy="stateful_exploration",
    )
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert result.normalized_worker_class == "stateful_flow"


def test_worker_command_accepts_new_class_names_directly():
    _reset_store()
    _create_campaign()
    for wc in ["access_control", "contract_fuzzing", "stateful_flow",
               "discovery_inventory", "misconfiguration", "ssrf_external"]:
        allowed_tools = ALLOWED_TOOLS_BY_WORKER_CLASS[wc]
        tool = allowed_tools[0]
        cmd = _base_command(worker_class=wc, tool_name=tool)
        result = CommandValidator().validate(cmd)
        assert result.valid is True, f"Failed for worker_class={wc}, tool={tool}: {result.errors}"
        assert result.normalized_worker_class == wc


def test_worker_command_rejects_unknown_worker_class():
    _reset_store()
    _create_campaign()
    cmd = _base_command(worker_class="quantum_hacking")
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "unknown_worker_class" in codes


def test_worker_command_validates_auth_profiles_exist():
    _reset_store()
    _create_campaign(
        roles_json=[{"name": "user_a"}, {"name": "user_b"}]
    )
    cmd = _base_command(inputs={"owner_role": "user_a", "attacker_role": "user_b"})
    result = CommandValidator().validate(cmd)
    assert result.valid is True


def test_worker_command_rejects_invalid_auth_profile_when_roles_configured():
    _reset_store()
    _create_campaign(
        roles_json=[{"name": "user_a"}, {"name": "user_b"}]
    )
    cmd = _base_command(inputs={"owner_role": "user_a", "attacker_role": "admin_ghost"})
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    codes = [e.code for e in result.errors]
    assert "auth_profile_not_found" in codes


def test_worker_command_warns_when_auth_profiles_not_configured():
    _reset_store()
    _create_campaign(roles_json=[])
    cmd = _base_command(inputs={"owner_role": "user_a"})
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert "auth_profiles_not_configured" in result.warnings


def test_worker_command_auto_generates_command_id():
    _reset_store()
    _create_campaign()
    cmd = _base_command()
    assert cmd.command_id == ""
    result = CommandValidator().validate(cmd)
    assert result.command_id.startswith("cmd_")
    assert len(result.command_id) > 4


def test_worker_command_fingerprint_duplicate_warning():
    _reset_store()
    _create_campaign()
    cmd1 = _base_command()
    validator = CommandValidator()

    result1 = validator.validate(cmd1)
    assert result1.valid is True
    dup_warnings_1 = [w for w in result1.warnings if "duplicate_command_fingerprint" in w]
    assert len(dup_warnings_1) == 0

    nc = result1.normalized_worker_class
    from backend.services.command_validator import _command_fingerprint
    fp = _command_fingerprint(cmd1, nc)
    memory_store.command_fingerprints[cmd1.campaign_id].add(fp)

    cmd2 = _base_command()
    result2 = validator.validate(cmd2)
    dup_warnings_2 = [w for w in result2.warnings if "duplicate_command_fingerprint" in w]
    assert len(dup_warnings_2) == 1


def test_worker_command_operation_id_missing_in_graph_is_warning_not_error():
    _reset_store()
    _create_campaign()
    memory_store.store_graph_for_campaign("cmp_test1", {
        "graph": {
            "operations": [{"operation_id": "op_get_users"}]
        }
    })
    cmd = _base_command(operation_id="op_nonexistent")
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert any("operation_id_not_in_graph" in w for w in result.warnings)


def test_worker_command_empty_operation_id_warns_when_graph_built():
    _reset_store()
    _create_campaign()
    memory_store.store_graph_for_campaign("cmp_test1", {
        "graph": {
            "operations": [{"operation_id": "op_get_users"}]
        }
    })
    cmd = _base_command(operation_id="")
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert "operation_id_missing" in result.warnings


def test_worker_command_empty_operation_id_warns_when_graph_not_built():
    _reset_store()
    _create_campaign()
    cmd = _base_command(operation_id="")
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert "operation_id_graph_not_built" in result.warnings


# ─── Route-level tests ─────────────────────────────────────────────

def _get_test_client():
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


def test_routes_validate_returns_200_for_valid_command():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "campaign_id": "cmp_test1",
        "worker_class": "access_control",
        "strategy": "role_swap_object_access",
        "tool_name": "custom_request_executor",
    }
    resp = client.post("/v1/workers/command/validate", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is True


def test_routes_validate_returns_200_with_errors_for_invalid_command():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "campaign_id": "cmp_test1",
        "worker_class": "access_control",
        "strategy": "role_swap_object_access",
        "tool_name": "imaginary_tool",
    }
    resp = client.post("/v1/workers/command/validate", json=payload)
    assert resp.status_code == 200
    body = resp.json()
    assert body["valid"] is False
    assert len(body["errors"]) > 0


def test_routes_submit_returns_201_for_valid_command():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "campaign_id": "cmp_test1",
        "worker_class": "access_control",
        "strategy": "role_swap_object_access",
        "tool_name": "custom_request_executor",
    }
    resp = client.post("/v1/workers/command", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["status"] == "accepted"
    assert body["command_id"].startswith("cmd_")


def test_routes_submit_returns_400_for_invalid_command():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "campaign_id": "cmp_test1",
        "worker_class": "access_control",
        "strategy": "role_swap_object_access",
        "tool_name": "imaginary_tool",
    }
    resp = client.post("/v1/workers/command", json=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["valid"] is False


def test_routes_submit_stores_command_but_does_not_execute_tool():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "campaign_id": "cmp_test1",
        "worker_class": "access_control",
        "strategy": "role_swap_object_access",
        "tool_name": "custom_request_executor",
    }
    resp = client.post("/v1/workers/command", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    cmd_id = body["command_id"]

    stored = memory_store.get_command(cmd_id)
    assert stored is not None
    assert stored["status"] == "accepted"
    assert stored["normalized_worker_class"] == "access_control"
    assert "tool_run_id" not in stored


def test_schemathesis_inputs_openapi_url_allowed_when_matches_campaign_openapi_url():
    spec = "https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json"
    _reset_store()
    _create_campaign(
        allowed_hosts=["testapp.local"],
        openapi_url=spec,
    )
    cmd = _base_command(
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_GET_/x",
        inputs={
            "openapi_url": spec,
            "target_url": "http://testapp.local",
            "max_examples": 3,
        },
    )
    result = CommandValidator().validate(cmd)
    assert result.valid is True
    assert not any(e.code == "host_not_allowed" for e in result.errors)


def test_schemathesis_inputs_openapi_url_rejected_when_differs_from_campaign():
    _reset_store()
    _create_campaign(
        allowed_hosts=["testapp.local"],
        openapi_url="https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json",
    )
    cmd = _base_command(
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_GET_/x",
        inputs={
            "openapi_url": "https://evil.example/other.json",
            "target_url": "http://testapp.local",
        },
    )
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    assert any(e.code == "host_not_allowed" for e in result.errors)


def test_schemathesis_target_url_still_requires_allowed_host():
    spec = "https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json"
    _reset_store()
    _create_campaign(allowed_hosts=["testapp.local"], openapi_url=spec)
    cmd = _base_command(
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_GET_/x",
        inputs={
            "openapi_url": spec,
            "target_url": "http://evil.example",
        },
    )
    result = CommandValidator().validate(cmd)
    assert result.valid is False
    assert any(e.code == "host_not_allowed" for e in result.errors)
