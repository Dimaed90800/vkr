"""Phase 5 — ToolExecutor / ToolRun / ToolResult tests.

28 tests covering:
- ToolExecutor sync/async lifecycle
- NoopAdapter behavior
- ToolRegistry
- ArtifactStore
- Route-level start/status/collect
- Regression guards
"""
from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits, CampaignStatus
from backend.models.tool_run import (
    ToolArtifactRef,
    ToolExecutionMode,
    ToolResult,
    ToolRun,
    ToolRunStatus,
    ToolRunStartRequest,
)
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.injection_test_adapter import InjectionTestAdapter
from backend.services.artifact_store import ArtifactStore
from backend.services.command_validator import CommandValidator
from backend.services.tool_executor import ToolExecutor, ToolExecutorStartError
from backend.services.tool_registry import ToolRegistry
from backend.services.zap_passive_client import ZapPassiveResult
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
    memory_store.tool_runs.clear()
    memory_store.tool_runs_by_campaign.clear()
    memory_store.tool_results.clear()
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()


def _create_campaign(
    campaign_id: str = "cmp_test1",
    allowed_hosts: list[str] | None = None,
) -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        allowed_hosts=allowed_hosts or ["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _sync_command(**overrides) -> WorkerCommand:
    defaults = dict(
        campaign_id="cmp_test1",
        worker_class="access_control",
        strategy="role_swap_object_access",
        tool_name="custom_request_executor",
    )
    defaults.update(overrides)
    return WorkerCommand(**defaults)


def _async_command(**overrides) -> WorkerCommand:
    defaults = dict(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="negative_schema_test",
        tool_name="schemathesis_negative_test",
    )
    defaults.update(overrides)
    return WorkerCommand(**defaults)


def _store_running_run(
    tool_run_id: str = "toolrun_manual_running",
    campaign_id: str = "cmp_test1",
    tool_name: str = "schemathesis_negative_test",
) -> ToolRun:
    run = ToolRun(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name=tool_name,
        execution_mode=ToolExecutionMode.async_,
        status=ToolRunStatus.running,
    )
    memory_store.store_tool_run(tool_run_id, campaign_id, run.model_dump(mode="json"))
    return run


# ─── ToolExecutor unit tests ──────────────────────────────────────


def test_sync_tool_run_returns_finished_tool_result():
    _reset_store()
    _create_campaign()
    cmd = _sync_command()
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "finished"
    assert result.tool_run_id.startswith("toolrun_")
    assert result.campaign_id == "cmp_test1"
    assert result.tool_name == "custom_request_executor"


def test_sync_tool_result_has_correct_schema_version():
    _reset_store()
    _create_campaign()
    cmd = _sync_command()
    result = ToolExecutor().execute_sync(cmd)
    assert result.schema_version == "tool-result/v1"


def test_sync_tool_result_contains_artifact_refs():
    _reset_store()
    _create_campaign()
    cmd = _sync_command()
    result = ToolExecutor().execute_sync(cmd)
    assert len(result.artifacts) >= 1
    assert result.artifacts[0].artifact_id.startswith("art_")
    assert "http_exchange" in result.artifacts[0].artifact_type


def test_async_start_known_tool_without_adapter_returns_controlled_error():
    _reset_store()
    _create_campaign()
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="stateful_flow",
        strategy="stateful_exploration",
        tool_name="restler_fuzz",
    )
    try:
        ToolExecutor().start_async(cmd)
        assert False, "Expected ToolExecutorStartError"
    except ToolExecutorStartError as exc:
        assert exc.code == "async_adapter_not_available"
    assert len(memory_store.tool_runs) == 0


def test_start_async_validates_command_before_creating_run():
    _reset_store()
    cmd = _async_command(campaign_id="cmp_nonexistent")
    try:
        ToolExecutor().start_async(cmd)
        assert False, "Expected ToolExecutorStartError"
    except ToolExecutorStartError as exc:
        assert exc.code == "validation_failed"
    assert len(memory_store.tool_runs) == 0


def test_running_tool_run_has_result_ready_false():
    _reset_store()
    _create_campaign()
    run = _store_running_run()
    fetched = ToolExecutor().get_status(run.tool_run_id)
    assert fetched is not None
    assert fetched.result_ready is False


def test_collect_finished_tool_run_returns_tool_result():
    _reset_store()
    _create_campaign()
    executor = ToolExecutor()
    run = _store_running_run()

    fake_result = ToolResult(
        tool_run_id=run.tool_run_id,
        campaign_id="cmp_test1",
        tool_name="schemathesis_negative_test",
        status="finished",
    )
    executor.mark_finished(run.tool_run_id, fake_result)

    collected = executor.collect(run.tool_run_id)
    assert collected is not None
    assert collected.status == "finished"
    assert collected.tool_run_id == run.tool_run_id


def test_collect_running_tool_run_returns_none_or_conflict():
    _reset_store()
    _create_campaign()
    executor = ToolExecutor()
    run = _store_running_run()
    collected = executor.collect(run.tool_run_id)
    assert collected is None


def test_failed_tool_returns_structured_error():
    _reset_store()
    _create_campaign()
    executor = ToolExecutor()
    run = _store_running_run()
    result = executor.mark_failed(run.tool_run_id, "test_failure", "Something went wrong")
    assert result.status == "failed"
    assert len(result.errors) >= 1
    assert result.errors[0].error_type == "test_failure"


def test_timeout_tool_returns_structured_error():
    _reset_store()
    _create_campaign()
    executor = ToolExecutor()
    run = _store_running_run()
    result = executor.mark_failed(run.tool_run_id, "timeout", "Tool exceeded timeout")
    assert result.status == "failed"
    assert result.errors[0].error_type == "timeout"


def test_artifacts_are_saved_and_referenced():
    _reset_store()
    _create_campaign()
    cmd = _sync_command()
    result = ToolExecutor().execute_sync(cmd)
    assert len(result.artifacts) >= 1
    art_id = result.artifacts[0].artifact_id
    stored = ArtifactStore().get_artifact(art_id)
    assert stored is not None
    assert stored["artifact_type"] == "http_exchange"


def test_unknown_tool_handled_gracefully():
    _reset_store()
    _create_campaign()
    cmd = _sync_command(tool_name="imaginary_tool_xyz")
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "failed"
    codes = [e.error_type for e in result.errors]
    assert "validation_failed" in codes


def test_known_but_unsupported_tool_does_not_noop_success():
    _reset_store()
    _create_campaign()
    cmd = _sync_command(
        worker_class="misconfiguration",
        tool_name="nuclei",
        strategy="template_scan",
    )
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "failed"
    codes = [e.error_type for e in result.errors]
    assert "adapter_not_available" in codes


def test_command_must_be_validated_before_execution():
    _reset_store()
    cmd = _sync_command(campaign_id="cmp_nonexistent")
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "failed"
    codes = [e.error_type for e in result.errors]
    assert "validation_failed" in codes


def test_tool_executor_does_not_call_judge():
    _reset_store()
    _create_campaign()
    cmd = _sync_command()
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "finished"
    assert len(memory_store.evidence_records) == 0
    assert len(memory_store.findings) == 0


def test_tool_run_isolation_per_campaign():
    _reset_store()
    _create_campaign(campaign_id="cmp_a")
    _create_campaign(campaign_id="cmp_b")
    executor = ToolExecutor()
    cmd_a = _sync_command(campaign_id="cmp_a")
    cmd_b = _sync_command(campaign_id="cmp_b")
    result_a = executor.execute_sync(cmd_a)
    result_b = executor.execute_sync(cmd_b)
    runs_a = memory_store.list_tool_runs_by_campaign("cmp_a")
    runs_b = memory_store.list_tool_runs_by_campaign("cmp_b")
    assert len(runs_a) == 1
    assert len(runs_b) == 1
    assert runs_a[0]["tool_run_id"] != runs_b[0]["tool_run_id"]


def test_noop_adapter_returns_valid_tool_result():
    _reset_store()
    _create_campaign()
    from backend.services.adapters.noop_adapter import NoopAdapter
    cmd = _sync_command()
    cmd.command_id = "cmd_test"
    campaign = Campaign(
        campaign_id="cmp_test1",
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
    )
    result = NoopAdapter().execute(cmd, campaign, "toolrun_noop_test")
    assert result.schema_version == "tool-result/v1"
    assert result.status == "finished"
    assert result.summary.request_count == 1
    assert result.summary.success_count == 1
    assert len(result.requests) == 1
    assert len(result.responses) == 1


def test_noop_adapter_not_fallback_for_every_tool():
    _reset_store()
    _create_campaign()
    cmd = _sync_command(
        worker_class="misconfiguration",
        tool_name="zap",
        strategy="api_scan",
    )
    result = ToolExecutor().execute_sync(cmd)
    assert result.status == "failed"
    assert any(e.error_type == "adapter_not_available" for e in result.errors)


def test_broad_zap_remains_known_but_unsupported():
    reg = ToolRegistry()
    assert reg.is_known("zap") is True
    assert reg.has_adapter("zap") is False


def test_zap_discovery_passive_executor_allows_internal_zap_base_url():
    class FakeZapClient:
        def run_discovery_passive(self, **kwargs):
            return ZapPassiveResult(discovered_urls=["http://testapp.local/api/users"])

    _reset_store()
    _create_campaign()
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="discovery_inventory",
        strategy="zap_discovery_passive",
        tool_name="zap_discovery_passive",
        inputs={
            "target_url": "http://testapp.local",
            "zap_base_url": "http://zap:8080",
        },
    )

    result = ToolExecutor(zap_passive_client=FakeZapClient()).execute_sync(cmd)

    assert result.status == "finished"
    assert result.tool_name == "zap_discovery_passive"
    assert [obs.observation_type for obs in result.observations] == ["discovered_endpoint"]


def test_validator_allows_exact_host_port_when_listed():
    _reset_store()
    _create_campaign(allowed_hosts=["host.docker.internal:8888"])
    cmd = _sync_command(
        tool_name="custom_request_executor",
        inputs={"url": "http://host.docker.internal:8888/api/v1/test"},
    )

    result = ToolExecutor().execute_sync(cmd)

    assert result.status == "finished"
    assert not any(err.error_type == "validation_failed" for err in result.errors)


def test_validator_rejects_wrong_port_even_with_same_host():
    _reset_store()
    _create_campaign(allowed_hosts=["host.docker.internal:9999"])
    cmd = _sync_command(
        tool_name="custom_request_executor",
        inputs={"url": "http://host.docker.internal:8888/api/v1/test"},
    )

    result = ToolExecutor().execute_sync(cmd)

    assert result.status == "failed"
    assert any(err.error_type == "validation_failed" for err in result.errors)


# ─── ToolRegistry tests ───────────────────────────────────────────


def test_tool_registry_reports_known_tools():
    reg = ToolRegistry()
    assert reg.is_known("custom_request_executor") is True
    assert reg.is_known("nuclei") is True
    assert reg.is_known("noop_tool") is True
    assert reg.is_known("zap_discovery_passive") is True
    assert reg.is_known("security_header_validator") is True
    assert reg.has_adapter("zap_discovery_passive") is True
    assert reg.has_adapter("security_header_validator") is True
    assert reg.is_known("totally_made_up_tool") is False


def test_tool_registry_returns_execution_mode():
    reg = ToolRegistry()
    assert reg.get_execution_mode("custom_request_executor") == "sync"
    assert reg.get_execution_mode("noop_tool") == "sync"
    assert reg.get_execution_mode("zap_discovery_passive") == "sync"
    assert reg.get_execution_mode("security_header_validator") == "sync"
    assert reg.get_execution_mode("schemathesis_negative_test") == "sync"
    assert reg.get_execution_mode("restler_fuzz") == "async"
    assert reg.has_adapter("schemathesis_negative_test") is True


def test_registry_injection_test_has_sync_adapter() -> None:
    reg = ToolRegistry()
    assert reg.has_adapter("injection_test") is True
    assert reg.get_execution_mode("injection_test") == "sync"


def test_security_header_validator_allowed_only_for_misconfiguration():
    _reset_store()
    _create_campaign()
    cmd = _sync_command(
        worker_class="access_control",
        strategy="validate_security_header",
        tool_name="security_header_validator",
        inputs={
            "request_url": "http://testapp.local/frame",
            "target_url": "http://testapp.local/frame",
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
        },
    )

    result = ToolExecutor().execute_sync(cmd)

    assert result.status == "failed"
    assert any(err.error_type == "validation_failed" for err in result.errors)


# ─── Route-level tests ────────────────────────────────────────────


def _get_test_client():
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


def test_routes_start_returns_201_for_sync_tool():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "command": {
            "campaign_id": "cmp_test1",
            "worker_class": "access_control",
            "strategy": "role_swap_object_access",
            "tool_name": "custom_request_executor",
        },
    }
    resp = client.post("/v1/tools/runs/start", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["execution_mode"] == "sync"
    assert body["status"] == "finished"
    assert body["result"] is not None


def test_routes_start_rejects_known_async_tool_without_adapter():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "command": {
            "campaign_id": "cmp_test1",
            "worker_class": "stateful_flow",
            "strategy": "stateful_exploration",
            "tool_name": "restler_fuzz",
        },
    }
    resp = client.post("/v1/tools/runs/start", json=payload)
    assert resp.status_code == 501
    body = resp.json()
    assert body["error"] in {"adapter_not_available", "async_adapter_not_available"}


def test_routes_start_schemathesis_sync_returns_201_with_tool_result():
    _reset_store()
    from backend.models.campaign import Campaign, CampaignLimits

    spec = "http://testapp.local/openapi.json"
    c = Campaign(
        campaign_id="cmp_test1",
        target_url="http://testapp.local",
        openapi_url=spec,
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign("cmp_test1", c.model_dump(mode="json"))
    client = _get_test_client()
    payload = {
        "execution_mode": "sync",
        "command": {
            "campaign_id": "cmp_test1",
            "worker_class": "contract_fuzzing",
            "strategy": "schema_negative_testing",
            "tool_name": "schemathesis_negative_test",
            "operation_id": "op_GET_/api/v1/x",
            "inputs": {
                "openapi_url": spec,
                "target_url": "http://testapp.local",
                "max_examples": 1,
            },
            "budget": {"max_requests": 3, "timeout_sec": 30},
        },
    }
    fake_completed = MagicMock()
    fake_completed.returncode = 0
    fake_completed.stdout = "ok"
    fake_completed.stderr = ""
    with patch("shutil.which", return_value="/bin/false_schemathesis"), patch(
        "backend.services.adapters.schemathesis_negative_test_adapter.subprocess.run",
        return_value=fake_completed,
    ) as mock_run:
        resp = client.post("/v1/tools/runs/start", json=payload)
    assert resp.status_code == 201
    body = resp.json()
    assert body["execution_mode"] == "sync"
    assert body["result"]["tool_name"] == "schemathesis_negative_test"
    assert body["result"]["status"] == "finished"
    mock_run.assert_called_once()


def test_schemathesis_adapter_subprocess_nonzero_partial_with_schema_observation():
    from backend.models.campaign import Campaign, CampaignLimits
    from backend.services.adapters.schemathesis_negative_test_adapter import (
        SchemathesisNegativeTestAdapter,
    )

    campaign = Campaign(
        campaign_id="cmp_x",
        target_url="http://testapp.local",
        openapi_url="http://testapp.local/openapi.json",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
    )
    cmd = WorkerCommand(
        campaign_id="cmp_x",
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_GET_/api/v1/x",
        inputs={
            "openapi_url": "http://testapp.local/openapi.json",
            "target_url": "http://testapp.local",
            "max_examples": 2,
        },
        budget=CommandBudget(max_requests=5, timeout_sec=60),
    )
    fake = MagicMock()
    fake.returncode = 1
    fake.stdout = "response violates schema"
    fake.stderr = ""
    with patch("shutil.which", return_value="/bin/st"), patch(
        "backend.services.adapters.schemathesis_negative_test_adapter.subprocess.run",
        return_value=fake,
    ):
        result = SchemathesisNegativeTestAdapter().execute(cmd, campaign, "toolrun_t1")
    assert result.status == "partial"
    assert result.observations
    assert result.observations[0].observation_type == "schema_mismatch"


def test_schemathesis_adapter_missing_cli_failed():
    from backend.models.campaign import Campaign, CampaignLimits
    from backend.services.adapters.schemathesis_negative_test_adapter import (
        SchemathesisNegativeTestAdapter,
    )

    campaign = Campaign(
        campaign_id="cmp_x",
        target_url="http://testapp.local",
        openapi_url="http://testapp.local/openapi.json",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
    )
    cmd = WorkerCommand(
        campaign_id="cmp_x",
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_x",
        inputs={
            "openapi_url": "http://testapp.local/openapi.json",
            "target_url": "http://testapp.local",
        },
        budget=CommandBudget(max_requests=3, timeout_sec=30),
    )
    with patch("shutil.which", return_value=None):
        result = SchemathesisNegativeTestAdapter().execute(cmd, campaign, "toolrun_t2")
    assert result.status == "failed"
    assert any(e.error_type == "tool_runtime_missing" for e in result.errors)


def test_schemathesis_adapter_openapi_mismatch_failed():
    from backend.models.campaign import Campaign, CampaignLimits
    from backend.services.adapters.schemathesis_negative_test_adapter import (
        SchemathesisNegativeTestAdapter,
    )

    campaign = Campaign(
        campaign_id="cmp_x",
        target_url="http://testapp.local",
        openapi_url="http://testapp.local/spec.json",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
    )
    cmd = WorkerCommand(
        campaign_id="cmp_x",
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_x",
        inputs={
            "openapi_url": "http://testapp.local/other.json",
            "target_url": "http://testapp.local",
        },
        budget=CommandBudget(max_requests=3, timeout_sec=30),
    )
    result = SchemathesisNegativeTestAdapter().execute(cmd, campaign, "toolrun_t3")
    assert result.status == "failed"
    assert any(e.error_type == "invalid_inputs" for e in result.errors)


def test_schemathesis_execute_sync_dispatches_adapter():
    _reset_store()
    from backend.models.campaign import Campaign, CampaignLimits

    spec = "http://testapp.local/openapi.json"
    c = Campaign(
        campaign_id="cmp_test1",
        target_url="http://testapp.local",
        openapi_url=spec,
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign("cmp_test1", c.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_x",
        inputs={"openapi_url": spec, "target_url": "http://testapp.local"},
        budget=CommandBudget(max_requests=3, timeout_sec=30),
    )
    fake = MagicMock(returncode=0, stdout="", stderr="")
    with patch("shutil.which", return_value="/bin/st"), patch(
        "backend.services.adapters.schemathesis_negative_test_adapter.subprocess.run",
        return_value=fake,
    ):
        result = ToolExecutor().execute_sync(cmd)
    assert result.tool_name == "schemathesis_negative_test"
    assert result.status == "finished"


def test_tool_registry_resolve_mode_schemathesis_requested_async_remains_sync():
    reg = ToolRegistry()
    assert reg.resolve_execution_mode("schemathesis_negative_test", "async") == "sync"


def test_schemathesis_adapter_truncates_long_output_in_artifact():
    from backend.models.campaign import Campaign, CampaignLimits
    from backend.services.adapters.schemathesis_negative_test_adapter import (
        SchemathesisNegativeTestAdapter,
    )

    campaign = Campaign(
        campaign_id="cmp_x",
        target_url="http://testapp.local",
        openapi_url="http://testapp.local/openapi.json",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
    )
    cmd = WorkerCommand(
        campaign_id="cmp_x",
        worker_class="contract_fuzzing",
        strategy="schema_negative_testing",
        tool_name="schemathesis_negative_test",
        operation_id="op_x",
        inputs={
            "openapi_url": "http://testapp.local/openapi.json",
            "target_url": "http://testapp.local",
        },
        budget=CommandBudget(max_requests=3, timeout_sec=30),
    )
    fake = MagicMock(returncode=0, stdout="x" * 5000 + "Bearer secret-token-123\n", stderr="")
    with patch("shutil.which", return_value="/bin/st"), patch(
        "backend.services.adapters.schemathesis_negative_test_adapter.subprocess.run",
        return_value=fake,
    ):
        result = SchemathesisNegativeTestAdapter().execute(cmd, campaign, "toolrun_tail")
    assert result.status == "finished"
    assert result.artifacts
    from backend.services.artifact_store import ArtifactStore

    blob = ArtifactStore().get_artifact(result.artifacts[0].artifact_id)
    assert blob is not None
    import json as _json

    content = _json.loads(blob["content"])
    assert len(content["stdout_tail"]) <= 2100
    assert "secret-token" not in content["stdout_tail"]


def test_routes_start_rejects_invalid_command():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    payload = {
        "command": {
            "campaign_id": "cmp_test1",
            "worker_class": "access_control",
            "strategy": "role_swap_object_access",
            "tool_name": "imaginary_tool",
        },
    }
    resp = client.post("/v1/tools/runs/start", json=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["valid"] is False


def test_routes_start_does_not_bypass_command_validator():
    _reset_store()
    client = _get_test_client()
    payload = {
        "command": {
            "campaign_id": "cmp_nonexistent",
            "worker_class": "access_control",
            "strategy": "test",
            "tool_name": "custom_request_executor",
        },
    }
    resp = client.post("/v1/tools/runs/start", json=payload)
    assert resp.status_code == 400
    body = resp.json()
    assert body["valid"] is False
    assert any(e["code"] == "campaign_not_found" for e in body["errors"])


def test_routes_status_returns_200_for_existing_run():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    run = _store_running_run()
    run_id = run.tool_run_id
    status_resp = client.get(f"/v1/tools/runs/{run_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "running"


def test_routes_status_returns_404_for_missing_run():
    _reset_store()
    client = _get_test_client()
    resp = client.get("/v1/tools/runs/toolrun_nonexistent")
    assert resp.status_code == 404


def test_routes_collect_returns_200_for_finished_run():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    start_payload = {
        "command": {
            "campaign_id": "cmp_test1",
            "worker_class": "access_control",
            "strategy": "role_swap_object_access",
            "tool_name": "custom_request_executor",
        },
    }
    start_resp = client.post("/v1/tools/runs/start", json=start_payload)
    assert start_resp.status_code == 201
    run_id = start_resp.json()["tool_run_id"]
    collect_resp = client.post(f"/v1/tools/runs/{run_id}/collect")
    assert collect_resp.status_code == 200
    body = collect_resp.json()
    assert body["schema_version"] == "tool-result/v1"
    assert body["status"] == "finished"


def test_routes_collect_returns_409_for_running_run():
    _reset_store()
    _create_campaign()
    client = _get_test_client()
    run = _store_running_run()
    run_id = run.tool_run_id
    collect_resp = client.post(f"/v1/tools/runs/{run_id}/collect")
    assert collect_resp.status_code == 409
    assert collect_resp.json()["error"] == "tool_run_not_ready"


def test_tool_run_rejects_invalid_status():
    _reset_store()
    _create_campaign()
    try:
        ToolRun(
            tool_run_id="toolrun_bad_status",
            campaign_id="cmp_test1",
            tool_name="custom_request_executor",
            status="not_a_real_status",
        )
        assert False, "Expected validation error for invalid status"
    except Exception:
        pass


def test_tool_run_rejects_invalid_execution_mode():
    _reset_store()
    _create_campaign()
    try:
        ToolRun(
            tool_run_id="toolrun_bad_mode",
            campaign_id="cmp_test1",
            tool_name="custom_request_executor",
            execution_mode="parallel",
        )
        assert False, "Expected validation error for invalid execution mode"
    except Exception:
        pass


def _injection_syn_row(
    *,
    b_stat: int = 200,
    a_stat: int = 500,
) -> dict:
    return {
        "baseline_status": b_stat,
        "attack_status": a_stat,
        "baseline_size_bucket": "small",
        "attack_size_bucket": "small",
        "marker_reflected": False,
        "error_pattern_class": "none",
        "response_delta_class": "new_5xx",
        "_attack_body_text": "",
    }


def test_tool_executor_dispatches_injection_test() -> None:
    _reset_store()
    c = Campaign(
        campaign_id="cmp_test1",
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign("cmp_test1", c.model_dump(mode="json"))
    syn = [_injection_syn_row()]
    ad = InjectionTestAdapter(synthetic_outcomes=syn)
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="injection_probe",
        tool_name="injection_test",
        operation_id="op_GET_/items",
        inputs={
            "target_url": "http://testapp.local",
            "payload_families": ["sql_like"],
            "max_payloads_per_param": 1,
        },
        budget=CommandBudget(max_requests=5, timeout_sec=20),
    )
    result = ToolExecutor(injection_adapter=ad).execute_sync(cmd)
    assert result.tool_name == "injection_test"
    assert result.status == "partial"
    assert result.observations and result.observations[0].observation_type == "injection_signal"


def test_tools_runs_start_sync_injection_test_returns_result() -> None:
    _reset_store()
    c = Campaign(
        campaign_id="cmp_test1",
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign("cmp_test1", c.model_dump(mode="json"))
    import backend.api.routes_tool_runs as tr

    prev = tr._executor
    tr._executor = ToolExecutor(
        injection_adapter=InjectionTestAdapter(synthetic_outcomes=[_injection_syn_row()]),
    )
    try:
        client = _get_test_client()
        payload = {
            "execution_mode": "sync",
            "command": {
                "campaign_id": "cmp_test1",
                "worker_class": "contract_fuzzing",
                "strategy": "injection_probe",
                "tool_name": "injection_test",
                "operation_id": "op_GET_/items",
                "inputs": {
                    "target_url": "http://testapp.local",
                    "payload_families": ["sql_like"],
                    "max_payloads_per_param": 1,
                },
                "budget": {"max_requests": 5, "timeout_sec": 20},
            },
        }
        resp = client.post("/v1/tools/runs/start", json=payload)
    finally:
        tr._executor = prev
    assert resp.status_code == 201
    body = resp.json()
    assert body["result"]["tool_name"] == "injection_test"
    assert body["result"]["observations"][0]["observation_type"] == "injection_signal"


def test_injection_test_rejects_target_url_not_campaign() -> None:
    _reset_store()
    _create_campaign()
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="injection_probe",
        tool_name="injection_test",
        operation_id="op_x",
        inputs={"target_url": "http://testapp.local/api/v1/other"},
        budget=CommandBudget(max_requests=5, timeout_sec=20),
    )
    v = CommandValidator().validate(cmd)
    assert not v.valid
    assert any(e.code == "injection_target_url_mismatch" for e in v.errors)


def test_injection_test_budget_caps() -> None:
    _reset_store()
    _create_campaign()
    cmd = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="injection_probe",
        tool_name="injection_test",
        operation_id="op_x",
        inputs={"target_url": "http://testapp.local"},
        budget=CommandBudget(max_requests=50, timeout_sec=20),
    )
    v = CommandValidator().validate(cmd)
    assert not v.valid
    assert any(e.code == "injection_budget_max_requests" for e in v.errors)

    cmd2 = WorkerCommand(
        campaign_id="cmp_test1",
        worker_class="contract_fuzzing",
        strategy="injection_probe",
        tool_name="injection_test",
        operation_id="op_x",
        inputs={"target_url": "http://testapp.local"},
        budget=CommandBudget(max_requests=5, timeout_sec=99),
    )
    v2 = CommandValidator().validate(cmd2)
    assert not v2.valid
    assert any(e.code == "injection_budget_timeout" for e in v2.errors)


def test_existing_wrapper_routes_still_respond():
    _reset_store()
    client = _get_test_client()
    resp = client.get("/v1/tools/capabilities")
    assert resp.status_code == 200
