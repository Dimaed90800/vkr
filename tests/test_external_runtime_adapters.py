from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.models.testing import ExecutionContext, TaskModel
from backend.models.tool_wrappers import ToolBudget, ToolWrapperRequest
from backend.services.tool_wrappers.service import ToolWrapperService


@pytest.fixture(autouse=True)
def _diagnostic_logs_to_tmp(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "diagnostic_logs"))


def _write_openapi(path: Path) -> Path:
    payload = {
        "openapi": "3.0.0",
        "info": {"title": "Adapter Test API", "version": "1.0.0"},
        "paths": {
            "/orders": {"get": {"operationId": "listOrders"}},
            "/orders/{id}": {"delete": {"operationId": "deleteOrder", "security": [{"bearerAuth": []}]}}
        },
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_restler_external_runtime_adapter_returns_normalized_result(tmp_path: Path, monkeypatch) -> None:
    spec_path = _write_openapi(tmp_path / "openapi.json")
    monkeypatch.setenv(
        "RESTLER_WRAPPER_COMMAND",
        "python scripts/runtime/restler_runtime_adapter.py --request-json {request_json} --result-json {result_json} --output-dir {output_dir}",
    )
    task = TaskModel.model_validate(
        {
            "id": "task_restler_adapter_001",
            "class": "business_logic",
            "subtype": "stateful_sequence",
            "endpoint": "/orders",
            "method": "POST",
            "hypothesis": "Stateful compile adapter should preserve runtime handoff.",
            "allowed_tools": ["restler_compile", "restler_fuzz"],
            "worker_role": "Business Flow / Stateful Agent",
            "preferred_tool": "restler_compile",
        }
    )
    request = ToolWrapperRequest(
        tool_name="restler_compile",
        run_id="run-restler-adapter",
        target_url="http://127.0.0.1:8001",
        openapi_spec_path=str(spec_path),
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-restler-adapter",
            openapi_url=str(spec_path),
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=20,
        ),
        task=task,
        budgets=ToolBudget(max_requests=5, max_duration_sec=20),
        output_dir=str(tmp_path / "runs"),
    )
    result = ToolWrapperService().execute(request)
    assert result.tool_name == "restler_compile"
    assert result.status in {"ok", "partial"}
    assert any(path.endswith("restler_runtime_result.json") for path in result.artifacts.raw_report_paths)
    assert any("restler" in signal for signal in result.signals)


def test_akto_external_runtime_adapter_returns_inventory_or_authz_plan(tmp_path: Path, monkeypatch) -> None:
    spec_path = _write_openapi(tmp_path / "openapi.json")
    monkeypatch.setenv(
        "AKTO_WRAPPER_COMMAND",
        "python scripts/runtime/akto_runtime_adapter.py --request-json {request_json} --result-json {result_json} --output-dir {output_dir}",
    )
    task = TaskModel.model_validate(
        {
            "id": "task_akto_adapter_001",
            "class": "authorization",
            "subtype": "function_level_authorization",
            "endpoint": "/orders/{id}",
            "method": "DELETE",
            "hypothesis": "Authorization adapter should produce a runtime-backed scan plan.",
            "allowed_tools": ["akto_authz_scan"],
            "worker_role": "Auth & Identity Agent",
            "preferred_tool": "akto_authz_scan",
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
        }
    )
    request = ToolWrapperRequest(
        tool_name="akto_authz_scan",
        run_id="run-akto-adapter",
        target_url="http://127.0.0.1:8001",
        openapi_spec_path=str(spec_path),
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-akto-adapter",
            openapi_url=str(spec_path),
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=20,
        ),
        task=task,
        budgets=ToolBudget(max_requests=5, max_duration_sec=20),
        output_dir=str(tmp_path / "runs"),
    )
    result = ToolWrapperService().execute(request)
    assert result.tool_name == "akto_authz_scan"
    assert result.status == "partial"
    assert "authz_runtime_plan_ready" in result.signals
    assert result.candidate_findings



def test_cats_external_runtime_adapter_returns_normalized_result(tmp_path: Path, monkeypatch) -> None:
    spec_path = _write_openapi(tmp_path / "openapi.json")
    monkeypatch.setenv(
        "CATS_WRAPPER_COMMAND",
        "python scripts/runtime/cats_runtime_adapter.py --request-json {request_json} --result-json {result_json} --output-dir {output_dir}",
    )
    task = TaskModel.model_validate(
        {
            "id": "task_cats_adapter_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/orders",
            "method": "GET",
            "hypothesis": "CATS adapter should preserve runtime handoff.",
            "allowed_tools": ["cats_fuzz_test"],
            "worker_role": "Contract & Negative Testing Agent",
            "preferred_tool": "cats_fuzz_test",
        }
    )
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        run_id="run-cats-adapter",
        target_url="http://127.0.0.1:8001",
        openapi_spec_path=str(spec_path),
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-cats-adapter",
            openapi_url=str(spec_path),
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=20,
        ),
        task=task,
        budgets=ToolBudget(max_requests=5, max_duration_sec=20),
        output_dir=str(tmp_path / "runs"),
    )
    result = ToolWrapperService().execute(request)
    assert result.tool_name == "cats_fuzz_test"
    assert result.status in {"ok", "partial"}
    assert any(path.endswith("cats_runtime_result.json") for path in result.artifacts.raw_report_paths)
    assert any("cats" in signal for signal in result.signals)
