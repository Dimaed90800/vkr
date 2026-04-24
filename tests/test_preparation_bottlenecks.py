import json
from pathlib import Path

import pytest

from backend.models.testing import ExecutionContext, TaskModel, ToolTestRequest
from backend.services.auth_preparation_service import AuthPreparationService
from backend.services.http_client import HttpExecutionResult


class _FakePreparationHttpClient:
    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        if url.endswith("/identity/api/auth/signup"):
            return HttpExecutionResult(
                method=method,
                url=url,
                status_code=201,
                headers={},
                body_text=json.dumps({"created": True, "email": (json_body or {}).get("email")}),
                elapsed_ms=1.0,
            )
        if url.endswith("/identity/api/auth/login"):
            principal = (json_body or {}).get("email") or (json_body or {}).get("username") or "user"
            return HttpExecutionResult(
                method=method,
                url=url,
                status_code=200,
                headers={},
                body_text=json.dumps({"access_token": f"token-for-{principal}"}),
                elapsed_ms=1.0,
            )
        if url.endswith("/workshop/api/shop/orders/all"):
            return HttpExecutionResult(
                method=method,
                url=url,
                status_code=200,
                headers={},
                body_text=json.dumps({"orders": [{"order_id": "ord-001", "status": "created"}]}),
                elapsed_ms=1.0,
            )
        return HttpExecutionResult(
            method=method,
            url=url,
            status_code=404,
            headers={},
            body_text=json.dumps({"error": "not found"}),
            elapsed_ms=1.0,
        )




class _CreateFailsThenListSucceedsHttpClient:
    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        if url.endswith('/workshop/api/shop/orders'):
            return HttpExecutionResult(
                method=method,
                url=url,
                status_code=409,
                headers={},
                body_text=json.dumps({"error": "already exists"}),
                elapsed_ms=1.0,
            )
        if url.endswith('/workshop/api/shop/orders/all'):
            return HttpExecutionResult(
                method=method,
                url=url,
                status_code=200,
                headers={},
                body_text=json.dumps({"orders": [{"order_id": "ord-409", "status": "created"}]}),
                elapsed_ms=1.0,
            )
        return HttpExecutionResult(
            method=method,
            url=url,
            status_code=404,
            headers={},
            body_text=json.dumps({"error": "not found"}),
            elapsed_ms=1.0,
        )


class _AlwaysMissingObjectHttpClient:
    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        return HttpExecutionResult(
            method=method,
            url=url,
            status_code=404,
            headers={},
            body_text=json.dumps({"error": "not found"}),
            elapsed_ms=1.0,
        )


def _auth_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_auth_bootstrap_001",
            "class": "authorization",
            "subtype": "auth_bootstrap",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "hypothesis": "Bootstrap two reusable identities.",
            "allowed_tools": ["auto_provision"],
            "readiness": "needs_preparation",
            "test_strategy": "provision_then_replay",
        }
    )


def _object_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_object_materialization_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/workshop/api/shop/orders/{id}",
            "method": "GET",
            "params": {
                "path_params": ["id"],
                "object_id_candidates": [],
                "selected_object_id": None,
                "requires_object_id_enrichment": True,
                "object_param_name": "id",
            },
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "hypothesis": "Order access should require ownership.",
            "allowed_tools": ["create_test_object"],
            "readiness": "needs_preparation",
            "test_strategy": "list_then_select_object_then_replay",
            "resource_family": "order",
        }
    )


@pytest.mark.asyncio
async def test_auto_provision_creates_user_a_user_b_usable_identities(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    context = ExecutionContext(
        target_url="http://api.test",
        run_id="run-auth-bootstrap",
        allowed_hosts=["api.test"],
        discovered_auth_endpoints=[
            {"type": "register", "path": "/identity/api/auth/signup", "method": "POST"},
            {"type": "login", "path": "/identity/api/auth/login", "method": "POST"},
        ],
    )
    request = ToolTestRequest(execution_context=context, task=_auth_task(), tool_name="auto_provision")

    response = await AuthPreparationService(http_client=_FakePreparationHttpClient()).auto_provision(request)

    assert response.raw_status == "success"
    assert "auto_provision_success" in response.indicators
    assert len(response.identities) == 2
    aliases = {alias for identity in response.identities for alias in identity.get("aliases", [])}
    assert {"user_a", "user_b"}.issubset(aliases)
    assert all(identity.get("auth_headers", {}).get("Authorization") for identity in response.identities)
    events = (tmp_path / "logs" / "run-auth-bootstrap" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_start" in events
    assert "auth_provision_login_success" in events
    assert "auth_provision_finish" in events


@pytest.mark.asyncio
async def test_object_materialization_list_path_tracks_attempt_and_success(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    context = ExecutionContext(
        target_url="http://api.test",
        run_id="run-object-materialization",
        allowed_hosts=["api.test"],
        roles=[
            {
                "name": "user_a",
                "role": "user_a",
                "aliases": ["user_a"],
                "auth_headers": {"Authorization": "Bearer token-a"},
            }
        ],
    )
    request = ToolTestRequest(execution_context=context, task=_object_task(), tool_name="create_test_object")

    response = await AuthPreparationService(http_client=_FakePreparationHttpClient()).create_test_object(request)

    assert response.raw_status == "success"
    assert response.created_object is not None
    assert response.created_object["object_id"] == "ord-001"
    summary_path = next((tmp_path / "logs").rglob("run_summary.json"), None)
    assert summary_path is not None
    summary = json.loads(summary_path.read_text(encoding="utf-8"))
    assert summary["_materialization_attempts"] > 0
    assert summary["_materialization_successes"] > 0
    events = (tmp_path / "logs" / "run-object-materialization" / "events.jsonl").read_text(encoding="utf-8")
    assert "object_materialization_start" in events
    assert "object_materialization_list_success" in events
    assert "object_materialization_id_harvested" in events


@pytest.mark.asyncio
async def test_object_materialization_failure_returns_partial_response_not_500(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    context = ExecutionContext(
        target_url="http://api.test",
        run_id="run-object-materialization-failed",
        allowed_hosts=["api.test"],
        roles=[
            {
                "name": "user_a",
                "role": "user_a",
                "aliases": ["user_a"],
                "auth_headers": {"Authorization": "Bearer token-a"},
            }
        ],
    )
    request = ToolTestRequest(execution_context=context, task=_object_task(), tool_name="create_test_object")

    response = await AuthPreparationService(http_client=_AlwaysMissingObjectHttpClient()).create_test_object(request)

    assert response.raw_status in {"failed", "partial"}
    assert response.created_object is None
    assert response.request_summary["owner_identity_name"] == "user_a"
    assert "create_test_object_failed" in response.indicators


@pytest.mark.asyncio
async def test_object_materialization_can_fallback_to_list_after_create_failure(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    context = ExecutionContext(
        target_url="http://api.test",
        run_id="run-object-materialization-create-fallback",
        allowed_hosts=["api.test"],
        roles=[
            {
                "name": "user_a",
                "role": "user_a",
                "aliases": ["user_a"],
                "auth_headers": {"Authorization": "Bearer token-a"},
            }
        ],
    )
    task = _object_task()
    task.endpoint = "/workshop/api/shop/orders/all"
    request = ToolTestRequest(execution_context=context, task=task, tool_name="create_test_object")

    response = await AuthPreparationService(http_client=_CreateFailsThenListSucceedsHttpClient()).create_test_object(request)

    assert response.raw_status == "success"
    assert response.created_object is not None
    assert response.created_object["object_id"] == "ord-409"
    events = (tmp_path / "logs" / "run-object-materialization-create-fallback" / "events.jsonl").read_text(encoding="utf-8")
    assert "object_materialization_list_success" in events
    assert "object_materialization_failed" not in events
