import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

from backend.models.testing import ExecutionContext, TaskModel, ToolTestRequest, ToolTestResponse
from backend.services.task_tooling_service import DEFAULT_TASK_TOOLING
from backend.services.testing_service import TestingService


def _task(**overrides):
    payload = {
        "id": "task_business_logic_rate_001",
        "class": "business_logic",
        "subtype": "rate_abuse",
        "endpoint": "/signin",
        "method": "GET",
        "hypothesis": "Repeated requests may bypass throttling.",
        "allowed_tools": ["logic_test"],
        "readiness": "ready_to_test",
        "preferred_tool": "schemathesis_stateful_test",
        "fallback_tools": ["bounded_burst_helper", "cats_fuzz_test", "resource_abuse_test"],
        "worker_role": "Business Flow / Stateful Agent",
        "tool_preference": {
            "preferred_tool": "schemathesis_stateful_test",
            "fallback_tools": ["bounded_burst_helper", "cats_fuzz_test", "resource_abuse_test"],
            "artifact_requirements": ["http_trace", "replay_pack", "raw_report"],
            "budget_profile": "burst",
        },
    }
    payload.update(overrides)
    return TaskModel.model_validate(payload)


def _request(task: TaskModel, **kwargs) -> ToolTestRequest:
    execution_context = ExecutionContext(
        target_url="http://127.0.0.1:8001",
        run_id="run-test-runtime-helpers",
        allowed_hosts=["127.0.0.1:8001"],
        max_requests=5,
        max_duration_sec=20,
        traffic_requests=kwargs.pop("traffic_requests", []),
    )
    return ToolTestRequest(
        execution_context=execution_context,
        task=task,
        tool_name=kwargs.pop("tool_name", "bounded_burst_helper"),
        arguments=kwargs.pop("arguments", {}),
    )


def test_task_tooling_adds_runtime_and_burst_helpers() -> None:
    task = _task()
    normalized = DEFAULT_TASK_TOOLING.normalize_task(task)
    assert normalized.allowed_tools[:4] == [
        "schemathesis_stateful_test",
        "logic_test",
        "bounded_burst_helper",
        "cats_fuzz_test",
    ]
    assert "replay_http_sequence" in normalized.allowed_tools
    assert normalized.recommended_next_step == "schemathesis_stateful_test"


def test_import_har_capture_normalizes_entries() -> None:
    service = TestingService()
    request = _request(
        TaskModel.model_validate({
        "id": "task_injection_001",
        "class": "injection",
        "subtype": "input_injection",
        "endpoint": "/api/orders",
        "method": "POST",
        "hypothesis": "Contract should reject malformed bodies.",
        "allowed_tools": ["import_har_capture"],
        "readiness": "needs_preparation",
        "worker_role": "Contract & Negative Testing Agent",
    }),
        tool_name="import_har_capture",
        traffic_requests=[
            {"request": {"method": "GET", "url": "http://127.0.0.1:8001/api/orders"}, "response": {"status": 200}},
            {"method": "POST", "url": "http://127.0.0.1:8001/api/orders", "status_code": 201},
        ],
    )
    response = asyncio.run(service.import_har_capture(request))
    assert response.raw_status == "ok"
    assert "traffic_imported" in response.indicators
    inventory_artifact = next(item for item in response.artifacts if item.type == "runtime_inventory_candidates")
    assert "/api/orders" in inventory_artifact.value


def test_bounded_burst_helper_emits_rate_limit_signal() -> None:
    service = TestingService()

    async def fake_execute(**kwargs):
        statuses = fake_execute.statuses
        return SimpleNamespace(
            method=kwargs["method"],
            url=kwargs["url"],
            status_code=statuses.pop(0),
            headers={},
            body_text="{}",
            elapsed_ms=12.0,
            error=None,
        )

    fake_execute.statuses = [200, 200, 429, 429]
    service.http_client.execute = fake_execute  # type: ignore[assignment]

    request = _request(
        _task(),
        tool_name="bounded_burst_helper",
        arguments={"burst_count": 4},
    )
    response = asyncio.run(service.bounded_burst_helper(request))
    assert response.raw_status == "ok"
    assert "rate_limit_detected" in response.indicators
    artifact = next(item for item in response.artifacts if item.type == "bounded_burst")
    assert artifact.value["status_codes"] == [200, 200, 429, 429]


def test_replay_http_sequence_executes_bounded_steps() -> None:
    service = TestingService()

    async def fake_execute(**kwargs):
        return SimpleNamespace(
            method=kwargs["method"],
            url=kwargs["url"],
            status_code=200,
            headers={},
            body_text="{}",
            elapsed_ms=5.0,
            error=None,
        )

    service.http_client.execute = fake_execute  # type: ignore[assignment]
    task = _task(endpoint="/api/orders", method="POST")
    request = _request(
        task,
        tool_name="replay_http_sequence",
        arguments={
            "sequence": [
                {"method": "POST", "endpoint": "/api/orders"},
                {"method": "GET", "endpoint": "/api/orders/1"},
            ]
        },
    )
    response = asyncio.run(service.replay_http_sequence(request))
    assert response.response_summary["step_count"] == 2
    assert "replay_sequence_completed" in response.indicators


def test_noop_outcome_rescues_preparation_task_to_create_object() -> None:
    service = TestingService()

    async def fake_create_test_object(request):
        from backend.models.testing import ToolTestResponse
        return ToolTestResponse(
            request_summary={"action": "create_test_object"},
            response_summary={"status": "prepared"},
            raw_status="ok",
            indicators=["test_object_created"],
            created_object={"object_id": "123"},
        )

    service.create_test_object = fake_create_test_object  # type: ignore[assignment]
    task = _task(
        class_name="authorization",
        subtype="vertical_privilege",
        endpoint="/workshop/api/management/users/all",
        method="GET",
        allowed_tools=["create_test_object"],
        readiness="needs_preparation",
        test_strategy="create_object_then_replay",
        worker_role="Auth & Identity Agent",
    )
    request = _request(
        task,
        tool_name="noop_outcome",
        arguments={"_parser_warning": {"error": "invalid_toolchain"}},
    )
    response = asyncio.run(service.noop_outcome(request))
    assert response.created_object is not None
    assert response.created_object["object_id"] == "123"
    assert "test_object_created" in response.indicators


def test_noop_outcome_rescues_snapshot_task_when_no_task_placeholder() -> None:
    service = TestingService()
    service.auth_preparation.create_test_object = AsyncMock(return_value=ToolTestResponse(raw_status="ok", indicators=["rescued"]))

    placeholder = TaskModel(
        id="__no_task__",
        class_name="authorization",
        subtype="vertical_privilege",
        endpoint="/admin",
        method="GET",
        hypothesis="noop",
        readiness="ready_to_test",
        allowed_tools=["noop_outcome"],
    )
    real_task = {
        "id": "auth_real",
        "class": "authorization",
        "subtype": "vertical_privilege",
        "endpoint": "/admin",
        "method": "GET",
        "hypothesis": "probe",
        "readiness": "needs_preparation",
        "allowed_tools": ["create_test_object"],
        "preferred_tool": "create_test_object",
    }
    request = ToolTestRequest(
        execution_context=ExecutionContext(target_url="http://example.test", current_task_snapshot=real_task),
        task=placeholder,
        tool_name="noop_outcome",
        arguments={"_parser_warning": {"reason": "lost_task"}},
    )

    response = asyncio.run(service.noop_outcome(request))

    assert response.raw_status == "ok"
    service.auth_preparation.create_test_object.assert_awaited_once()
