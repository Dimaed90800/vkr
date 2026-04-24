import json

from backend.api.routes_tests import _coerce_tool_request_payload


def _task() -> dict:
    return {
        "id": "task_authorization_028__create_object_then_replay_1",
        "class": "authorization",
        "subtype": "function_level_authorization",
        "endpoint": "/identity/api/v2/admin/videos/{video_id}",
        "method": "DELETE",
        "params": {"path_params": [], "query_params": [], "body_fields": []},
        "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
        "hypothesis": "replay should reach runtime",
        "allowed_tools": ["replay_http_sequence"],
        "test_strategy": "create_object_then_replay",
    }


def test_replay_contract_accepts_dify_active_task_and_context_aliases() -> None:
    request = _coerce_tool_request_payload(
        {
            "active_task_json": json.dumps(_task()),
            "current_execution_context_json": json.dumps(
                {
                    "target_url": "http://example.test/",
                    "run_id": "run-regression",
                    "root_trace_id": "run-regression",
                }
            ),
            "tool_arguments_json": json.dumps(
                {
                    "sequence": [{"method": "GET", "endpoint": "/api/item/1", "expected_status": 200}],
                    "headers": {"X-Test": "1"},
                }
            ),
        },
        default_tool_name="replay_http_sequence",
    )

    assert request.tool_name == "replay_http_sequence"
    assert request.task.id == "task_authorization_028__create_object_then_replay_1"
    assert request.execution_context.run_id == "run-regression"
    assert request.arguments["sequence"][0]["endpoint"] == "/api/item/1"
    assert request.arguments["headers"]["X-Test"] == "1"


def test_replay_contract_builds_execution_context_from_top_level_runtime_fields() -> None:
    request = _coerce_tool_request_payload(
        {
            "current_task": _task(),
            "target_url": "http://example.test/",
            "run_id": "run-regression",
            "root_trace_id": "run-regression",
            "sequence": [{"method": "POST", "endpoint": "/api/item"}],
        },
        default_tool_name="replay_http_sequence",
    )

    assert request.execution_context.target_url.unicode_string() == "http://example.test/"
    assert request.arguments["sequence"][0]["method"] == "POST"


def test_replay_contract_recovers_task_from_execution_context_snapshot() -> None:
    request = _coerce_tool_request_payload(
        {
            "execution_context_json": json.dumps(
                {
                    "target_url": "http://example.test/",
                    "run_id": "run-regression",
                    "root_trace_id": "run-regression",
                    "current_task_snapshot": _task(),
                }
            ),
            "tool_arguments_json": json.dumps({"headers": {"X-Test": "1"}}),
        },
        default_tool_name="replay_http_sequence",
    )

    assert request.task.id == "task_authorization_028__create_object_then_replay_1"
    assert request.arguments["sequence"][0]["endpoint"] == "/identity/api/v2/admin/videos/{video_id}"
