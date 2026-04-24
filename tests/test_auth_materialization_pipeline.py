from __future__ import annotations

from backend.models.testing import ExecutionContext, TaskModel, ToolTestRequest
from backend.services.auth_preparation_service import AuthPreparationService
from backend.services.testing_service import TestingService


def _request_with_roles(roles: list[dict]) -> ToolTestRequest:
    task = TaskModel.model_validate({
        "id": "task_auth_materialization_001",
        "class": "authorization",
        "subtype": "function_level_authorization",
        "endpoint": "/identity/api/v2/admin/videos/{video_id}",
        "method": "DELETE",
        "hypothesis": "cross-role delete may be possible",
        "allowed_tools": ["create_test_object"],
        "readiness": "needs_preparation",
        "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
    })
    ctx = ExecutionContext(
        target_url="http://127.0.0.1:8001",
        allowed_hosts=["127.0.0.1:8001"],
        roles=roles,
    )
    return ToolTestRequest(execution_context=ctx, task=task, tool_name="create_test_object", arguments={})


def test_owner_identity_matches_role_aliases() -> None:
    service = AuthPreparationService()
    request = _request_with_roles([
        {"name": "user_auto_a", "role": "user_a", "aliases": ["user_a"], "token": "tok", "auth_headers": {"Authorization": "Bearer tok"}},
        {"name": "user_auto_b", "role": "user_b", "aliases": ["user_b"], "token": "tok2", "auth_headers": {"Authorization": "Bearer tok2"}},
    ])
    owner = service._owner_identity(request, None)
    assert owner is not None
    assert owner.get("role") == "user_a"


def test_testing_service_role_profiles_index_aliases() -> None:
    service = TestingService()
    request = _request_with_roles([
        {"name": "user_auto_a", "role": "user_a", "aliases": ["user_a"], "token": "tok", "auth_headers": {"Authorization": "Bearer tok"}},
    ])
    profiles = service._role_profiles(request)
    assert "user_a" in profiles
    assert profiles["user_a"]["token"] == "tok"
