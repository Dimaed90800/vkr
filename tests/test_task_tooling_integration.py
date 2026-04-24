from backend.models.scheduling import ExecutabilityDecision
from backend.models.testing import TaskModel
from backend.services.followup_task_generation_service import FollowupTaskGenerationService
from backend.services.task_executability_service import TaskExecutabilityService


def _task(**overrides) -> TaskModel:
    payload = {
        "id": "task_business_logic_001",
        "class": "business_logic",
        "subtype": "rate_abuse",
        "endpoint": "/signin",
        "method": "GET",
        "hypothesis": "rate limit may be missing",
        "allowed_tools": ["logic_test"],
        "readiness": "ready_to_test",
        "preferred_tool": "schemathesis_stateful_test",
        "fallback_tools": ["restler_fuzz", "akto_authz_scan", "logic_test"],
        "worker_role": "Business Flow / Stateful Agent",
        "tool_preference": {
            "preferred_tool": "schemathesis_stateful_test",
            "fallback_tools": ["restler_fuzz", "akto_authz_scan", "logic_test"],
            "artifact_requirements": ["http_trace", "replay_pack", "raw_report"],
            "budget_profile": "balanced",
        },
    }
    payload.update(overrides)
    return TaskModel.model_validate(payload)


def test_prepare_task_for_execution_preserves_wrapper_first_tooling() -> None:
    task = _task()
    decision = ExecutabilityDecision(executable=True, execution_mode="test")

    updated = TaskExecutabilityService().prepare_task_for_execution(task, decision)

    assert updated.readiness == "ready_to_test"
    assert updated.recommended_next_step == "schemathesis_stateful_test"
    assert updated.allowed_tools[:5] == [
        "schemathesis_stateful_test",
        "restler_fuzz",
        "restler_replay",
        "replay_http_sequence",
        "logic_test",
    ]


def test_followup_clone_keeps_wrapper_first_business_logic_tools() -> None:
    task = _task(id="task_business_logic_026")

    cloned = FollowupTaskGenerationService()._clone_task(
        task,
        "cross_role_sequence_probe",
        allowed_tools=["logic_test"],
        priority_boost=8,
    )

    assert cloned.readiness == "ready_to_test"
    assert cloned.recommended_next_step == "schemathesis_stateful_test"
    assert "schemathesis_stateful_test" in cloned.allowed_tools
    assert "restler_fuzz" in cloned.allowed_tools
    assert cloned.allowed_tools[0] == "schemathesis_stateful_test"


def test_preparation_task_stays_preparation_only() -> None:
    task = TaskModel.model_validate(
        {
            "id": "task_auth_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/orders/{id}",
            "method": "GET",
            "hypothesis": "cross-object access may be possible",
            "allowed_tools": ["create_test_object"],
            "readiness": "needs_preparation",
            "preferred_tool": "akto_authz_scan",
            "fallback_tools": ["astf_top10_suite", "auth_test_access"],
            "preparation_options": ["auto_provision"],
            "worker_role": "Auth & Identity Agent",
        }
    )

    updated = TaskExecutabilityService().prepare_task_for_execution(
        task,
        ExecutabilityDecision(executable=True, execution_mode="preparation", preferred_tool="create_test_object"),
    )

    assert updated.readiness == "needs_preparation"
    assert updated.recommended_next_step == "create_test_object"
    assert updated.allowed_tools == ["create_test_object", "auto_provision", "auth_probe_entrypoints"]
