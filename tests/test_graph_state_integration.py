from types import SimpleNamespace

from backend.models.scheduling import SchedulerState
from backend.models.testing import ExecutionContext, TaskModel
from backend.services.task_executability_service import TaskExecutabilityService
from backend.services.task_generator import TaskGenerator
from backend.services.task_scheduler import TaskScheduler


def _auth_task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_auth_bola_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/videos/{video_id}",
            "method": "GET",
            "hypothesis": "cross object access may be possible",
            "readiness": "needs_preparation",
            "allowed_tools": ["auto_provision", "create_test_object"],
            "preparation_options": ["auto_provision", "create_test_object"],
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "prerequisites": {"requires_auth_context": True, "requires_object_id": True},
            "resource_family": "video",
        }
    )


def test_executability_uses_graph_state_for_specific_auth_roles() -> None:
    service = TaskExecutabilityService()
    task = _auth_task()
    context = ExecutionContext(
        target_url="http://example.test",
        roles=[
            {"name": "auto_user_a", "role": "user_a", "aliases": ["user_a"], "token": "tok-a"},
        ],
        graph_state={
            "nodes": {
                "auth:user_b:context": {
                    "id": "auth:user_b:context",
                    "kind": "auth_context",
                    "status": "ready",
                    "aliases": ["user_b"],
                    "has_auth_material": True,
                }
            },
            "edges": [],
        },
    )
    decision = service.evaluate(task, execution_context=context, scheduler_state=SchedulerState())
    assert decision.auth_context_available is True
    assert "missing_auth_context" not in decision.missing_prerequisites
    assert any(edge["type"] == "requires" for edge in context.graph_state.get("edges", []))


def test_queue_update_enrichment_populates_graph_nodes() -> None:
    scheduler = TaskScheduler()
    task = _auth_task()
    context = ExecutionContext(target_url="http://example.test")
    evidence = {
        "artifacts": [
            {
                "type": "provisioned_identities",
                "value": [
                    {"name": "auto_user_a", "role": "user_a", "aliases": ["user_a"], "token": "tok-a"},
                    {"name": "auto_user_b", "role": "user_b", "aliases": ["user_b"], "token": "tok-b"},
                ],
            },
            {
                "type": "prepared_object",
                "value": {"object_id": "vid-123", "resource_family": "video", "source": "prepared_object"},
            },
        ]
    }
    _, updated_context, _ = scheduler._apply_evidence_runtime_enrichment(
        pending=[task],
        active_task=task,
        evidence=evidence,
        execution_context=context,
        scheduler_state=SchedulerState(run_id="run-1", root_trace_id="run-1"),
    )
    graph = updated_context.graph_state
    assert "auth:user_a:context" in graph["nodes"]
    assert "auth:user_b:context" in graph["nodes"]
    assert "object:video:vid-123" in graph["nodes"]


def test_generator_keeps_auth_and_materialization_tools_for_object_authorization() -> None:
    generator = TaskGenerator()
    endpoint = SimpleNamespace(path="/videos/{video_id}", auth_required=True, path_params=["video_id"])
    capabilities = {
        "has_auth_profiles": False,
        "has_api_surface": True,
        "has_register_endpoint": True,
        "has_login_endpoint": True,
    }
    allowed_tools = generator._allowed_tools("authorization", "object_authorization", endpoint, capabilities)
    preparation = generator._preparation_options("authorization", "object_authorization", endpoint, capabilities)
    assert allowed_tools[:2] == ["auto_provision", "create_test_object"]
    assert preparation[:2] == ["auto_provision", "create_test_object"]


def test_materialization_strategy_prefers_auto_provision_when_owner_identity_missing() -> None:
    service = TaskExecutabilityService()
    task = TaskModel.model_validate(
        {
            "id": "task_authorization_materialization_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/admin/videos/{video_id}",
            "method": "DELETE",
            "hypothesis": "Materialization should run after bootstrap.",
            "readiness": "needs_preparation",
            "test_strategy": "create_object_then_replay",
            "allowed_tools": ["create_test_object", "auto_provision"],
            "preparation_options": ["create_test_object", "auto_provision"],
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "params": {"requires_object_id_enrichment": True},
            "prerequisites": {"requires_auth_context": True},
            "resource_family": "video",
        }
    )
    decision = service.evaluate(
        task,
        execution_context=ExecutionContext(target_url="http://example.test", roles=[]),
        scheduler_state=SchedulerState(),
    )

    assert decision.executable is True
    assert decision.execution_mode == "preparation"
    assert decision.preferred_tool == "auto_provision"
    assert "missing_auth_context" in decision.missing_prerequisites
    assert "object_id_missing" in decision.missing_prerequisites


def test_materialization_strategy_prefers_create_test_object_with_owner_identity() -> None:
    service = TaskExecutabilityService()
    task = TaskModel.model_validate(
        {
            "id": "task_authorization_materialization_002",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/admin/videos/{video_id}",
            "method": "DELETE",
            "hypothesis": "Materialization should continue with owner auth.",
            "readiness": "needs_preparation",
            "test_strategy": "create_object_then_replay",
            "allowed_tools": ["create_test_object", "auto_provision"],
            "preparation_options": ["create_test_object", "auto_provision"],
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "params": {"requires_object_id_enrichment": True},
            "prerequisites": {"requires_auth_context": True},
            "resource_family": "video",
        }
    )
    context = ExecutionContext(
        target_url="http://example.test",
        roles=[{"name": "user_a", "role": "user_a", "aliases": ["user_a"], "token": "tok-a"}],
    )
    decision = service.evaluate(task, execution_context=context, scheduler_state=SchedulerState())

    assert decision.executable is True
    assert decision.execution_mode == "preparation"
    assert decision.preferred_tool == "create_test_object"
    assert "missing_auth_context" in decision.missing_prerequisites
    assert "object_id_missing" in decision.missing_prerequisites


def test_authorization_followup_keeps_materialization_requirements() -> None:
    from backend.services.followup_task_generation_service import FollowupTaskGenerationService

    service = FollowupTaskGenerationService()
    active_task = TaskModel.model_validate(
        {
            "id": "task_auth_collection_001",
            "class": "authorization",
            "subtype": "generic_access_control",
            "endpoint": "/workshop/api/shop/orders/all",
            "method": "GET",
            "hypothesis": "Collection may leak across users.",
            "readiness": "ready_to_test",
            "allowed_tools": ["auth_test_access"],
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "hypothesis_family": "collection_access_control",
            "resource_family": "order",
        }
    )

    followups = service._authorization_followups(active_task, {}, set(), None, evidence={})
    candidate = next(task for task in followups if task.test_strategy == "object_specific_auth_probe")

    assert candidate.readiness == "needs_preparation"
    assert candidate.prerequisites.requires_object_id is True
    assert candidate.params.requires_object_id_enrichment is True
    assert candidate.preferred_tool == "create_test_object"
    assert candidate.allowed_tools == ["create_test_object"]


def test_scheduler_prioritizes_materialization_preparation_over_tests() -> None:
    scheduler = TaskScheduler()
    prep_task = TaskModel.model_validate(
        {
            "id": "task_authorization_materialize_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/admin/videos/{video_id}",
            "method": "DELETE",
            "hypothesis": "Need an object before replay.",
            "readiness": "needs_preparation",
            "test_strategy": "create_object_then_replay",
            "strategy_family": "object_materialization",
            "allowed_tools": ["create_test_object"],
            "preparation_options": ["create_test_object"],
            "preferred_tool": "create_test_object",
            "params": {"requires_object_id_enrichment": True},
            "prerequisites": {"requires_auth_context": True, "requires_object_id": True},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "resource_family": "video",
            "priority": 90,
        }
    )
    test_task = TaskModel.model_validate(
        {
            "id": "task_business_logic_001",
            "class": "business_logic",
            "subtype": "rate_abuse",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "hypothesis": "Rate limiting may be absent.",
            "readiness": "ready_to_test",
            "allowed_tools": ["schemathesis_stateful_test"],
            "preferred_tool": "schemathesis_stateful_test",
            "priority": 100,
        }
    )
    context = ExecutionContext(
        target_url="http://example.test",
        roles=[{"name": "user_a", "role": "user_a", "aliases": ["user_a"], "token": "tok-a"}],
    )

    response = scheduler.select_next_task(
        [prep_task, test_task],
        state=SchedulerState(run_id="run-1", root_trace_id="run-1"),
        execution_context=context,
    )

    assert response.next_task is not None
    assert response.next_task.id == "task_authorization_materialize_001"
    assert response.selection_reason == "selected_highest_priority_preparation_task"


def test_queue_update_enrichment_applies_replay_endpoint_to_object_task() -> None:
    scheduler = TaskScheduler()
    task = TaskModel.model_validate(
        {
            "id": "task_auth_vehicle_collection_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/vehicle/vehicles",
            "method": "GET",
            "hypothesis": "Collection may expose object-specific access.",
            "readiness": "needs_preparation",
            "allowed_tools": ["create_test_object"],
            "preparation_options": ["create_test_object"],
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "prerequisites": {"requires_auth_context": True, "requires_object_id": True},
            "params": {"requires_object_id_enrichment": True},
            "resource_family": "vehicle",
        }
    )
    context = ExecutionContext(target_url="http://example.test")
    evidence = {
        "artifacts": [
            {
                "type": "prepared_object",
                "value": {
                    "object_id": "veh-123",
                    "resource_family": "vehicle",
                    "source": "harvested_from_list",
                    "replay_endpoint_template": "/identity/api/v2/vehicle/{vehicleId}/location",
                    "replay_path_params": {"vehicleId": "veh-123"},
                },
            }
        ]
    }

    pending, _, enrichment = scheduler._apply_evidence_runtime_enrichment(
        pending=[task],
        active_task=task,
        evidence=evidence,
        execution_context=context,
        scheduler_state=SchedulerState(run_id="run-1", root_trace_id="run-1"),
    )

    assert enrichment["propagated_object_id"] == "veh-123"
    updated = pending[0]
    assert updated.endpoint == "/identity/api/v2/vehicle/{vehicleId}/location"
    assert updated.params.object_param_name == "vehicleId"
    assert updated.params.selected_object_id == "veh-123"


def test_build_post_preparation_replay_task_applies_object_replay_endpoint() -> None:
    scheduler = TaskScheduler()
    active = TaskModel.model_validate(
        {
            "id": "task_authorization_vehicle_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/vehicle/vehicles",
            "method": "GET",
            "hypothesis": "Cross-user access to a specific vehicle may be possible.",
            "readiness": "needs_preparation",
            "allowed_tools": ["create_test_object"],
            "preparation_options": ["create_test_object"],
            "preferred_tool": "create_test_object",
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "prerequisites": {"requires_auth_context": True, "requires_object_id": True},
            "params": {"requires_object_id_enrichment": True},
            "resource_family": "vehicle",
            "test_strategy": "create_object_then_replay",
            "hypothesis_family": "object_authorization",
        }
    )

    replay = scheduler._build_post_preparation_replay_task(
        active,
        "veh-123",
        "vehicle",
        replay_endpoint="/identity/api/v2/vehicle/{vehicleId}/location",
        replay_path_params={"vehicleId": "veh-123"},
    )

    assert replay is not None
    assert replay.endpoint == "/identity/api/v2/vehicle/{vehicleId}/location"
    assert replay.params.object_param_name == "vehicleId"
    assert replay.params.selected_object_id == "veh-123"
    assert replay.readiness == "ready_to_test"
