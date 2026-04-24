from backend.models.scheduling import FairnessConfig, SchedulerState
from backend.models.planning import TaskPlanningRequest
from backend.models.testing import ExecutionContext, TaskModel
from backend.services.task_scheduler import TaskScheduler
from backend.services.task_planner import TaskPlanner


def _task(task_id: str, task_class: str, priority: int, retry_count: int = 0) -> TaskModel:
    return TaskModel(
        id=task_id,
        class_name=task_class,
        subtype="bola" if task_class == "authorization" else "workflow_bypass",
        endpoint=f"/{task_class}/{task_id}",
        method="GET" if task_class == "authorization" else "POST",
        params={
            "path_params": [],
            "query_params": [],
            "body_fields": [],
            "object_id_candidates": [],
            "selected_object_id": None,
            "requires_object_id_enrichment": False,
            "object_param_name": None,
        },
        auth_context={
            "owner_role": "user_a",
            "other_role": "user_b",
            "token_strategy": "cross_role_replay",
        },
        hypothesis="test",
        priority=priority,
        retry_count=retry_count,
        rework_hint=None,
        status="pending",
        allowed_tools=["auth_test_access"] if task_class == "authorization" else ["logic_test"],
    )


def test_authorization_cannot_be_picked_three_times_in_a_row_when_others_exist() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("auth_2", "authorization", 90),
        _task("auth_3", "authorization", 80),
        _task("logic_1", "business_logic", 40),
    ]

    ordered, _ = scheduler.order_queue(tasks, fairness=FairnessConfig(max_consecutive_tasks_per_class=2))

    assert [task.id for task in ordered[:3]] == ["auth_1", "auth_2", "logic_1"]


def test_lower_priority_class_gets_turn_after_consecutive_limit() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_high", "authorization", 100),
        _task("auth_mid", "authorization", 90),
        _task("inj_low", "injection", 10),
    ]

    state = SchedulerState(last_executed_class="authorization", consecutive_class_count=2)
    selection = scheduler.schedule(tasks, state=state, fairness=FairnessConfig(max_consecutive_tasks_per_class=2))

    assert selection.selected_task_id == "inj_low"
    assert selection.selected_class == "injection"


def test_rework_authorization_task_does_not_starve_other_classes() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_rework", "authorization", 100, retry_count=1),
        _task("logic_1", "business_logic", 50),
    ]

    state = SchedulerState(last_executed_class="authorization", consecutive_class_count=2)
    selection = scheduler.schedule(tasks, state=state, fairness=FairnessConfig(max_consecutive_tasks_per_class=2))

    assert selection.selected_task_id == "logic_1"
    assert selection.selected_class == "business_logic"


def test_class_budget_limit_prevents_over_scheduling_one_class() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_blocked", "authorization", 100),
        _task("logic_open", "business_logic", 70),
    ]

    state = SchedulerState(class_budget_used={"authorization": 2})
    fairness = FairnessConfig(
        max_consecutive_tasks_per_class=2,
        max_tasks_per_class_per_run={"authorization": 2, "business_logic": 2, "injection": 2},
    )
    selection = scheduler.schedule(tasks, state=state, fairness=fairness)

    assert selection.selected_task_id == "logic_open"
    assert selection.selected_class == "business_logic"
    assert "authorization" in selection.deferred_classes


def test_single_class_queue_still_works_without_deadlock() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("auth_2", "authorization", 90),
        _task("auth_3", "authorization", 80),
    ]

    ordered, _ = scheduler.order_queue(
        tasks,
        state=SchedulerState(last_executed_class="authorization", consecutive_class_count=2),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert [task.id for task in ordered] == ["auth_1", "auth_2", "auth_3"]


def test_next_task_endpoint_respects_max_consecutive_tasks_per_class() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("logic_1", "business_logic", 60),
    ]

    response = scheduler.select_next_task(
        tasks,
        state=SchedulerState(last_executed_class="authorization", consecutive_class_count=2),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert response.next_task is not None
    assert response.next_task.id == "logic_1"
    assert response.scheduler_state.last_executed_class == "business_logic"


def test_next_task_endpoint_respects_max_tasks_per_class_per_run() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("inj_1", "injection", 50),
    ]

    response = scheduler.select_next_task(
        tasks,
        state=SchedulerState(class_budget_used={"authorization": 1}),
        fairness=FairnessConfig(
            max_tasks_per_class_per_run={
                "authorization": 1,
                "injection": 2,
                "business_logic": 2,
            }
        ),
    )

    assert response.next_task is not None
    assert response.next_task.id == "inj_1"
    assert "authorization" in response.deferred_classes


def test_rework_task_reenters_fairly_without_starving_other_classes() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_rework", "authorization", 100, retry_count=0)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.test_strategy = "cross_role_replay"
    active_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    active_task.resource_family = "video"
    active_task.context_hints = {"resource_family": "video"}
    active_task.params.path_params = ["video_id"]
    active_task.params.object_param_name = "video_id"
    active_task.params.selected_object_id = "vid-001"
    active_task.params.object_id_candidates = ["vid-001"]
    pending_tasks = [_task("logic_1", "business_logic", 40)]
    scheduler_state = SchedulerState(last_executed_class="authorization", consecutive_class_count=2)

    updated = scheduler.update_queue_after_verdict(
        tasks=pending_tasks,
        active_task=active_task,
        verdict="rework",
        rework_hint="retry with safer input",
        evidence={"response_summary": {}, "indicators": []},
        max_retries=1,
        state=scheduler_state,
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert [task.id for task in updated.pending_tasks] == ["logic_1", "auth_rework__privileged_function_replay_1"]
    assert updated.requeued_task_id == "auth_rework__privileged_function_replay_1"
    assert updated.generated_followup_task_ids == ["auth_rework__privileged_function_replay_1"]

    next_task = scheduler.select_next_task(
        updated.pending_tasks,
        state=updated.scheduler_state,
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )
    assert next_task.next_task is not None
    assert next_task.next_task.id == "logic_1"


def test_object_dependent_auth_rework_without_object_id_generates_materialization_followups() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_video", "authorization", 95)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.subtype = "function_level_authorization"
    active_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    active_task.method = "DELETE"
    active_task.resource_family = "video"
    active_task.context_hints = {"resource_family": "video"}
    active_task.params.path_params = ["video_id"]
    active_task.params.object_param_name = "video_id"
    active_task.params.requires_object_id_enrichment = True
    active_task.test_strategy = "register_then_login_retry"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Provisioned auth worked, now materialize a real video object first.",
        evidence={"response_summary": {}, "indicators": ["auto_provision_success"]},
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    strategies = {task.test_strategy for task in updated.pending_tasks}
    assert "create_object_then_replay" in strategies
    assert "list_then_select_object_then_replay" in strategies
    assert "privileged_function_replay" not in strategies
    assert all(task.readiness == "needs_preparation" for task in updated.pending_tasks)
    assert all(task.params.requires_object_id_enrichment is True for task in updated.pending_tasks)
    assert all(task.prerequisites.requires_object_id is True for task in updated.pending_tasks)
    assert all(task.allowed_tools == ["create_test_object"] for task in updated.pending_tasks)
    assert all(task.recommended_next_step == "create_test_object" for task in updated.pending_tasks)


def test_object_dependent_auth_rework_with_object_id_allows_privileged_replay() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_video_ready", "authorization", 95)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.subtype = "function_level_authorization"
    active_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    active_task.method = "DELETE"
    active_task.resource_family = "video"
    active_task.context_hints = {"resource_family": "video"}
    active_task.params.path_params = ["video_id"]
    active_task.params.object_param_name = "video_id"
    active_task.params.requires_object_id_enrichment = True
    active_task.params.selected_object_id = "vid-777"
    active_task.params.object_id_candidates = ["vid-777"]
    active_task.test_strategy = "register_then_login_retry"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Replay the privileged function with the materialized object.",
        evidence={"response_summary": {}, "indicators": ["auto_provision_success"]},
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert updated.generated_followup_task_ids == ["auth_video_ready__privileged_function_replay_1"]
    assert updated.pending_tasks[0].test_strategy == "privileged_function_replay"


def test_materialization_followup_prefers_create_test_object_over_auto_provision() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_video_mat", "authorization", 91)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.method = "DELETE"
    task.hypothesis_family = "privileged_function_access"
    task.resource_family = "video"
    task.context_hints = {"resource_family": "video"}
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.readiness = "needs_preparation"
    task.test_strategy = "create_object_then_replay"
    task.allowed_tools = ["create_test_object"]
    task.preparation_options = ["auto_provision", "create_test_object"]

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(
            target_url="http://example.test",
            roles=[{"name": "user_a", "auth_headers": {"Authorization": "Bearer a"}}],
        ),
    )

    assert response.next_task is not None
    assert response.next_task.allowed_tools == ["create_test_object"]
    assert response.next_task.recommended_next_step == "create_test_object"
    assert response.next_task.test_strategy == "create_object_then_replay"


def test_list_then_select_materialization_followup_does_not_fall_back_to_auto_provision() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_video_list", "authorization", 90)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.method = "DELETE"
    task.hypothesis_family = "object_authorization"
    task.resource_family = "video"
    task.context_hints = {"resource_family": "video"}
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.readiness = "needs_preparation"
    task.test_strategy = "list_then_select_object_then_replay"
    task.allowed_tools = ["create_test_object"]
    task.preparation_options = ["auto_provision", "create_test_object"]

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(
            target_url="http://example.test",
            roles=[{"name": "user_a", "auth_headers": {"Authorization": "Bearer a"}}],
        ),
    )

    assert response.next_task is not None
    assert response.next_task.allowed_tools == ["create_test_object"]
    assert response.next_task.test_strategy == "list_then_select_object_then_replay"


def test_rejected_object_auth_failure_generates_list_then_select_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_object", "authorization", 90)
    active_task.hypothesis_family = "object_authorization"
    active_task.params.requires_object_id_enrichment = True
    active_task.resource_family = "video"
    active_task.context_hints = {"resource_family": "video"}

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={"response_summary": {"failure_reason": "placeholder_object_id"}, "indicators": ["placeholder_object_id"]},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert any(task.test_strategy == "list_then_select_object_then_replay" for task in updated.pending_tasks)
    assert any(task.test_strategy == "create_object_then_replay" for task in updated.pending_tasks)


def test_rejected_unauthenticated_workflow_probe_generates_authenticated_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("logic_auth", "business_logic", 80)
    active_task.subtype = "invalid_transition"
    active_task.resource_family = "order"
    active_task.context_hints = {"resource_family": "order", "auth_required": True}

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={"response_summary": {"failure_reason": "unauthenticated_request_to_auth_required_endpoint"}, "indicators": ["missing_auth_context"]},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert any(task.test_strategy == "authenticated_workflow_retry" for task in updated.pending_tasks)


def test_rework_order_workflow_generates_deeper_order_followups() -> None:
    scheduler = TaskScheduler()
    active_task = _task("logic_order_return", "business_logic", 85)
    active_task.subtype = "invalid_transition"
    active_task.endpoint = "/workshop/api/shop/orders/return_order"
    active_task.method = "POST"
    active_task.resource_family = "order"
    active_task.context_hints = {"resource_family": "order", "auth_required": True}
    active_task.hypothesis_family = "invalid_transition"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Prepare an order context and retry the invalid transition sequence.",
        evidence={"response_summary": {"state_delta_summary": {}}, "indicators": []},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    strategies = {task.test_strategy for task in updated.pending_tasks}
    assert "create_order_then_return_order" in strategies
    assert "list_orders_then_pick_order_then_return_order" in strategies


def test_auth_bootstrap_missing_auth_context_generates_reuse_roles_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_bootstrap_1", "authorization", 70)
    active_task.subtype = "auth_bootstrap"
    active_task.hypothesis_family = "authentication_weakness"
    active_task.allowed_tools = ["auto_provision"]

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={"response_summary": {"failure_reason": "missing_auth_context"}, "indicators": ["missing_auth_context"]},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert any(task.test_strategy == "reuse_existing_provisioned_roles" for task in updated.pending_tasks)


def test_injection_baseline_invalid_from_spec_generates_baseline_refinement_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("inj_invalid_spec", "injection", 64)
    active_task.subtype = "body_input_injection"
    active_task.method = "POST"
    active_task.allowed_tools = ["injection_test"]
    active_task.hypothesis_family = "body_input_injection"
    active_task.test_strategy = "direct_input_probe"
    active_task.payload_family = "sqlish"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={"response_summary": {"failure_reason": "baseline_invalid_from_spec"}, "indicators": ["baseline_invalid"]},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert updated.generated_followup_task_ids == ["inj_invalid_spec__baseline_refinement_1"]
    assert updated.pending_tasks[0].test_strategy == "baseline_refinement"
    assert updated.pending_tasks[0].allowed_tools == ["input_shape_probe"]


def test_noop_active_task_does_not_mutate_queue_or_create_normal_update() -> None:
    scheduler = TaskScheduler()
    pending_tasks = [_task("logic_1", "business_logic", 40)]
    active_task = TaskModel(
        id="__no_task__",
        class_name="authorization",
        subtype="noop",
        endpoint="/__dify_no_task__",
        method="GET",
        params={"path_params": [], "query_params": [], "body_fields": []},
        auth_context={"owner_role": "user_a", "other_role": "user_b", "token_strategy": "none"},
        hypothesis="No task available.",
        priority=0,
        retry_count=0,
        rework_hint=None,
        status="pending",
        allowed_tools=["noop_outcome"],
    )

    updated = scheduler.update_queue_after_verdict(
        tasks=pending_tasks,
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        max_retries=1,
    )

    assert updated.queue_update_reason == "noop_active_task"
    assert [task.id for task in updated.pending_tasks] == ["logic_1"]


def test_single_class_queue_select_next_task_still_works() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("auth_2", "authorization", 90),
    ]

    response = scheduler.select_next_task(
        tasks,
        state=SchedulerState(last_executed_class="authorization", consecutive_class_count=2),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_1"
    assert response.should_stop is False


def test_fallback_does_not_repeat_same_class_when_other_classes_exist() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("logic_1", "business_logic", 80),
        _task("inj_1", "injection", 70),
    ]

    response = scheduler.select_next_task(
        tasks,
        state=SchedulerState(
            last_executed_class="authorization",
            consecutive_class_count=8,
            class_budget_used={"authorization": 4, "business_logic": 4, "injection": 4},
        ),
        fairness=FairnessConfig(
            max_consecutive_tasks_per_class=2,
            max_tasks_per_class_per_run={
                "authorization": 4,
                "business_logic": 4,
                "injection": 4,
            },
        ),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_1"
    assert response.selection_reason == "selected_runnable_task_after_all_class_budgets_exhausted"
    assert response.should_stop is False


def test_all_class_budgets_exhausted_keeps_runnable_task_available() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("logic_1", "business_logic", 90),
    ]

    selection = scheduler.schedule(
        tasks,
        state=SchedulerState(class_budget_used={"authorization": 1, "business_logic": 1}),
        fairness=FairnessConfig(
            max_tasks_per_class_per_run={
                "authorization": 1,
                "business_logic": 1,
                "injection": 1,
            }
        ),
    )

    assert selection.selected_task_id == "auth_1"
    assert selection.selected_class == "authorization"
    assert selection.reason == "fallback_single_class_queue"

    response = scheduler.select_next_task(
        tasks,
        state=SchedulerState(class_budget_used={"authorization": 1, "business_logic": 1}),
        fairness=FairnessConfig(
            max_tasks_per_class_per_run={
                "authorization": 1,
                "business_logic": 1,
                "injection": 1,
            }
        ),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_1"
    assert response.should_stop is False
    assert response.selection_reason == "fallback_single_class_queue"


def test_confirmed_vertical_privilege_requires_replay_evidence() -> None:
    scheduler = TaskScheduler()
    active = _task("auth_create_then_replay", "authorization", 100).model_copy(
        update={
            "subtype": "vertical_privilege",
            "test_strategy": "create_object_then_replay",
            "readiness": "needs_preparation",
            "allowed_tools": ["create_test_object"],
        }
    )

    verdict, evidence = scheduler._downgrade_unsafe_confirmed_verdict(
        active_task=active,
        verdict="confirmed",
        evidence={
            "indicators": ["test_object_created"],
            "response_summary": {"finding_type_hint": "vertical_privilege"},
        },
    )

    assert verdict == "rework"
    assert evidence["response_summary"]["unsafe_confirm_downgraded"] is True
    assert evidence["response_summary"]["unsafe_confirm_reason"] == "authorization_confirm_requires_access_or_replay_evidence"




def test_confirmed_function_level_authorization_requires_replay_evidence() -> None:
    scheduler = TaskScheduler()
    active = _task("auth_fn_then_replay", "authorization", 100).model_copy(
        update={
            "subtype": "function_level_authorization",
            "test_strategy": "create_object_then_replay",
            "readiness": "needs_preparation",
            "allowed_tools": ["create_test_object"],
        }
    )

    verdict, evidence = scheduler._downgrade_unsafe_confirmed_verdict(
        active_task=active,
        verdict="confirmed",
        evidence={
            "indicators": ["test_object_created"],
            "response_summary": {"finding_type_hint": "function_level_authorization"},
        },
    )

    assert verdict == "rework"
    assert evidence["response_summary"]["unsafe_confirm_reason"] == "authorization_confirm_requires_access_or_replay_evidence"

def test_should_stop_true_when_no_runnable_tasks_remain() -> None:
    scheduler = TaskScheduler()

    response = scheduler.select_next_task([], state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is None
    assert response.remaining_tasks == []
    assert response.should_stop is True


def test_ready_tasks_of_other_class_are_not_starved_by_fallback() -> None:
    scheduler = TaskScheduler()
    tasks = [
        _task("auth_1", "authorization", 100),
        _task("logic_1", "business_logic", 60),
        _task("inj_1", "injection", 50),
    ]

    selection = scheduler.schedule(
        tasks,
        state=SchedulerState(last_executed_class="authorization", consecutive_class_count=2),
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert selection.selected_task_id != "auth_1"
    assert selection.selected_class in {"business_logic", "injection"}


def test_first_schedule_after_plan_returns_real_task() -> None:
    planner = TaskPlanner()
    scheduler = TaskScheduler()
    planning = planner.plan(
        TaskPlanningRequest(
            execution_context={
                "target_url": "http://example.com",
                "allowed_hosts": ["example.com"],
                "roles": [{"name": "user_a"}, {"name": "user_b"}],
                "max_requests": 10,
                "max_duration_sec": 300,
                "max_retries_per_task": 1,
            },
            normalized_surface={"endpoints": []},
            generated_tasks=[
                _task("auth_1", "authorization", 100),
                _task("logic_1", "business_logic", 70),
                _task("inj_1", "injection", 60),
            ],
            routing_mode="backend_only",
            scheduler_state=SchedulerState(
                class_budget_used={"authorization": 4, "business_logic": 4, "injection": 4},
                class_tasks_completed={"authorization": 4},
                consecutive_class_count=8,
                last_executed_class="authorization",
            ),
        )
    )

    response = scheduler.select_next_task(
        planning.final_task_queue,
        state=planning.scheduler_state,
        fairness=FairnessConfig(),
    )

    assert response.next_task is not None
    assert response.should_stop is False
    assert response.selection_reason != "all_class_budgets_exhausted"


def test_semantic_duplicate_tasks_with_different_ids_only_one_remains_runnable() -> None:
    scheduler = TaskScheduler()
    tasks = [
        TaskModel(
            id="task_auth_a",
            class_name="authorization",
            subtype="bola",
            endpoint="/identity/api/v2/vehicle/{id}/location",
            method="GET",
            params={
                "path_params": ["id"],
                "query_params": [],
                "body_fields": [],
                "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                "selected_object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
                "requires_object_id_enrichment": False,
                "object_param_name": "carId",
            },
            auth_context={
                "owner_role": "user_a",
                "other_role": "user_b",
                "token_strategy": "cross_role_replay",
            },
            hypothesis="Cross-role access may be possible.",
            priority=80,
            retry_count=0,
            rework_hint=None,
            status="pending",
            allowed_tools=["auth_test_access"],
        ),
        TaskModel(
            id="task_auth_b",
            class_name="authorization",
            subtype="bola",
            endpoint="/identity/api/v2/vehicle/{id}/location",
            method="GET",
            params={
                "path_params": ["id"],
                "query_params": [],
                "body_fields": [],
                "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                "selected_object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
                "requires_object_id_enrichment": False,
                "object_param_name": "carId",
            },
            auth_context={
                "owner_role": "user_a",
                "other_role": "user_b",
                "token_strategy": "cross_role_replay",
            },
            hypothesis="Cross-role access may be possible.",
            priority=60,
            retry_count=0,
            rework_hint=None,
            status="pending",
            allowed_tools=["auth_test_access"],
        ),
    ]

    response = scheduler.select_next_task(tasks, state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is not None
    assert response.next_task.id == "task_auth_a"
    assert response.remaining_tasks == []


def test_confirmed_bola_fingerprint_blocks_equivalent_followup_selection() -> None:
    scheduler = TaskScheduler()
    active_task = TaskModel(
        id="task_auth_confirmed",
        class_name="authorization",
        subtype="bola",
        endpoint="/identity/api/v2/vehicle/{id}/location",
        method="GET",
        params={
            "path_params": ["id"],
            "query_params": [],
            "body_fields": [],
            "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
            "selected_object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            "requires_object_id_enrichment": False,
            "object_param_name": "carId",
        },
        auth_context={
            "owner_role": "user_a",
            "other_role": "user_b",
            "token_strategy": "cross_role_replay",
        },
        hypothesis="Cross-role access may be possible.",
        priority=90,
        retry_count=0,
        rework_hint=None,
        status="pending",
        allowed_tools=["auth_test_access"],
    )
    duplicate_pending = [
        active_task.model_copy(update={"id": "task_auth_duplicate", "priority": 70}),
    ]

    updated = scheduler.update_queue_after_verdict(
        tasks=duplicate_pending,
        active_task=active_task,
        verdict="confirmed",
        rework_hint=None,
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.pending_tasks == []
    assert len(updated.scheduler_state.confirmed_finding_fingerprints) == 1

    response = scheduler.select_next_task(
        duplicate_pending,
        state=updated.scheduler_state,
        fairness=FairnessConfig(),
    )
    assert response.next_task is None
    assert response.should_stop is True


def test_confirmed_task_is_not_requeued_again() -> None:
    scheduler = TaskScheduler()
    active_task = TaskModel(
        id="auth_1",
        class_name="authorization",
        subtype="bola",
        endpoint="/identity/api/v2/vehicle/{id}/location",
        method="GET",
        params={
            "path_params": ["id"],
            "query_params": [],
            "body_fields": [],
            "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
            "selected_object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            "requires_object_id_enrichment": False,
            "object_param_name": "carId",
        },
        auth_context={
            "owner_role": "user_a",
            "other_role": "user_b",
            "token_strategy": "cross_role_replay",
        },
        hypothesis="Cross-role access may be possible.",
        priority=100,
        retry_count=0,
        rework_hint=None,
        status="pending",
        allowed_tools=["auth_test_access"],
    )
    pending = [active_task.model_copy(update={"id": "auth_2", "priority": 90})]

    updated = scheduler.update_queue_after_verdict(
        tasks=pending,
        active_task=active_task,
        verdict="confirmed",
        rework_hint=None,
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.requeued_task_id is None
    assert len(updated.pending_tasks) == 0


def test_rework_before_confirmation_is_still_allowed() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_1", "authorization", 100)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.test_strategy = "cross_role_replay"
    active_task.endpoint = "/workshop/api/management/users/all"
    active_task.resource_family = "generic_resource"
    active_task.context_hints = {"resource_family": "generic_resource"}

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="use alternate token",
        evidence={"response_summary": {}, "indicators": []},
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.requeued_task_id == "auth_1__privileged_function_replay_1"
    assert len(updated.pending_tasks) == 1
    assert updated.pending_tasks[0].retry_count == 1
    assert updated.pending_tasks[0].test_strategy == "privileged_function_replay"


def test_queue_cleanup_prefers_highest_priority_semantic_duplicate() -> None:
    scheduler = TaskScheduler()
    base = TaskModel(
        id="dup_low",
        class_name="authorization",
        subtype="bola",
        endpoint="/identity/api/v2/vehicle/{id}/location",
        method="GET",
        params={
            "path_params": ["id"],
            "query_params": [],
            "body_fields": [],
            "object_id_candidates": ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
            "selected_object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            "requires_object_id_enrichment": False,
            "object_param_name": "carId",
        },
        auth_context={
            "owner_role": "user_a",
            "other_role": "user_b",
            "token_strategy": "cross_role_replay",
        },
        hypothesis="Cross-role access may be possible.",
        priority=20,
        retry_count=0,
        rework_hint=None,
        status="pending",
        allowed_tools=["auth_test_access"],
    )
    high = base.model_copy(update={"id": "dup_high", "priority": 95})

    response = scheduler.select_next_task([base, high], state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is not None
    assert response.next_task.id == "dup_high"


def test_injection_rework_creates_alternate_payload_followup() -> None:
    scheduler = TaskScheduler()
    active_task = TaskModel(
        id="inj_signup",
        class_name="injection",
        subtype="body_input_injection",
        endpoint="/workshop/api/mechanic/signup",
        method="POST",
        params={"path_params": [], "query_params": [], "body_fields": ["email", "password", "name"]},
        auth_context={},
        hypothesis="Injected payload may trigger a parsing or sink anomaly.",
        priority=65,
        retry_count=0,
        status="pending",
        allowed_tools=["injection_test", "reflection_probe", "path_fuzz_probe"],
        readiness="ready_to_test",
        test_strategy="direct_input_probe",
        hypothesis_family="body_input_injection",
        payload_family="sqlish",
    )

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Retry with alternate payload family and verify sink/error/reflection signals.",
        evidence={"response_summary": {"evidence_strength": "weak"}, "indicators": []},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.queue_update_reason == "generated_rework_followups"
    assert updated.generated_followup_task_ids == ["inj_signup__alternate_payload_family_1"]
    assert updated.pending_tasks[0].test_strategy == "alternate_payload_family"
    assert updated.pending_tasks[0].payload_family == "templateish"
    assert updated.pending_tasks[0].allowed_tools == ["injection_test"]


def test_validation_only_exposure_rework_creates_success_path_followup() -> None:
    scheduler = TaskScheduler()
    active_task = TaskModel(
        id="exposure_orders",
        class_name="business_logic",
        subtype="excessive_data_exposure",
        endpoint="/workshop/api/shop/orders/all",
        method="GET",
        params={"path_params": [], "query_params": ["limit"], "body_fields": []},
        auth_context={},
        hypothesis="Collection response may expose unnecessary sensitive order data.",
        priority=72,
        retry_count=0,
        status="pending",
        allowed_tools=["data_exposure_test"],
        readiness="ready_to_test",
        test_strategy="collection_probe",
        hypothesis_family="excessive_data_exposure",
        context_hints={"resource_family": "order"},
    )

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Retry with authenticated success-path response and inspect returned object fields.",
        evidence={"response_summary": {"weak_signal_class": "schema_disclosure"}, "indicators": []},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.generated_followup_task_ids == ["exposure_orders__success_path_exposure_probe_1"]
    assert updated.pending_tasks[0].test_strategy == "success_path_exposure_probe"
    assert updated.pending_tasks[0].allowed_tools == ["data_exposure_test"]


def test_different_object_ids_are_not_deduped_together() -> None:
    scheduler = TaskScheduler()
    first = _task("auth_obj_a", "authorization", 90)
    first.endpoint = "/identity/api/v2/vehicle/{vehicleId}/location"
    first.params.path_params = ["vehicleId"]
    first.params.object_param_name = "vehicleId"
    first.params.selected_object_id = "veh-1"
    second = first.model_copy(deep=True)
    second.id = "auth_obj_b"
    second.priority = 80
    second.params.selected_object_id = "veh-2"

    response = scheduler.select_next_task([first, second], state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is not None
    assert response.next_task.id == "auth_obj_a"
    assert [task.id for task in response.remaining_tasks] == ["auth_obj_b"]


def test_different_payload_families_are_preserved() -> None:
    scheduler = TaskScheduler()
    base = TaskModel(
        id="inj_sql",
        class_name="injection",
        subtype="body_input_injection",
        endpoint="/api/search",
        method="POST",
        params={"path_params": [], "query_params": [], "body_fields": ["q"]},
        auth_context={},
        hypothesis="Input may reach a dangerous sink.",
        priority=60,
        retry_count=0,
        status="pending",
        allowed_tools=["injection_test"],
        readiness="ready_to_test",
        test_strategy="alternate_payload_family",
        hypothesis_family="body_input_injection",
        payload_family="sqlish",
    )
    other = base.model_copy(update={"id": "inj_tpl", "priority": 55, "payload_family": "templateish"})

    response = scheduler.select_next_task([base, other], state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is not None
    assert response.next_task.id == "inj_sql"
    assert [task.id for task in response.remaining_tasks] == ["inj_tpl"]


def test_rejected_missing_object_context_generates_preparation_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_vehicle", "authorization", 88)
    active_task.endpoint = "/identity/api/v2/vehicle/{vehicleId}/location"
    active_task.params.path_params = ["vehicleId"]
    active_task.params.object_param_name = "vehicleId"
    active_task.params.requires_object_id_enrichment = True
    active_task.hypothesis_family = "object_authorization"
    active_task.context_hints = {"resource_family": "vehicle"}
    active_task.test_strategy = "cross_role_replay"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={"response_summary": {"failure_reason": "object_creation_failed"}, "indicators": ["invalid_object_id"]},
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.queue_update_reason == "verdict_rejected_generated_followups"
    assert updated.generated_followup_task_ids == ["auth_vehicle__create_object_then_replay_1"]
    assert updated.pending_tasks[0].allowed_tools == ["create_test_object"]
    assert updated.pending_tasks[0].readiness == "needs_preparation"


def test_create_object_then_replay_injects_real_harvested_object_id_into_followup() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_create", "authorization", 86)
    active_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    active_task.params.path_params = ["video_id"]
    active_task.params.object_param_name = "video_id"
    active_task.params.requires_object_id_enrichment = True
    active_task.hypothesis_family = "object_authorization"
    active_task.context_hints = {"resource_family": "video"}

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={
            "response_summary": {"failure_reason": "object_creation_failed"},
            "indicators": ["invalid_object_id"],
            "artifacts": [
                {"type": "prepared_object", "value": {"object_id": "vid-123", "resource_family": "video"}},
                {"type": "harvested_object_ids", "value": ["vid-123"]},
            ],
        },
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    followup = updated.pending_tasks[0]
    assert followup.params.selected_object_id == "vid-123"
    assert "vid-123" in followup.params.object_id_candidates


def test_queue_update_propagates_materialized_object_into_execution_context_and_siblings() -> None:
    scheduler = TaskScheduler()
    active_task = _task("prep_video", "authorization", 86)
    active_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    active_task.params.path_params = ["video_id"]
    active_task.params.object_param_name = "video_id"
    active_task.params.requires_object_id_enrichment = True
    active_task.allowed_tools = ["create_test_object"]
    active_task.readiness = "needs_preparation"
    active_task.hypothesis_family = "object_authorization"
    active_task.resource_family = "video"
    active_task.context_hints = {"resource_family": "video"}

    sibling = _task("auth_video_replay", "authorization", 84)
    sibling.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    sibling.params.path_params = ["video_id"]
    sibling.params.object_param_name = "video_id"
    sibling.params.requires_object_id_enrichment = True
    sibling.allowed_tools = ["create_test_object"]
    sibling.readiness = "needs_preparation"
    sibling.hypothesis_family = "object_authorization"
    sibling.resource_family = "video"
    sibling.context_hints = {"resource_family": "video"}

    updated = scheduler.update_queue_after_verdict(
        tasks=[sibling],
        active_task=active_task,
        verdict="rejected",
        rework_hint=None,
        evidence={
            "response_summary": {"failure_reason": "object_creation_failed"},
            "indicators": ["invalid_object_id"],
            "artifacts": [
                {"type": "prepared_object", "value": {"object_id": "vid-222", "resource_family": "video", "source": "harvested_from_list"}},
                {"type": "harvested_object_ids", "value": ["vid-222"]},
            ],
        },
        max_retries=2,
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test"),
    )

    assert updated.updated_execution_context is not None
    assert updated.updated_execution_context.prepared_objects["video"]["object_id"] == "vid-222"
    assert "vid-222" in updated.updated_execution_context.harvested_object_ids
    assert updated.queue_enrichment["propagated_object_id"] == "vid-222"
    sibling_after = next(task for task in updated.pending_tasks if task.id == "auth_video_replay")
    assert sibling_after.params.selected_object_id == "vid-222"
    assert sibling_after.readiness == "ready_to_test"
    assert sibling_after.allowed_tools == ["auth_test_access"]


def test_list_then_select_followup_becomes_executable_when_prepared_object_exists() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_video", "authorization", 82)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.hypothesis_family = "object_authorization"
    task.resource_family = "video"
    task.readiness = "needs_preparation"
    task.allowed_tools = ["create_test_object"]
    task.preparation_options = ["create_test_object"]
    task.test_strategy = "list_then_select_object_then_replay"

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(
            target_url="http://example.test",
            prepared_objects={"video": {"object_id": "vid-777", "resource_family": "video"}},
            harvested_object_ids=["vid-777"],
        ),
    )

    assert response.next_task is not None
    assert response.next_task.params.selected_object_id == "vid-777"
    assert response.next_task.readiness == "ready_to_test"


def test_object_dependent_auth_task_without_object_id_is_not_executable() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_missing_obj", "authorization", 79)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.allowed_tools = ["auth_test_access"]
    task.preparation_options = []
    task.hypothesis_family = "object_authorization"
    task.resource_family = "video"
    task.prerequisites.requires_object_id = True
    task.prerequisites.requires_auth_context = True

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test", roles=[{"name": "user_a", "auth_headers": {"Authorization": "Bearer a"}}]),
    )

    assert response.next_task is None
    assert response.selection_reason == "missing_object_materialization_path"
    assert response.blocked_by_reason["missing_object_materialization_path"] >= 1


def test_preparation_task_without_object_id_is_still_executable() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_prepare_video", "authorization", 88)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.hypothesis_family = "object_authorization"
    task.resource_family = "video"
    task.prerequisites.requires_object_id = True
    task.readiness = "needs_preparation"
    task.allowed_tools = ["create_test_object"]
    task.preparation_options = ["create_test_object"]
    task.test_strategy = "create_object_then_replay"

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test"),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_prepare_video"
    assert response.next_task.readiness == "needs_preparation"
    assert response.next_task.allowed_tools == ["create_test_object"]
    assert response.selection_reason == "selected_highest_priority_preparation_task"
    assert response.executable_preparation_task_count >= 1


def test_materialization_preparation_can_run_after_class_budget_is_exhausted() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_prepare_video_budget", "authorization", 88)
    task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    task.params.path_params = ["video_id"]
    task.params.object_param_name = "video_id"
    task.params.requires_object_id_enrichment = True
    task.hypothesis_family = "object_authorization"
    task.resource_family = "video"
    task.prerequisites.requires_object_id = True
    task.readiness = "needs_preparation"
    task.allowed_tools = ["create_test_object"]
    task.preparation_options = ["create_test_object"]
    task.test_strategy = "create_object_then_replay"
    task.strategy_family = "object_materialization"

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(class_budget_used={"authorization": 4}),
        fairness=FairnessConfig(max_tasks_per_class_per_run={"authorization": 4, "business_logic": 4, "injection": 4}),
        execution_context=ExecutionContext(
            target_url="http://example.test",
            roles=[
                {"name": "user_a", "role": "user_a", "aliases": ["user_a"], "auth_headers": {"Authorization": "Bearer a"}},
                {"name": "user_b", "role": "user_b", "aliases": ["user_b"], "auth_headers": {"Authorization": "Bearer b"}},
            ],
        ),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_prepare_video_budget"
    assert response.next_task.allowed_tools == ["create_test_object"]
    assert response.next_task.readiness == "needs_preparation"
    assert response.selection_reason == "selected_materialization_preparation_despite_class_budget"
    assert response.scheduler_state.class_budget_used["authorization"] == 4
    assert response.scheduler_state.preparation_budget_used >= 1


def test_scheduler_prioritizes_preparation_when_prerequisites_are_missing() -> None:
    scheduler = TaskScheduler()
    prep_task = _task("auth_prepare_first", "authorization", 100)
    prep_task.endpoint = "/identity/api/v2/admin/videos/{video_id}"
    prep_task.readiness = "needs_preparation"
    prep_task.allowed_tools = ["auto_provision"]
    prep_task.preparation_options = ["auto_provision"]
    prep_task.test_strategy = "register_then_login_retry"
    prep_task.hypothesis_family = "privileged_function_access"
    prep_task.resource_family = "video"
    prep_task.prerequisites.requires_auth_context = True

    test_task = _task("logic_test_ready", "business_logic", 90)
    test_task.allowed_tools = ["logic_test"]
    test_task.readiness = "ready_to_test"
    test_task.test_strategy = "workflow_sequence_probe"

    response = scheduler.select_next_task(
        [test_task, prep_task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(
            target_url="http://example.test",
            capabilities={"has_auth_profiles": False, "has_object_candidates": False},
        ),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_prepare_first"
    assert response.next_task.readiness == "needs_preparation"
    assert response.selection_reason == "selected_highest_priority_preparation_task"
    assert response.scheduler_state.preparation_budget_used >= 1


def test_queue_update_uses_lightweight_remaining_ordering() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_root_lightweight", "authorization", 90)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.test_strategy = "cross_role_replay"

    def _unexpected_order_queue(*args, **kwargs):
        raise AssertionError("update_queue_after_verdict should not resimulate full scheduling")

    scheduler.order_queue = _unexpected_order_queue

    updated = scheduler.update_queue_after_verdict(
        tasks=[_task("logic_still_pending", "business_logic", 50)],
        active_task=active_task,
        verdict="rework",
        rework_hint="materialize object and replay",
        evidence={"response_summary": {"failure_reason": "object_id_missing"}, "indicators": []},
        max_retries=2,
        state=SchedulerState(run_id="run-test-lightweight"),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test"),
    )

    assert updated.pending_tasks
    assert updated.queue_update_reason in {"generated_rework_followups", "requeued_rework_task"}


def test_high_value_followups_are_bounded_by_root_budget() -> None:
    scheduler = TaskScheduler()
    active_task = _task("auth_root", "authorization", 80)
    active_task.hypothesis_family = "privileged_function_access"
    active_task.test_strategy = "cross_role_replay"
    state = SchedulerState(root_followup_counts={"auth_root": 3})

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="retry with stronger privileged replay",
        evidence={"response_summary": {}, "indicators": []},
        max_retries=3,
        state=state,
        fairness=FairnessConfig(),
    )

    assert updated.generated_followup_task_ids == []
    assert updated.requeued_task_id == "auth_root"


def test_scheduler_stops_with_explicit_reason_when_only_non_executable_tasks_exist() -> None:
    scheduler = TaskScheduler()
    task = _task("inj_blocked", "injection", 61)
    task.allowed_tools = ["injection_test"]
    task.readiness = "ready_to_test"
    task.hypothesis_family = "body_input_injection"
    task.prerequisites.requires_valid_baseline = True
    task.context_hints = {"baseline_valid": False, "spec_baseline_available": False}

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test"),
    )

    assert response.next_task is None
    assert response.selection_reason == "missing_valid_baseline_path"
    assert response.blocked_by_reason["missing_valid_baseline_path"] >= 1


def test_baseline_refinement_budget_does_not_consume_alternate_payload_budget() -> None:
    scheduler = TaskScheduler()
    active_task = _task("inj_budget", "injection", 68)
    active_task.subtype = "body_input_injection"
    active_task.method = "POST"
    active_task.allowed_tools = ["injection_test", "input_shape_probe"]
    active_task.hypothesis_family = "body_input_injection"
    active_task.test_strategy = "direct_input_probe"
    active_task.strategy_family = "payload_probe:sqlish"
    active_task.payload_family = "sqlish"

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="Try a different payload family after baseline refinement.",
        evidence={"response_summary": {"evidence_strength": "weak"}, "indicators": []},
        max_retries=2,
        state=SchedulerState(strategy_retry_counts={"injection|/injection/inj_budget|baseline_refinement||user_a|user_b|": 2}),
        fairness=FairnessConfig(),
    )

    assert updated.generated_followup_task_ids == ["inj_budget__alternate_payload_family_1"]
    assert updated.pending_tasks[0].test_strategy == "alternate_payload_family"


def test_authorization_property_tasks_do_not_block_on_missing_baseline_if_mutation_probe_available() -> None:
    scheduler = TaskScheduler()
    task = _task("auth_prop", "authorization", 70)
    task.subtype = "property_level_authorization"
    task.method = "PATCH"
    task.allowed_tools = ["property_mutation_test"]
    task.preferred_tool = "property_mutation_test"
    task.params.body_fields = ["email", "role"]
    task.prerequisites.requires_valid_baseline = True
    task.context_hints = {"baseline_valid": False, "spec_baseline_available": False}

    response = scheduler.select_next_task(
        [task],
        state=SchedulerState(),
        fairness=FairnessConfig(),
        execution_context=ExecutionContext(target_url="http://example.test"),
    )

    assert response.next_task is not None
    assert response.next_task.id == "auth_prop"
    assert response.should_stop is False
