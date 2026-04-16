from backend.models.scheduling import FairnessConfig, SchedulerState
from backend.models.testing import TaskModel
from backend.services.task_scheduler import TaskScheduler


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
    pending_tasks = [_task("logic_1", "business_logic", 40)]
    scheduler_state = SchedulerState(last_executed_class="authorization", consecutive_class_count=2)

    updated = scheduler.update_queue_after_verdict(
        tasks=pending_tasks,
        active_task=active_task,
        verdict="rework",
        rework_hint="retry with safer input",
        max_retries=1,
        state=scheduler_state,
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )

    assert [task.id for task in updated.pending_tasks] == ["logic_1", "auth_rework"]
    assert updated.requeued_task_id == "auth_rework"

    next_task = scheduler.select_next_task(
        updated.pending_tasks,
        state=updated.scheduler_state,
        fairness=FairnessConfig(max_consecutive_tasks_per_class=2),
    )
    assert next_task.next_task is not None
    assert next_task.next_task.id == "logic_1"


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


def test_should_stop_true_when_no_runnable_tasks_remain() -> None:
    scheduler = TaskScheduler()

    response = scheduler.select_next_task([], state=SchedulerState(), fairness=FairnessConfig())

    assert response.next_task is None
    assert response.remaining_tasks == []
    assert response.should_stop is True


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

    updated = scheduler.update_queue_after_verdict(
        tasks=[],
        active_task=active_task,
        verdict="rework",
        rework_hint="use alternate token",
        max_retries=1,
        state=SchedulerState(),
        fairness=FairnessConfig(),
    )

    assert updated.requeued_task_id == "auth_1"
    assert len(updated.pending_tasks) == 1
    assert updated.pending_tasks[0].retry_count == 1


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
