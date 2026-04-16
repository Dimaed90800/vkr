from backend.models.api_surface import NormalizedApiSurface
from backend.models.planning import TaskPlanningRequest
from backend.services.task_planner import TaskPlanner


def _execution_context(max_requests: int = 10) -> dict:
    return {
        "target_url": "http://example.com",
        "allowed_hosts": ["example.com"],
        "roles": [{"name": "user_a"}, {"name": "user_b"}],
        "max_requests": max_requests,
        "max_duration_sec": 300,
        "max_retries_per_task": 1,
    }


def _task(
    task_id: str,
    priority: int,
    *,
    task_class: str = "authorization",
    status: str = "pending",
    endpoint: str | None = None,
) -> dict:
    return {
        "id": task_id,
        "class": task_class,
        "subtype": "bola" if task_class == "authorization" else "workflow_bypass",
        "endpoint": endpoint or f"/resource/{task_id}",
        "method": "GET" if task_class == "authorization" else "POST",
        "params": {
            "path_params": ["id"] if task_class == "authorization" else [],
            "query_params": [],
            "body_fields": [],
            "object_id_candidates": [],
        },
        "auth_context": {
            "owner_role": "user_a",
            "other_role": "user_b",
            "token_strategy": "cross_role_replay",
        },
        "hypothesis": "test hypothesis",
        "priority": priority,
        "retry_count": 0,
        "rework_hint": None,
        "status": status,
        "allowed_tools": ["auth_test_access"] if task_class == "authorization" else ["logic_test"],
    }


def test_planner_backend_only_sorts_and_filters_by_priority() -> None:
    request = TaskPlanningRequest(
        execution_context=_execution_context(max_requests=2),
        normalized_surface=NormalizedApiSurface(endpoints=[]),
        generated_tasks=[
            _task("task_low", 20),
            _task("task_high", 90),
            _task("task_mid", 50),
        ],
        routing_mode="backend_only",
    )

    result = TaskPlanner().plan(request)

    assert result.routing_mode == "backend_only"
    assert result.stats.generated_total == 3
    assert result.stats.returned_total == 2
    assert [task.id for task in result.final_task_queue] == ["task_high", "task_mid"]
    assert result.router_candidate_queue == []


def test_planner_hybrid_prepares_router_candidates() -> None:
    request = TaskPlanningRequest(
        execution_context=_execution_context(max_requests=5),
        normalized_surface=NormalizedApiSurface(endpoints=[]),
        generated_tasks=[
            _task("task_auth", 88, task_class="authorization", endpoint="/users/{id}"),
            _task("task_logic", 67, task_class="business_logic", endpoint="/payments/transfer"),
        ],
        routing_mode="hybrid",
    )

    result = TaskPlanner().plan(request)

    assert result.routing_mode == "hybrid"
    assert result.stats.generated_total == 2
    assert result.stats.returned_total == 2
    assert result.stats.router_candidate_total == 2
    assert [task.id for task in result.router_candidate_queue] == ["task_auth", "task_logic"]
    assert result.metadata.used_backend_generation is True
    assert result.metadata.llm_router_required is False


def test_planner_deduplicates_and_skips_inactive_tasks() -> None:
    request = TaskPlanningRequest(
        execution_context=_execution_context(max_requests=10),
        normalized_surface=NormalizedApiSurface(endpoints=[]),
        generated_tasks=[
            _task("task_a", 80, endpoint="/users/{id}"),
            _task("task_dup", 70, endpoint="/users/{id}"),
            _task("task_done", 95, status="done", endpoint="/users/{id}/history"),
        ],
        routing_mode="backend_only",
    )

    result = TaskPlanner().plan(request)

    assert result.stats.generated_total == 3
    assert result.stats.returned_total == 1
    assert result.metadata.filtered_duplicates == 1
    assert result.metadata.filtered_inactive == 1
    assert [task.id for task in result.final_task_queue] == ["task_a"]


def test_planner_handles_empty_task_generation_case() -> None:
    request = TaskPlanningRequest(
        execution_context=_execution_context(max_requests=5),
        normalized_surface=NormalizedApiSurface(endpoints=[]),
        generated_tasks=[],
        routing_mode="backend_only",
    )

    result = TaskPlanner().plan(request)

    assert result.routing_mode == "backend_only"
    assert result.final_task_queue == []
    assert result.stats.generated_total == 0
    assert result.stats.returned_total == 0
    assert "Generated 0 candidate tasks" in result.planner_summary


def test_planner_llm_only_defers_final_queue_to_router() -> None:
    request = TaskPlanningRequest(
        execution_context=_execution_context(max_requests=5),
        normalized_surface=NormalizedApiSurface(endpoints=[]),
        generated_tasks=[_task("task_a", 80)],
        routing_mode="llm_only",
    )

    result = TaskPlanner().plan(request)

    assert result.routing_mode == "llm_only"
    assert result.final_task_queue == []
    assert result.router_candidate_queue == []
    assert result.metadata.llm_router_required is True
    assert result.stats.generated_total == 1
    assert result.stats.returned_total == 0
