from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
from backend.models.planning import TaskPlanningRequest
from backend.models.testing import ExecutionContext
from backend.services.task_planner import TaskPlanner


def _ctx() -> ExecutionContext:
    return ExecutionContext(
        target_url="http://host.docker.internal:8888",
        roles=[
            {"name": "user_a"},
            {"name": "user_b"},
        ],
        max_requests=20,
        max_duration_sec=300,
        max_retries_per_task=1,
    )


def test_planner_generates_tasks_from_merged_surface() -> None:
    request = TaskPlanningRequest(
        execution_context=_ctx(),
        normalized_surface=NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{id}/location",
                    method="GET",
                    path_params=["id"],
                    object_param_name="id",
                    object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        generated_tasks=[],
        routing_mode="backend_only",
    )

    response = TaskPlanner().plan(request)

    assert response.final_task_queue
    first = response.final_task_queue[0]
    assert first.class_name == "authorization"
    assert first.params.selected_object_id == "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"


def test_planner_works_when_openapi_empty_but_discovery_exists() -> None:
    request = TaskPlanningRequest(
        execution_context=_ctx(),
        normalized_surface=NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/orders/{id}",
                    method="GET",
                    path_params=["id"],
                    object_param_name="id",
                    object_id_candidates=["123"],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        generated_tasks=[],
        routing_mode="backend_only",
    )

    response = TaskPlanner().plan(request)

    assert response.stats.generated_total >= 1
    assert response.final_task_queue
