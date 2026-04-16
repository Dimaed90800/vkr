import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.planning import TaskPlanningRequest, TaskPlanningResponse
    from backend.services.task_planner import TaskPlanner
except ModuleNotFoundError:  # pragma: no cover
    from models.planning import TaskPlanningRequest, TaskPlanningResponse
    from services.task_planner import TaskPlanner


logger = logging.getLogger(__name__)
router = APIRouter(tags=["planning"])
task_planner = TaskPlanner()


@router.post(
    "/plan/tasks",
    response_model=TaskPlanningResponse,
    status_code=status.HTTP_200_OK,
)
def plan_tasks(request: TaskPlanningRequest) -> TaskPlanningResponse:
    logger.info(
        "Planning tasks routing_mode=%s generated_tasks=%s",
        request.routing_mode,
        len(request.generated_tasks),
    )
    try:
        response = task_planner.plan(request)
        logger.info(
            "Planner completed routing_mode=%s returned_total=%s router_candidates=%s",
            response.routing_mode,
            response.stats.returned_total,
            response.stats.router_candidate_total,
        )
        return response
    except ValueError as exc:
        logger.warning("Task planning rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_task_planning_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected task planning failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "task_planning_failed", "message": str(exc)},
        ) from exc
