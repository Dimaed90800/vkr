import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.scheduling import (
        NextTaskRequest,
        NextTaskResponse,
        QueueUpdateRequest,
        QueueUpdateResponse,
    )
    from backend.services.task_scheduler import TaskScheduler
except ModuleNotFoundError:  # pragma: no cover
    from models.scheduling import (
        NextTaskRequest,
        NextTaskResponse,
        QueueUpdateRequest,
        QueueUpdateResponse,
    )
    from services.task_scheduler import TaskScheduler


logger = logging.getLogger(__name__)
router = APIRouter(tags=["scheduling"])
task_scheduler = TaskScheduler()


@router.post(
    "/schedule/next-task",
    response_model=NextTaskResponse,
    status_code=status.HTTP_200_OK,
)
def schedule_next_task(request: NextTaskRequest) -> NextTaskResponse:
    logger.info(
        "Selecting next task pending_tasks=%s last_class=%s consecutive=%s",
        len(request.pending_tasks),
        request.scheduler_state.last_executed_class,
        request.scheduler_state.consecutive_class_count,
    )
    try:
        response = task_scheduler.select_next_task(
            request.pending_tasks,
            state=request.scheduler_state,
            fairness=request.fairness_config,
            execution_context=request.execution_context,
        )
        logger.info(
            "Selected next task task_id=%s selected_class=%s should_stop=%s",
            response.next_task.id if response.next_task else None,
            response.next_task.class_name if response.next_task else None,
            response.should_stop,
        )
        return response
    except ValueError as exc:
        logger.warning("Next-task scheduling rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_next_task_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected next-task scheduling failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "next_task_failed", "message": str(exc)},
        ) from exc


@router.post(
    "/schedule/update-queue",
    response_model=QueueUpdateResponse,
    status_code=status.HTTP_200_OK,
)
def update_queue(request: QueueUpdateRequest) -> QueueUpdateResponse:
    logger.info(
        "Updating queue after verdict=%s pending_tasks=%s active_task=%s",
        request.verdict,
        len(request.pending_tasks),
        request.active_task.id if request.active_task else None,
    )
    try:
        response = task_scheduler.update_queue_after_verdict(
            tasks=request.pending_tasks,
            active_task=request.active_task,
            verdict=request.verdict,
            rework_hint=request.rework_hint,
            evidence=request.evidence,
            max_retries=request.max_retries,
            state=request.scheduler_state,
            fairness=request.fairness_config,
            execution_context=request.execution_context,
        )
        logger.info(
            "Queue update completed pending_tasks=%s reason=%s should_stop=%s",
            len(response.pending_tasks),
            response.queue_update_reason,
            response.should_stop,
        )
        return response
    except ValueError as exc:
        logger.warning("Queue update rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_queue_update_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected queue update failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "queue_update_failed", "message": str(exc)},
        ) from exc
