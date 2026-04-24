import logging
import traceback

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
    run_id = request.scheduler_state.run_id or (request.execution_context.run_id if request.execution_context else None)
    root_trace_id = request.scheduler_state.root_trace_id or (request.execution_context.root_trace_id if request.execution_context else None) or run_id
    task_scheduler.diagnostics.emit(
        event_type="schedule_next_task_start",
        component="scheduler_api",
        status="started",
        summary="Received next-task scheduling request.",
        run_id=run_id,
        trace_context=task_scheduler.diagnostics.trace_context(run_id=run_id, root_trace_id=root_trace_id),
        counters={
            "pending_task_count": len(request.pending_tasks or []),
            "class_budget_used_total": sum(int(value or 0) for value in (request.scheduler_state.class_budget_used or {}).values()),
            "preparation_budget_used": int(request.scheduler_state.preparation_budget_used or 0),
            "exploration_budget_used": int(request.scheduler_state.exploration_budget_used or 0),
        },
        artifacts={
            "last_executed_class": request.scheduler_state.last_executed_class,
            "consecutive_class_count": request.scheduler_state.consecutive_class_count,
        },
    )
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
        task_scheduler.diagnostics.emit(
            event_type="schedule_next_task_finish",
            component="scheduler_api",
            status="ok",
            summary="Finished next-task scheduling request.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(run_id=run_id, root_trace_id=root_trace_id),
            reason={"selection_reason": response.selection_reason, "should_stop": response.should_stop},
            counters={
                "remaining_task_count": len(response.remaining_tasks or []),
                "executable_test_task_count": response.executable_test_task_count,
                "executable_preparation_task_count": response.executable_preparation_task_count,
            },
            artifacts={
                "selected_task_id": response.next_task.id if response.next_task else None,
                "selected_class": response.next_task.class_name if response.next_task else None,
            },
        )
        return response
    except ValueError as exc:
        logger.warning("Next-task scheduling rejected: %s", exc)
        task_scheduler.diagnostics.emit(
            event_type="schedule_next_task_error",
            component="scheduler_api",
            status="failed",
            summary="Rejected next-task scheduling request.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(run_id=run_id, root_trace_id=root_trace_id),
            reason={"error": "invalid_next_task_request", "message": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_next_task_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected next-task scheduling failure")
        task_scheduler.diagnostics.emit(
            event_type="schedule_next_task_error",
            component="scheduler_api",
            status="failed",
            summary="Unexpected next-task scheduling failure.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(run_id=run_id, root_trace_id=root_trace_id),
            reason={"error": "next_task_failed", "message": str(exc), "exception_type": type(exc).__name__},
            artifacts={"traceback_preview": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))},
        )
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
    run_id = request.scheduler_state.run_id or (request.execution_context.run_id if request.execution_context else None)
    root_trace_id = request.scheduler_state.root_trace_id or (request.execution_context.root_trace_id if request.execution_context else None) or run_id
    task_scheduler.diagnostics.emit(
        event_type="queue_update_start",
        component="scheduler_api",
        status="started",
        summary="Received queue update request.",
        run_id=run_id,
        trace_context=task_scheduler.diagnostics.trace_context(
            run_id=run_id,
            root_trace_id=root_trace_id,
            task=request.active_task,
        ),
        reason={"verdict": request.verdict},
        counters={
            "pending_task_count": len(request.pending_tasks or []),
            "class_budget_used_total": sum(int(value or 0) for value in (request.scheduler_state.class_budget_used or {}).values()),
            "preparation_budget_used": int(request.scheduler_state.preparation_budget_used or 0),
            "max_retries": int(request.max_retries or 0),
        },
        artifacts={
            "active_task_id": request.active_task.id if request.active_task else None,
            "active_task_class": request.active_task.class_name if request.active_task else None,
        },
    )
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
        task_scheduler.diagnostics.emit(
            event_type="queue_update_finish",
            component="scheduler_api",
            status="ok",
            summary="Finished queue update request.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(
                run_id=run_id,
                root_trace_id=root_trace_id,
                task=request.active_task,
            ),
            reason={
                "queue_update_reason": response.queue_update_reason,
                "should_stop": response.should_stop,
            },
            counters={
                "pending_task_count": len(response.pending_tasks or []),
                "generated_followup_count": len(response.generated_followup_task_ids or []),
            },
            artifacts={
                "requeued_task_id": response.requeued_task_id,
                "generated_followup_task_ids": response.generated_followup_task_ids,
                "queue_enrichment": response.queue_enrichment,
            },
        )
        return response
    except ValueError as exc:
        logger.warning("Queue update rejected: %s", exc)
        task_scheduler.diagnostics.emit(
            event_type="queue_update_error",
            component="scheduler_api",
            status="failed",
            summary="Rejected queue update request.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(
                run_id=run_id,
                root_trace_id=root_trace_id,
                task=request.active_task,
            ),
            reason={"error": "invalid_queue_update_request", "message": str(exc)},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_queue_update_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected queue update failure")
        task_scheduler.diagnostics.emit(
            event_type="queue_update_error",
            component="scheduler_api",
            status="failed",
            summary="Unexpected queue update failure.",
            run_id=run_id,
            trace_context=task_scheduler.diagnostics.trace_context(
                run_id=run_id,
                root_trace_id=root_trace_id,
                task=request.active_task,
            ),
            reason={"error": "queue_update_failed", "message": str(exc), "exception_type": type(exc).__name__},
            artifacts={"traceback_preview": "".join(traceback.format_exception(type(exc), exc, exc.__traceback__, limit=8))},
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "queue_update_failed", "message": str(exc)},
        ) from exc
