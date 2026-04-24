import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.tool_wrappers import ToolWrapperRequest
    from backend.services.evidence_builder_service import EvidenceBuilderService
    from backend.services.tool_wrappers import ToolWrapperService
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from models.tool_wrappers import ToolWrapperRequest
    from services.evidence_builder_service import EvidenceBuilderService
    from services.tool_wrappers import ToolWrapperService
    from services.wrapper_observability import append_run_event


logger = logging.getLogger(__name__)
router = APIRouter(tags=["tool-wrappers"])
wrapper_service = ToolWrapperService()
evidence_builder = EvidenceBuilderService()


@router.get("/tools/capabilities", status_code=status.HTTP_200_OK)
def get_tool_capabilities() -> dict:
    return wrapper_service.preflight_summary()


@router.get("/tools/preflight", status_code=status.HTTP_200_OK)
def get_tool_preflight() -> dict:
    return wrapper_service.preflight_summary()



@router.post("/tools/wrappers/execute", status_code=status.HTTP_200_OK)
def execute_tool_wrapper(request: ToolWrapperRequest) -> dict:
    logger.info("Executing wrapper tool=%s task_id=%s", request.tool_name, getattr(request.task, "id", None))
    run_id = request.run_id or request.execution_context.run_id
    task_id = getattr(request.task, "id", None)
    worker_role = _worker_role(request)
    preferred_tool = (
        getattr(request.task, "preferred_tool", None)
        or getattr(getattr(request.task, "tool_preference", None), "preferred_tool", None)
        if request.task
        else None
    )
    dispatch_notes = request.task_metadata.get("dispatch_notes") if isinstance(request.task_metadata, dict) else []
    wrapper_first_override = next(
        (str(note) for note in (dispatch_notes or []) if str(note).startswith("wrapper_first_override")),
        None,
    )
    append_run_event(
        event_name="wrapper_dispatch_start",
        run_id=run_id,
        task_id=task_id,
        worker_role=worker_role,
        tool_name=request.tool_name,
        status="started",
        summary="Wrapper dispatch received by backend.",
        target_url=str(request.target_url or request.execution_context.target_url),
        reason={"fallback_reason": None, "wrapper_first_override": wrapper_first_override},
        extra={
            "preferred_tool": preferred_tool,
            "wrapper_first_override": wrapper_first_override,
            "fallback_reason": None,
            "has_openapi_ref": bool(request.openapi_url or request.openapi_spec_path or request.execution_context.openapi_url),
            "has_auth_contexts": bool(request.auth_contexts or request.roles_json or request.execution_context.roles),
            "allowed_hosts_present": bool(request.execution_context.allowed_hosts),
        },
    )
    try:
        for note in dispatch_notes or []:
            if str(note).startswith("wrapper_first_override"):
                logger.info(
                    "Wrapper-first override tool=%s task_id=%s note=%s",
                    request.tool_name,
                    getattr(request.task, "id", None),
                    note,
                )
        result = wrapper_service.execute(request)
        if result.fallback_reason:
            logger.info(
                "Wrapper fallback tool=%s task_id=%s reason=%s",
                request.tool_name,
                getattr(request.task, "id", None),
                result.fallback_reason,
            )
        evidence = evidence_builder.from_wrapper_result(
            task=request.task,
            worker_role=worker_role,
            tool_result=result,
            run_id=run_id,
            notes=["wrapper_normalized_result"],
        )
        append_run_event(
            event_name="wrapper_dispatch_finish",
            run_id=run_id,
            task_id=task_id,
            worker_role=worker_role,
            tool_name=request.tool_name,
            status=result.status,
            summary="Wrapper dispatch completed.",
            reason={"fallback_reason": result.fallback_reason, "termination_reason": result.termination_reason},
            counters={"http_status": status.HTTP_200_OK},
            extra={
                "http_status": status.HTTP_200_OK,
                "wrapper_status": result.status,
                "termination_reason": result.termination_reason,
                "judge_ready_evidence": True,
            },
        )
        return {
            "tool_name": request.tool_name,
            "status": result.status,
            "result": result.model_dump(mode="json"),
            "judge_ready_evidence": evidence.model_dump(mode="json"),
        }
    except Exception as exc:  # pragma: no cover
        append_run_event(
            event_name="wrapper_dispatch_finish",
            run_id=run_id,
            task_id=task_id,
            worker_role=worker_role,
            tool_name=request.tool_name,
            status="error",
            summary="Wrapper dispatch failed before producing judge-ready evidence.",
            reason={"exception_type": type(exc).__name__, "exception_message": str(exc)},
            counters={"http_status": status.HTTP_500_INTERNAL_SERVER_ERROR},
            extra={"http_status": status.HTTP_500_INTERNAL_SERVER_ERROR, "judge_ready_evidence": False},
        )
        logger.exception("Tool wrapper execution failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "tool_wrapper_failed", "message": str(exc)},
        ) from exc


def _worker_role(request: ToolWrapperRequest) -> str:
    if request.task:
        return str(
            (request.task.context_hints or {}).get("worker_role")
            or (request.task.context_hints or {}).get("router_assigned_worker")
            or request.task.worker_role
            or request.task_metadata.get("worker_role")
            or ""
        )
    return str(request.task_metadata.get("worker_role") or "")
