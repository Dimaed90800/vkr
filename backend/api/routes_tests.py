import logging
from typing import Any

from fastapi import APIRouter, Body, HTTPException, status

try:
    from backend.models.testing import ToolTestRequest, ToolTestResponse
    from backend.services.testing_service import TestingService
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ToolTestRequest, ToolTestResponse
    from services.testing_service import TestingService
    from services.wrapper_observability import append_run_event


logger = logging.getLogger(__name__)
router = APIRouter(tags=["tests"])
testing_service = TestingService()


TOOL_NAME_ALIASES = {
    "probe_entrypoints": "auth_probe_entrypoints",
}


def _normalized_request(request: ToolTestRequest) -> ToolTestRequest:
    canonical_tool_name = TOOL_NAME_ALIASES.get(request.tool_name, request.tool_name)
    normalized = request if canonical_tool_name == request.tool_name else request.model_copy(update={"tool_name": canonical_tool_name})
    append_run_event(
        event_name="legacy_tool_dispatch_start",
        run_id=normalized.execution_context.run_id,
        task_id=normalized.task.id,
        worker_role=normalized.task.worker_role or (normalized.task.context_hints or {}).get("router_assigned_worker"),
        tool_name=normalized.tool_name,
        status="started",
        summary="Legacy tool endpoint received a request.",
        target_url=str(normalized.execution_context.target_url),
        reason={"fallback_reason": "legacy_endpoint_selected"},
        extra={
            "preferred_tool": normalized.task.preferred_tool
            or getattr(normalized.task.tool_preference, "preferred_tool", None),
            "used_legacy_path": True,
            "noop_path": normalized.tool_name == "noop_outcome",
            "current_task_missing": normalized.task.id == "__no_task__",
        },
    )
    return normalized


@router.post(
    "/auth/test-access",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_test_access(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Authorization test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.test_access(request)
    except ValueError as exc:
        logger.warning("Authorization test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_authorization_test", "message": str(exc)},
        ) from exc


@router.post("/auth/auto-provision", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_auto_provision(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.auto_provision(request)
    except ValueError as exc:
        logger.warning("Auth auto-provision rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/probe-entrypoints", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_probe_entrypoints(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.probe_entrypoints(request)
    except ValueError as exc:
        logger.warning("Auth entrypoint probe rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/create-test-object", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_create_test_object(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.create_test_object(request)
    except ValueError as exc:
        logger.warning("Auth create-test-object rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/property-mutation-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_property_mutation_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.property_mutation_test(request)
    except ValueError as exc:
        logger.warning("Auth property-mutation test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_property_mutation_test", "message": str(exc)},
        ) from exc


@router.post(
    "/injection/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def injection_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Injection test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.run_injection_test(request)
    except ValueError as exc:
        logger.warning("Injection test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_injection_test", "message": str(exc)},
        ) from exc


@router.post("/injection/input-shape-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_input_shape_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.input_shape_probe(request)


@router.post("/injection/reflection-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_reflection_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.reflection_probe(request)


@router.post("/injection/path-fuzz-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_path_fuzz_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.path_fuzz_probe(request)


@router.post(
    "/logic/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def logic_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Business logic test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.run_logic_test(request)
    except ValueError as exc:
        logger.warning("Business logic test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_logic_test", "message": str(exc)},
        ) from exc


@router.post("/logic/workflow-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def logic_workflow_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.workflow_probe(request)


@router.post("/data/exposure-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def data_exposure_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.data_exposure_test(request)


@router.post("/resource/abuse-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def resource_abuse_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.resource_abuse_test(request)


@router.post("/config/misconfiguration-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def misconfiguration_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.misconfiguration_test(request)


@router.post("/assets/version-diff-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def version_diff_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.version_diff_test(request)


@router.post("/recon/capture-authenticated-traffic", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def capture_authenticated_traffic(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.capture_authenticated_traffic(request)


@router.post("/recon/capture-anonymous-traffic", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def capture_anonymous_traffic(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.capture_anonymous_traffic(request)


@router.post("/worker/noop-outcome", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def noop_outcome(payload: Any = Body(default=None)) -> ToolTestResponse:
    if not isinstance(payload, dict):
        logger.info("Noop outcome received non-object payload type=%s", type(payload).__name__)
        append_run_event(
            event_name="legacy_tool_dispatch_start",
            run_id=None,
            task_id=None,
            worker_role=None,
            tool_name="noop_outcome",
            status="skipped",
            summary="Noop endpoint received an empty or invalid non-object payload.",
            reason={"fallback_reason": "empty_or_invalid_noop_request"},
            extra={"used_legacy_path": True, "noop_path": True, "current_task_missing": True},
        )
        return ToolTestResponse(
            request_summary={"action": "noop_outcome"},
            response_summary={
                "status": "skipped",
                "reason": "empty_or_invalid_noop_request",
                "payload_type": type(payload).__name__,
            },
            raw_status="skipped",
            indicators=["noop_outcome", "invalid_noop_request"],
        )
    try:
        request = _normalized_request(ToolTestRequest.model_validate(payload))
    except Exception as exc:
        logger.info("Noop outcome received invalid payload: %s", exc)
        append_run_event(
            event_name="legacy_tool_dispatch_start",
            run_id=None,
            task_id=None,
            worker_role=None,
            tool_name="noop_outcome",
            status="skipped",
            summary="Noop endpoint received an invalid object payload.",
            reason={"fallback_reason": "invalid_noop_request", "exception_type": type(exc).__name__},
            extra={"used_legacy_path": True, "noop_path": True, "current_task_missing": True},
        )
        return ToolTestResponse(
            request_summary={"action": "noop_outcome"},
            response_summary={"status": "skipped", "reason": "invalid_noop_request"},
            raw_status="skipped",
            indicators=["noop_outcome", "invalid_noop_request"],
        )
    return await testing_service.noop_outcome(request)
