import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.testing import ToolTestRequest, ToolTestResponse
    from backend.services.testing_service import TestingService
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ToolTestRequest, ToolTestResponse
    from services.testing_service import TestingService


logger = logging.getLogger(__name__)
router = APIRouter(tags=["tests"])
testing_service = TestingService()


TOOL_NAME_ALIASES = {
    "probe_entrypoints": "auth_probe_entrypoints",
}


def _normalized_request(request: ToolTestRequest) -> ToolTestRequest:
    canonical_tool_name = TOOL_NAME_ALIASES.get(request.tool_name, request.tool_name)
    return request if canonical_tool_name == request.tool_name else request.model_copy(update={"tool_name": canonical_tool_name})


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
async def noop_outcome(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.noop_outcome(request)
