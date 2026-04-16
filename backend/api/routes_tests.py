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


@router.post(
    "/auth/test-access",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_test_access(request: ToolTestRequest) -> ToolTestResponse:
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


@router.post(
    "/injection/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def injection_test(request: ToolTestRequest) -> ToolTestResponse:
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


@router.post(
    "/logic/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def logic_test(request: ToolTestRequest) -> ToolTestResponse:
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
