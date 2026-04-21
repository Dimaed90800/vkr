import json
import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.recon import OpenAPIReconRequest, OpenAPIReconResponse
    from backend.services.openapi_normalizer import OpenAPINormalizer
    from backend.services.openapi_service import OpenAPIService
    from backend.services.task_generator import TaskGenerator
except ModuleNotFoundError:  # pragma: no cover
    from models.recon import OpenAPIReconRequest, OpenAPIReconResponse
    from services.openapi_normalizer import OpenAPINormalizer
    from services.openapi_service import OpenAPIService
    from services.task_generator import TaskGenerator


logger = logging.getLogger(__name__)
router = APIRouter(tags=["recon"])
openapi_service = OpenAPIService()
openapi_normalizer = OpenAPINormalizer()
task_generator = TaskGenerator()


@router.post(
    "/recon/openapi",
    response_model=OpenAPIReconResponse,
    status_code=status.HTTP_200_OK,
)
def parse_openapi(request: OpenAPIReconRequest) -> OpenAPIReconResponse:
    logger.info(
        "Received OpenAPI recon request target_url=%s openapi_url=%s has_spec_text=%s",
        request.target_url,
        request.openapi_url,
        bool(request.openapi_spec_text),
    )
    try:
        surface = openapi_service.parse(request)
        normalized_surface = openapi_normalizer.normalize(request, surface)
        generated_tasks: list[dict] = []
        if request.planner_mode in {"auto_tasks", "hybrid", "mvp_openapi"}:
            generated_tasks = task_generator.generate(
                normalized_surface,
                roles=request.roles,
            )
        surface.normalized_surface = normalized_surface if request.planner_mode in {"surface_only", "hybrid", "auto_tasks", "mvp_openapi"} else None
        surface.generated_tasks = generated_tasks
        surface.raw_metadata = {
            **(surface.raw_metadata or {}),
            "normalization_mode": "backend_candidate_extraction",
            "planner_mode": request.planner_mode,
            "generated_tasks_total": len(generated_tasks),
        }
        logger.info(
            "Parsed API surface target_url=%s endpoints=%s generated_tasks=%s",
            surface.target_url,
            len(surface.endpoints),
            len(generated_tasks),
        )
        return surface
    except ValueError as exc:
        logger.warning("Failed to parse OpenAPI input: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_openapi_input", "message": str(exc)},
        ) from exc
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in OpenAPI spec: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_openapi_json", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected OpenAPI parsing failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "openapi_parse_failed", "message": str(exc)},
        ) from exc
