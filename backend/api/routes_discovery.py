import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.discovery import DiscoveryRequest, DiscoveryResponse
    from backend.services.discovery_service import DiscoveryService
except ModuleNotFoundError:  # pragma: no cover
    from models.discovery import DiscoveryRequest, DiscoveryResponse
    from services.discovery_service import DiscoveryService


logger = logging.getLogger(__name__)
router = APIRouter(tags=["discovery"])
discovery_service = DiscoveryService()


@router.post(
    "/recon/discovery",
    response_model=DiscoveryResponse,
    status_code=status.HTTP_200_OK,
)
def run_discovery(request: DiscoveryRequest) -> DiscoveryResponse:
    logger.info(
        "Starting discovery target_url=%s mode=%s zap_base_url=%s",
        request.target_url,
        request.discovery_mode,
        request.zap_base_url,
    )
    try:
        response = discovery_service.discover(request)
        logger.info(
            "Discovery completed target_url=%s raw_urls=%s normalized_endpoints=%s",
            response.target_url,
            len(response.raw_urls),
            len(response.normalized_surface.endpoints),
        )
        return response
    except ValueError as exc:
        logger.warning("Discovery rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_discovery_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected discovery failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "discovery_failed", "message": str(exc)},
        ) from exc
