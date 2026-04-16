import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.traffic_discovery import TrafficDiscoveryRequest, TrafficDiscoveryResponse
    from backend.services.traffic_capture_service import TrafficCaptureService
except ModuleNotFoundError:  # pragma: no cover
    from models.traffic_discovery import TrafficDiscoveryRequest, TrafficDiscoveryResponse
    from services.traffic_capture_service import TrafficCaptureService


logger = logging.getLogger(__name__)
router = APIRouter(tags=["traffic-discovery"])
traffic_capture_service = TrafficCaptureService()


@router.post(
    "/recon/traffic",
    response_model=TrafficDiscoveryResponse,
    status_code=status.HTTP_200_OK,
)
def import_traffic_surface(request: TrafficDiscoveryRequest) -> TrafficDiscoveryResponse:
    logger.info("Importing traffic discovery requests=%s", len(request.requests))
    try:
        response = traffic_capture_service.capture(request)
        logger.info(
            "Traffic discovery completed observed_requests=%s normalized_endpoints=%s",
            len(request.requests),
            len(response.normalized_surface.endpoints),
        )
        return response
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_traffic_discovery_request", "message": str(exc)},
        ) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected traffic discovery failure")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "traffic_discovery_failed", "message": str(exc)},
        ) from exc
