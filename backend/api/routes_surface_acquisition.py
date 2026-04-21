import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.acquisition import (
        BrowserTrafficCaptureRequest,
        BrowserTrafficCaptureResponse,
        JsAnalyzeRequest,
        JsAnalyzeResponse,
        PassiveDiscoveryRequest,
        PassiveDiscoveryResponse,
    )
    from backend.services.browser_capture_service import BrowserCaptureService
    from backend.services.js_analysis_service import JsAnalysisService
    from backend.services.passive_discovery_service import PassiveDiscoveryService
except ModuleNotFoundError:  # pragma: no cover
    from models.acquisition import (
        BrowserTrafficCaptureRequest,
        BrowserTrafficCaptureResponse,
        JsAnalyzeRequest,
        JsAnalyzeResponse,
        PassiveDiscoveryRequest,
        PassiveDiscoveryResponse,
    )
    from services.browser_capture_service import BrowserCaptureService
    from services.js_analysis_service import JsAnalysisService
    from services.passive_discovery_service import PassiveDiscoveryService


logger = logging.getLogger(__name__)
router = APIRouter(tags=["surface-acquisition"])
passive_discovery_service = PassiveDiscoveryService()
js_analysis_service = JsAnalysisService()
browser_capture_service = BrowserCaptureService()


@router.post("/recon/passive-discovery", response_model=PassiveDiscoveryResponse, status_code=status.HTTP_200_OK)
def passive_discovery(request: PassiveDiscoveryRequest) -> PassiveDiscoveryResponse:
    try:
        return passive_discovery_service.discover(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_passive_discovery_request", "message": str(exc)}) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected passive discovery failure")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"error": "passive_discovery_failed", "message": str(exc)}) from exc


@router.post("/recon/js-analyze", response_model=JsAnalyzeResponse, status_code=status.HTTP_200_OK)
def js_analyze(request: JsAnalyzeRequest) -> JsAnalyzeResponse:
    try:
        return js_analysis_service.analyze(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_js_analyze_request", "message": str(exc)}) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected JS analysis failure")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"error": "js_analyze_failed", "message": str(exc)}) from exc


@router.post("/recon/capture-browser-traffic", response_model=BrowserTrafficCaptureResponse, status_code=status.HTTP_200_OK)
def capture_browser_traffic(request: BrowserTrafficCaptureRequest) -> BrowserTrafficCaptureResponse:
    try:
        return browser_capture_service.capture(request)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail={"error": "invalid_browser_capture_request", "message": str(exc)}) from exc
    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected browser traffic capture failure")
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail={"error": "browser_capture_failed", "message": str(exc)}) from exc
