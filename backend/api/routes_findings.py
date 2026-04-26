"""Phase 7 - confirmed finding read routes."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

try:
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from storage.memory_store import memory_store


findings_router = APIRouter(prefix="/v1/findings", tags=["findings"])


@findings_router.get("/confirmed/{campaign_id}")
async def list_confirmed_findings(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found", "message": f"Campaign '{campaign_id}' not found."},
        )
    findings = memory_store.list_confirmed_findings_by_campaign(campaign_id)
    return JSONResponse(status_code=200, content=findings)


@findings_router.get("/confirmed/item/{finding_id}")
async def get_confirmed_finding(finding_id: str) -> JSONResponse:
    finding = memory_store.get_confirmed_finding(finding_id)
    if finding is None:
        return JSONResponse(
            status_code=404,
            content={"error": "finding_not_found", "message": f"Finding '{finding_id}' not found."},
        )
    return JSONResponse(status_code=200, content=finding)
