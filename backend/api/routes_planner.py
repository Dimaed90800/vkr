"""Phase 12A — backend WorkerCommand planner routes."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import ValidationError

try:
    from backend.models.planner import PlannerRequest
    from backend.services.planner_service import PlannerError, PlannerService
except ModuleNotFoundError:  # pragma: no cover
    from models.planner import PlannerRequest
    from services.planner_service import PlannerError, PlannerService


planner_router = APIRouter(prefix="/v1/planner", tags=["planner"])

_planner = PlannerService()


@planner_router.post("/{campaign_id}/candidates")
async def planner_candidates(campaign_id: str, body: dict[str, Any]) -> JSONResponse:
    try:
        request = PlannerRequest.model_validate(body)
    except ValidationError as exc:
        return JSONResponse(
            status_code=400,
            content={
                "error": "invalid_planner_request",
                "message": str(exc),
            },
        )
    try:
        response = _planner.plan(campaign_id, request)
    except PlannerError as exc:
        status = 404 if exc.code == "campaign_not_found" else 400
        return JSONResponse(
            status_code=status,
            content={"error": exc.code, "message": exc.message},
        )
    return JSONResponse(status_code=200, content=response.model_dump(mode="json"))
