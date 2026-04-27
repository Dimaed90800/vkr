"""Phase 15A — stateless scenario planning API."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse
from pydantic import ValidationError

try:
    from backend.models.scenario_plan import ScenarioPlanRequestBody
    from backend.services.scenario_plan_service import ScenarioPlanError, ScenarioPlanService
except ModuleNotFoundError:  # pragma: no cover
    from models.scenario_plan import ScenarioPlanRequestBody
    from services.scenario_plan_service import ScenarioPlanError, ScenarioPlanService


scenarios_router = APIRouter(prefix="/v1/scenarios", tags=["scenarios"])
_service = ScenarioPlanService()


@scenarios_router.post("/plan/{campaign_id}")
async def plan_scenarios(campaign_id: str, body: dict) -> JSONResponse:
    try:
        request = ScenarioPlanRequestBody.model_validate(body)
    except ValidationError as exc:
        return JSONResponse(
            status_code=400,
            content={"error": "invalid_scenario_plan_request", "message": str(exc)},
        )
    try:
        response = _service.plan(campaign_id, request)
    except ScenarioPlanError as exc:
        return JSONResponse(
            status_code=int(exc.http_status),
            content={"error": exc.code, "message": exc.message},
        )
    return JSONResponse(status_code=200, content=response.model_dump(mode="json"))
