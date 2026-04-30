"""Phase 5.6 — Observation and VerificationPlan routes.

POST /v1/observations/normalize/{tool_run_id}
POST /v1/observations/triage/{observation_id}
GET  /v1/observations/{campaign_id}
GET  /v1/verification-plans/{campaign_id}

No Judge calls. No EvidencePack construction. No confirmed findings.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

try:
    from backend.models.observation import NormalizeResponse, Observation, TriageResponse
    from backend.services.observation_normalizer import NormalizeError, ObservationNormalizer
    from backend.services.observation_triage import ObservationTriage
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.observation import NormalizeResponse, Observation, TriageResponse
    from services.observation_normalizer import NormalizeError, ObservationNormalizer
    from services.observation_triage import ObservationTriage
    from storage.memory_store import memory_store

observations_router = APIRouter(prefix="/v1/observations", tags=["observations"])
verification_plans_router = APIRouter(prefix="/v1/verification-plans", tags=["verification-plans"])

_normalizer = ObservationNormalizer()
_triage = ObservationTriage()


@observations_router.post("/normalize/{tool_run_id}")
async def normalize_tool_run(tool_run_id: str) -> JSONResponse:
    existing_before = memory_store.list_observations_by_tool_run(tool_run_id)
    try:
        result = _normalizer.normalize(tool_run_id)
    except Exception as exc:  # pragma: no cover
        return JSONResponse(
            status_code=500,
            content={
                "error": "observation_normalization_failed",
                "message": str(exc),
            },
        )
    if isinstance(result, NormalizeError):
        if result.code == "tool_run_not_found":
            return JSONResponse(status_code=404, content={"error": result.code, "message": result.message})
        if result.code == "tool_run_not_terminal":
            return JSONResponse(status_code=409, content={"error": result.code, "message": result.message})
        if result.code == "tool_result_not_found":
            return JSONResponse(status_code=404, content={"error": result.code, "message": result.message})
        return JSONResponse(status_code=400, content={"error": result.code, "message": result.message})

    observations = result
    run_data = memory_store.get_tool_run(tool_run_id)
    campaign_id = run_data.get("campaign_id", "") if run_data else ""

    already = len(existing_before) > 0
    created = 0 if already else len(observations)

    resp = NormalizeResponse(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        observations_created=created,
        observations=observations,
        already_normalized=already,
    )
    return JSONResponse(status_code=200, content=resp.model_dump(mode="json"))


@observations_router.post("/triage/{observation_id}")
async def triage_observation(observation_id: str) -> JSONResponse:
    obs, plan, error = _triage.triage(observation_id)
    if error == "observation_not_found":
        return JSONResponse(status_code=404, content={"error": "observation_not_found"})

    resp = TriageResponse(observation=obs, verification_plan=plan)
    return JSONResponse(status_code=200, content=resp.model_dump(mode="json"))


@observations_router.get("/{campaign_id}")
async def list_observations(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(status_code=404, content={"error": "campaign_not_found"})
    items = memory_store.list_observations_by_campaign(campaign_id)
    return JSONResponse(status_code=200, content=items)


@verification_plans_router.get("/{campaign_id}")
async def list_verification_plans(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(status_code=404, content={"error": "campaign_not_found"})
    items = memory_store.list_verification_plans_by_campaign(campaign_id)
    return JSONResponse(status_code=200, content=items)
