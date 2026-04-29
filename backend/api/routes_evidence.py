"""Phase 6 — Evidence routes.

Strict-resolve build endpoints and read endpoints for ``EvidencePack``.

Routes never:
* call the Judge,
* create confirmed Findings,
* execute tools,
* enqueue tasks,
* mutate Observations / VerificationPlans.

Endpoint paths (Q7 — avoid ambiguity with static segments):
* ``POST /v1/evidence/build/{observation_id}``
* ``POST /v1/evidence/build-from-plan/{verification_plan_id}``
* ``GET  /v1/evidence/packs/{evidence_id}``
* ``GET  /v1/evidence/campaign/{campaign_id}``
"""
from __future__ import annotations

from fastapi import APIRouter, Query
from fastapi.responses import JSONResponse

try:
    from backend.models.evidence_pack import EvidencePackBuildResponse
    from backend.services.auto_judge_service import apply_judge_for_ready_evidence_in_campaign
    from backend.services.evidence_pack_builder import (
        EvidencePackBuildError,
        EvidencePackBuilder,
    )
    from backend.services.ssrf_evidence_reconciliation_service import (
        reconcile_and_build_ssrf_evidence_for_campaign,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.evidence_pack import EvidencePackBuildResponse
    from services.auto_judge_service import apply_judge_for_ready_evidence_in_campaign
    from services.evidence_pack_builder import (
        EvidencePackBuildError,
        EvidencePackBuilder,
    )
    from services.ssrf_evidence_reconciliation_service import (
        reconcile_and_build_ssrf_evidence_for_campaign,
    )
    from storage.memory_store import memory_store


evidence_router = APIRouter(prefix="/v1/evidence", tags=["evidence"])

_builder = EvidencePackBuilder()


def _error_status(code: str) -> int:
    if code in {
        "observation_not_found",
        "verification_plan_not_found",
        "parent_observation_not_found",
        "campaign_not_found",
    }:
        return 404
    if code in {
        "verification_plan_without_parent_observation",
        "parent_observation_campaign_mismatch",
        "tool_run_campaign_mismatch",
    }:
        return 409
    return 400


def _build_response(pack, existing: bool) -> JSONResponse:
    payload = EvidencePackBuildResponse(evidence_pack=pack, existing=existing)
    return JSONResponse(status_code=200, content=payload.model_dump(mode="json"))


@evidence_router.post("/build/{observation_id}")
async def build_from_observation(
    observation_id: str,
    campaign_id: str | None = Query(default=None),
) -> JSONResponse:
    pack, error, existing = _builder.build_from_observation(
        observation_id,
        campaign_id_hint=campaign_id,
    )
    if isinstance(error, EvidencePackBuildError):
        return JSONResponse(
            status_code=_error_status(error.code),
            content={"error": error.code, "message": error.message},
        )
    return _build_response(pack, existing)


@evidence_router.post("/build-for-campaign/{campaign_id}/{observation_id}")
async def build_from_observation_scoped(
    campaign_id: str,
    observation_id: str,
) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found"},
        )
    pack, error, existing = _builder.build_from_observation(
        observation_id,
        campaign_id_hint=campaign_id,
    )
    if isinstance(error, EvidencePackBuildError):
        return JSONResponse(
            status_code=_error_status(error.code),
            content={"error": error.code, "message": error.message},
        )
    return _build_response(pack, existing)


@evidence_router.post("/build-from-plan/{verification_plan_id}")
async def build_from_verification_plan(verification_plan_id: str) -> JSONResponse:
    pack, error, existing = _builder.build_from_verification_plan(
        verification_plan_id
    )
    if isinstance(error, EvidencePackBuildError):
        return JSONResponse(
            status_code=_error_status(error.code),
            content={"error": error.code, "message": error.message},
        )
    return _build_response(pack, existing)


@evidence_router.get("/packs/{evidence_id}")
async def get_evidence_pack(evidence_id: str) -> JSONResponse:
    pack = memory_store.get_evidence_pack(evidence_id)
    if pack is None:
        return JSONResponse(
            status_code=404,
            content={"error": "evidence_pack_not_found"},
        )
    return JSONResponse(status_code=200, content=pack)


@evidence_router.get("/campaign/{campaign_id}")
async def list_evidence_packs_by_campaign(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found"},
        )
    reconcile_and_build_ssrf_evidence_for_campaign(campaign_id)
    packs = memory_store.list_evidence_packs_by_campaign(campaign_id)
    return JSONResponse(status_code=200, content=packs)


@evidence_router.post("/campaign/{campaign_id}/apply-ready-judge")
async def apply_ready_judge_for_campaign(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found"},
        )
    summary = apply_judge_for_ready_evidence_in_campaign(campaign_id=campaign_id)
    return JSONResponse(status_code=200, content=summary)
