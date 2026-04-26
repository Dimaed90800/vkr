"""Phase 7 - JudgeApply routes.

These routes apply already-produced Judge verdicts. They do not call a Judge,
build evidence, execute tools, enqueue tasks, or write legacy findings.
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

try:
    from backend.models.judge import JudgeApplyRequest
    from backend.services.judge_apply_service import JudgeApplyError, JudgeApplyService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.judge import JudgeApplyRequest
    from services.judge_apply_service import JudgeApplyError, JudgeApplyService
    from storage.memory_store import memory_store


judge_apply_router = APIRouter(prefix="/v1/judge", tags=["judge-apply"])
_service = JudgeApplyService()


@judge_apply_router.post("/apply")
async def apply_judge_verdict(request: JudgeApplyRequest) -> JSONResponse:
    result, error = _service.apply(request)
    if isinstance(error, JudgeApplyError):
        return JSONResponse(
            status_code=error.status_code,
            content={"error": error.code, "message": error.message},
        )
    return JSONResponse(status_code=200, content=result.model_dump(mode="json"))


@judge_apply_router.get("/decisions/{campaign_id}")
async def list_judge_decisions(campaign_id: str) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found", "message": f"Campaign '{campaign_id}' not found."},
        )
    decisions = memory_store.list_judge_decisions_by_campaign(campaign_id)
    return JSONResponse(status_code=200, content=decisions)
