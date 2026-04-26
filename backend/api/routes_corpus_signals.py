"""Phase 8 — RequestCorpus signal bridge routes."""
from __future__ import annotations

from pydantic import BaseModel
from fastapi import APIRouter
from fastapi.responses import JSONResponse

try:
    from backend.services.corpus_signal_service import CorpusSignalService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from services.corpus_signal_service import CorpusSignalService
    from storage.memory_store import memory_store


class CrossRoleSignalRequest(BaseModel):
    operation_id: str = ""
    limit: int = 10


router = APIRouter(tags=["corpus-signals"])
_service = CorpusSignalService()


@router.post("/corpus/{campaign_id}/cross-role-signals")
async def create_cross_role_signals(
    campaign_id: str,
    request: CrossRoleSignalRequest | None = None,
) -> JSONResponse:
    if memory_store.get_campaign(campaign_id) is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": "campaign_not_found",
                "message": f"Campaign '{campaign_id}' not found.",
            },
        )
    body = request or CrossRoleSignalRequest()
    result = _service.create_cross_role_signals(
        campaign_id,
        operation_id=body.operation_id,
        limit=body.limit,
    )
    return JSONResponse(status_code=200, content=result)
