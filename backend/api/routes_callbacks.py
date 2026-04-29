from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

try:
    from backend.services.ssrf_callback_store import SsrfCallbackStore
except ModuleNotFoundError:  # pragma: no cover
    from services.ssrf_callback_store import SsrfCallbackStore


callbacks_router = APIRouter(prefix="/v1/callbacks", tags=["callbacks"])
_store = SsrfCallbackStore()


def _headers_count(request: Request) -> int:
    try:
        return len(list(request.headers.items()))
    except Exception:
        return 0


@callbacks_router.get("/ssrf/{correlation_id}")
async def ssrf_callback_get(correlation_id: str, request: Request) -> JSONResponse:
    _store.record_callback(
        correlation_id=correlation_id,
        method="GET",
        path=str(request.url.path),
        user_agent=request.headers.get("user-agent"),
        source_ip=(request.client.host if request.client else None),
        headers_count=_headers_count(request),
    )
    return JSONResponse(content={"status": "recorded", "correlation_id": str(correlation_id or "")})


@callbacks_router.post("/ssrf/{correlation_id}")
async def ssrf_callback_post(correlation_id: str, request: Request) -> JSONResponse:
    _store.record_callback(
        correlation_id=correlation_id,
        method="POST",
        path=str(request.url.path),
        user_agent=request.headers.get("user-agent"),
        source_ip=(request.client.host if request.client else None),
        headers_count=_headers_count(request),
    )
    return JSONResponse(content={"status": "recorded", "correlation_id": str(correlation_id or "")})


@callbacks_router.get("/ssrf/{correlation_id}/status")
async def ssrf_callback_status(correlation_id: str) -> JSONResponse:
    return JSONResponse(content=_store.get_status(correlation_id))

