"""Phase 3 — API graph routes (campaign-scoped)."""
from __future__ import annotations

import logging
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.api_graph import (
        GraphBuildRequest,
        GraphBuildResponse,
        GraphSummary,
        Operation,
    )
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.api_graph_service import GraphBuildError
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import (
        GraphBuildRequest,
        GraphBuildResponse,
        GraphSummary,
        Operation,
    )
    from services.api_graph_service import ApiGraphService
    from services.api_graph_service import GraphBuildError
    from storage.memory_store import memory_store


logger = logging.getLogger(__name__)
router = APIRouter(tags=["graph"])

_graph_service = ApiGraphService()

_OPENAPI_URL_FETCH_TIMEOUT_SEC = 10.0
_OPENAPI_URL_MAX_BYTES = 5 * 1024 * 1024


def _ensure_campaign(campaign_id: str) -> None:
    if not memory_store.get_campaign(campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )


def _openapi_url_scheme_ok(url: str) -> bool:
    parsed = urlparse(url.strip())
    return parsed.scheme in ("http", "https") and bool(parsed.netloc)


def _fetch_openapi_spec_from_url(url: str) -> str:
    """Fetch OpenAPI document text from URL (spec source only; not target traffic).

    Allowed: explicit http/https URLs from the build request or campaign record.
    Does not log response body.
    """
    trimmed = (url or "").strip()
    if not _openapi_url_scheme_ok(trimmed):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_openapi_url",
                "message": "openapi_url must be http or https with a host.",
            },
        )
    host = urlparse(trimmed).netloc
    try:
        with httpx.Client(
            timeout=_OPENAPI_URL_FETCH_TIMEOUT_SEC,
            follow_redirects=True,
        ) as client:
            resp = client.get(trimmed)
    except httpx.RequestError as exc:
        logger.warning(
            "openapi_url_fetch_failed host=%s exc=%s",
            host,
            type(exc).__name__,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "openapi_url_fetch_failed",
                "message": "Could not fetch OpenAPI document from URL.",
            },
        ) from exc
    if resp.status_code != 200:
        logger.warning(
            "openapi_url_fetch_failed host=%s status=%s",
            host,
            resp.status_code,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "openapi_url_fetch_failed",
                "message": f"OpenAPI URL returned HTTP {resp.status_code}.",
            },
        )
    raw = resp.content
    if len(raw) > _OPENAPI_URL_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "openapi_url_too_large",
                "message": f"OpenAPI document exceeds {_OPENAPI_URL_MAX_BYTES} bytes.",
            },
        )
    if not raw.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "openapi_url_fetch_failed",
                "message": "OpenAPI URL returned an empty body.",
            },
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "openapi_url_fetch_failed",
                "message": "OpenAPI URL body decodes to empty text.",
            },
        )
    logger.info("graph_build_openapi_fetched host=%s bytes=%d", host, len(raw))
    return text


def _resolve_openapi_spec_text(campaign_id: str, request: GraphBuildRequest) -> str:
    """Resolve spec text: inline text, then request.openapi_url, then campaign.openapi_url."""
    spec_text = (request.openapi_spec_text or "").strip()
    if spec_text:
        return spec_text

    fetch_url = (request.openapi_url or "").strip()
    if not fetch_url:
        raw = memory_store.get_campaign(campaign_id) or {}
        fetch_url = str(raw.get("openapi_url") or "").strip()

    if not fetch_url:
        return ""

    return _fetch_openapi_spec_from_url(fetch_url)


@router.post(
    "/graph/{campaign_id}/build",
    response_model=GraphBuildResponse,
    status_code=status.HTTP_201_CREATED,
)
def build_graph(campaign_id: str, request: GraphBuildRequest) -> GraphBuildResponse:
    _ensure_campaign(campaign_id)
    spec_text = _resolve_openapi_spec_text(campaign_id, request)
    if not spec_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_graph_build_request",
                "message": (
                    "Provide non-empty openapi_spec_text, openapi_url on the request, "
                    "or openapi_url on the campaign."
                ),
            },
        )
    try:
        graph = _graph_service.build_from_openapi(campaign_id, spec_text)
    except GraphBuildError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": exc.code, "message": exc.message},
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        ) from exc
    sources_used: list[str] = []
    if any("openapi" in op.sources for op in graph.operations):
        sources_used.append("openapi")
    if any(
        "corpus" in op.sources or op.sources == ["corpus_only"]
        for op in graph.operations
    ):
        sources_used.append("corpus")
    return GraphBuildResponse(
        campaign_id=campaign_id,
        status="built",
        operations_count=len(graph.operations),
        edges_count=len(graph.edges),
        resource_types_count=len(graph.resource_types),
        parameters_count=len(graph.parameters),
        auth_profiles_count=len(graph.auth_profiles),
        sources_used=sources_used,
    )


@router.get(
    "/graph/{campaign_id}/summary",
    response_model=GraphSummary,
    status_code=status.HTTP_200_OK,
)
def get_graph_summary(campaign_id: str) -> GraphSummary:
    _ensure_campaign(campaign_id)
    return _graph_service.summary_for_planner(campaign_id)


@router.get(
    "/graph/{campaign_id}/operations",
    response_model=list[Operation],
    status_code=status.HTTP_200_OK,
)
def list_graph_operations(campaign_id: str) -> list[Operation]:
    _ensure_campaign(campaign_id)
    return _graph_service.list_operations(campaign_id)
