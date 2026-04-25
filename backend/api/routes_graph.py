"""Phase 3 — API graph routes (campaign-scoped)."""
from __future__ import annotations

import logging

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


def _ensure_campaign(campaign_id: str) -> None:
    if not memory_store.get_campaign(campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )


@router.post(
    "/graph/{campaign_id}/build",
    response_model=GraphBuildResponse,
    status_code=status.HTTP_201_CREATED,
)
def build_graph(campaign_id: str, request: GraphBuildRequest) -> GraphBuildResponse:
    _ensure_campaign(campaign_id)
    spec_text = (request.openapi_spec_text or "").strip()
    if not spec_text:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_graph_build_request",
                "message": "openapi_spec_text is required and cannot be empty.",
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
