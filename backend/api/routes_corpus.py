from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.corpus import (
        CorpusAddRequest,
        CorpusAddResponse,
        RequestCorpusItem,
    )
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.corpus import (
        CorpusAddRequest,
        CorpusAddResponse,
        RequestCorpusItem,
    )
    from services.request_corpus_service import RequestCorpusService
    from storage.memory_store import memory_store


logger = logging.getLogger(__name__)
router = APIRouter(tags=["corpus"])

_corpus_service = RequestCorpusService()


@router.post(
    "/corpus/add",
    response_model=CorpusAddResponse,
    status_code=status.HTTP_201_CREATED,
)
def add_corpus_item(request: CorpusAddRequest) -> CorpusAddResponse:
    if not memory_store.get_campaign(request.campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": request.campaign_id},
        )

    item = _corpus_service.add_exchange(
        campaign_id=request.campaign_id,
        method=request.method,
        url=request.url,
        headers=request.headers,
        body=request.body,
        status_code=request.status_code,
        response_body=request.response_body,
        response_content_type=request.response_content_type,
        auth_profile=request.auth_profile,
        source=request.source,
        source_tool_run_id=request.source_tool_run_id,
        operation_id=request.operation_id,
        path_template=request.path_template,
    )

    resources_created = len([
        d for d in memory_store.list_resources_by_campaign(request.campaign_id)
        if d.get("source_request_id") == item.request_id
    ])

    return CorpusAddResponse(
        request_id=item.request_id,
        campaign_id=item.campaign_id,
        classification=item.classification,
        extracted_ids=item.extracted_ids,
        resource_instances_created=resources_created,
    )


@router.get(
    "/corpus/{campaign_id}/items",
    response_model=list[RequestCorpusItem],
    status_code=status.HTTP_200_OK,
)
def list_corpus_items(campaign_id: str) -> list[RequestCorpusItem]:
    if not memory_store.get_campaign(campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )
    return _corpus_service.list_by_campaign(campaign_id)


@router.get(
    "/corpus/{campaign_id}/seeds",
    response_model=list[RequestCorpusItem],
    status_code=status.HTTP_200_OK,
)
def list_corpus_seeds(campaign_id: str) -> list[RequestCorpusItem]:
    if not memory_store.get_campaign(campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )
    return [
        item for item in _corpus_service.list_by_campaign(campaign_id)
        if item.classification.value == "successful_seed"
    ]


@router.get(
    "/corpus/{campaign_id}/cross-role-candidates",
    response_model=list[dict[str, Any]],
    status_code=status.HTTP_200_OK,
)
def list_cross_role_candidates(campaign_id: str) -> list[dict[str, Any]]:
    if not memory_store.get_campaign(campaign_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )
    return _corpus_service.find_cross_role_candidates(campaign_id)
