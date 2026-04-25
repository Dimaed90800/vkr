import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.campaign import (
        Campaign,
        CampaignCreateRequest,
        CampaignCreateResponse,
        CampaignSummary,
    )
    from backend.services.campaign_service import CampaignService
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import (
        Campaign,
        CampaignCreateRequest,
        CampaignCreateResponse,
        CampaignSummary,
    )
    from services.campaign_service import CampaignService


logger = logging.getLogger(__name__)
router = APIRouter(tags=["campaigns"])

_campaign_service = CampaignService()


@router.post(
    "/campaigns",
    response_model=CampaignCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
def create_campaign(request: CampaignCreateRequest) -> CampaignCreateResponse:
    logger.info("Creating campaign target_url=%s", request.target_url)
    campaign = _campaign_service.create_campaign(
        target_url=request.target_url,
        openapi_url=request.openapi_url,
        allowed_hosts=request.allowed_hosts or None,
        profile=request.profile,
        limits=request.limits,
        roles_json=request.roles_json,
    )
    return CampaignCreateResponse(
        campaign_id=campaign.campaign_id,
        run_id=campaign.run_id,
        status=campaign.status,
    )


@router.get(
    "/campaigns/{campaign_id}",
    response_model=Campaign,
    status_code=status.HTTP_200_OK,
)
def get_campaign(campaign_id: str) -> Campaign:
    campaign = _campaign_service.get_campaign(campaign_id)
    if campaign is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )
    return campaign


@router.get(
    "/campaigns/{campaign_id}/summary",
    response_model=CampaignSummary,
    status_code=status.HTTP_200_OK,
)
def get_campaign_summary(campaign_id: str) -> CampaignSummary:
    summary = _campaign_service.get_summary(campaign_id)
    if summary is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "campaign_not_found", "campaign_id": campaign_id},
        )
    return summary
