import logging

from fastapi import APIRouter, HTTPException, status

try:
    from backend.models.storage import (
        EvidenceStoreAck,
        EvidenceStoreRequest,
        FindingStoreAck,
        FindingStoreRequest,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.storage import (
        EvidenceStoreAck,
        EvidenceStoreRequest,
        FindingStoreAck,
        FindingStoreRequest,
    )
    from storage.memory_store import memory_store


logger = logging.getLogger(__name__)
router = APIRouter(tags=["store"])


@router.post(
    "/evidence/store",
    response_model=EvidenceStoreAck,
    status_code=status.HTTP_201_CREATED,
)
def store_evidence(request: EvidenceStoreRequest) -> EvidenceStoreAck:
    logger.info("Storing evidence task_id=%s", request.evidence.task_id)
    try:
        evidence_id = memory_store.store_evidence(request.session_id, request.evidence)
        return EvidenceStoreAck(evidence_id=evidence_id, status="stored")
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to store evidence")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "evidence_store_failed", "message": str(exc)},
        ) from exc


@router.post(
    "/findings/store",
    response_model=FindingStoreAck,
    status_code=status.HTTP_201_CREATED,
)
def store_finding(request: FindingStoreRequest) -> FindingStoreAck:
    logger.info("Storing finding title=%s", request.finding.title)
    try:
        finding_id = memory_store.store_finding(request.session_id, request.finding)
        return FindingStoreAck(finding_id=finding_id, status="stored")
    except Exception as exc:  # pragma: no cover
        logger.exception("Failed to store finding")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail={"error": "finding_store_failed", "message": str(exc)},
        ) from exc
