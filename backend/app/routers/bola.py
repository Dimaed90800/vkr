from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..db import SessionLocal
from ..models import RoleCredential, Observation, TestSession
from ..services.http_service import send_request
from ..services.bola_service import infer_bola_from_observations

router = APIRouter()


class ProbeSameObjectAcrossRolesRequest(BaseModel):
    session_id: int
    owner_role: str
    other_role: str
    endpoint: str
    method: str = "GET"


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/probe-same-object-across-roles")
def probe_same_object_across_roles(payload: ProbeSameObjectAcrossRolesRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    owner = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id,
        RoleCredential.role_name == payload.owner_role
    ).first()

    other = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id,
        RoleCredential.role_name == payload.other_role
    ).first()

    if not owner or not other:
        raise HTTPException(status_code=404, detail="Owner or other role not found")

    if not owner.access_token or not other.access_token:
        raise HTTPException(status_code=400, detail="Both roles must have access tokens")

    owner_headers = {"Authorization": f"{owner.token_type or 'Bearer'} {owner.access_token}"}
    other_headers = {"Authorization": f"{other.token_type or 'Bearer'} {other.access_token}"}

    owner_result = send_request(
        method=payload.method,
        url=payload.endpoint,
        headers=owner_headers
    )
    other_result = send_request(
        method=payload.method,
        url=payload.endpoint,
        headers=other_headers
    )

    obs_owner = Observation(
        session_id=payload.session_id,
        endpoint=payload.endpoint,
        method=payload.method.upper(),
        role_name=owner.role_name,
        request_headers=str(owner_headers),
        request_params="{}",
        request_body="{}",
        status_code=owner_result["status_code"],
        response_headers=str(owner_result["headers"]),
        body_preview=owner_result["text"][:1000]
    )
    db.add(obs_owner)
    db.commit()
    db.refresh(obs_owner)

    obs_other = Observation(
        session_id=payload.session_id,
        endpoint=payload.endpoint,
        method=payload.method.upper(),
        role_name=other.role_name,
        request_headers=str(other_headers),
        request_params="{}",
        request_body="{}",
        status_code=other_result["status_code"],
        response_headers=str(other_result["headers"]),
        body_preview=other_result["text"][:1000]
    )
    db.add(obs_other)
    db.commit()
    db.refresh(obs_other)

    analysis = infer_bola_from_observations(obs_owner, obs_other)

    return {
        "owner_observation_id": obs_owner.id,
        "other_observation_id": obs_other.id,
        "analysis": analysis
    }


@router.get("/infer-from-observations/{owner_observation_id}/{other_observation_id}")
def infer_from_saved_observations(owner_observation_id: int, other_observation_id: int, db: Session = Depends(get_db)):
    obs_owner = db.query(Observation).filter(Observation.id == owner_observation_id).first()
    obs_other = db.query(Observation).filter(Observation.id == other_observation_id).first()

    if not obs_owner or not obs_other:
        raise HTTPException(status_code=404, detail="Observations not found")

    return infer_bola_from_observations(obs_owner, obs_other)