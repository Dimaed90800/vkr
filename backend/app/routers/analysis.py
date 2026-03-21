import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..db import SessionLocal
from ..models import Observation
from ..services.analysis_service import compare_observations

router = APIRouter()


class CompareObservationsRequest(BaseModel):
    observation_a_id: int
    observation_b_id: int


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/compare-observations")
def compare_two_observations(payload: CompareObservationsRequest, db: Session = Depends(get_db)):
    obs_a = db.query(Observation).filter(Observation.id == payload.observation_a_id).first()
    obs_b = db.query(Observation).filter(Observation.id == payload.observation_b_id).first()

    if not obs_a or not obs_b:
        raise HTTPException(status_code=404, detail="One or both observations not found")

    result = compare_observations(obs_a, obs_b)
    return result


@router.get("/latest-pair/{session_id}")
def latest_cross_role_pair(session_id: int, db: Session = Depends(get_db)):
    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).order_by(Observation.id.desc()).all()

    seen = {}
    for obs in observations:
        key = (obs.endpoint, obs.method)
        seen.setdefault(key, []).append(obs)

    for key, items in seen.items():
        roles = {}
        for item in items:
            if item.role_name:
                roles.setdefault(item.role_name, item)

        if len(roles) >= 2:
            role_names = list(roles.keys())[:2]
            obs_a = roles[role_names[0]]
            obs_b = roles[role_names[1]]
            return compare_observations(obs_a, obs_b)

    raise HTTPException(status_code=404, detail="No suitable cross-role observation pair found")