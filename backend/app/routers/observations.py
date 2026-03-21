import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Observation, RoleCredential, TestSession
from ..schemas import ProbeRequest
from ..services.http_service import send_request

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/probe")
def probe(payload: ProbeRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    final_headers = dict(payload.headers or {})

    if payload.use_role_token:
        if not payload.role_name:
            raise HTTPException(status_code=400, detail="role_name is required when use_role_token=true")

        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
            RoleCredential.role_name == payload.role_name
        ).first()

        if not role:
            raise HTTPException(status_code=404, detail="Role not found")

        if not role.access_token:
            raise HTTPException(status_code=400, detail="Role has no access token")

        token_type = role.token_type or "Bearer"
        final_headers["Authorization"] = f"{token_type} {role.access_token}"

    result = send_request(
        method=payload.method,
        url=payload.endpoint,
        headers=final_headers,
        params=payload.params,
        json_body=payload.json_body
    )

    obs = Observation(
        session_id=payload.session_id,
        endpoint=payload.endpoint,
        method=payload.method.upper(),
        role_name=payload.role_name,
        request_headers=json.dumps(final_headers, ensure_ascii=False),
        request_params=json.dumps(payload.params or {}, ensure_ascii=False),
        request_body=json.dumps(payload.json_body or {}, ensure_ascii=False),
        status_code=result["status_code"],
        response_headers=json.dumps(result["headers"], ensure_ascii=False),
        body_preview=result["text"][:5000]
    )

    db.add(obs)
    db.commit()
    db.refresh(obs)

    return {
        "observation_id": obs.id,
        "status_code": obs.status_code,
        "body_preview": obs.body_preview[:500]
    }


@router.get("/{session_id}")
def list_observations(session_id: int, db: Session = Depends(get_db)):
    return db.query(Observation).filter(Observation.session_id == session_id).all()