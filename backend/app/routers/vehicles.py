import json
import time
import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel

from ..db import SessionLocal
from ..models import TestSession, RoleCredential, Observation
from ..services.http_service import send_request
from ..services.vehicle_service import build_add_vehicle_body, try_extract_vehicle_ids

router = APIRouter()


class AddVehicleRequest(BaseModel):
    session_id: int
    role_name: str


class ListVehiclesRequest(BaseModel):
    session_id: int
    role_name: str


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _get_session_and_role(db: Session, session_id: int, role_name: str):
    session = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    role = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id,
        RoleCredential.role_name == role_name
    ).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    if not role.access_token:
        raise HTTPException(status_code=400, detail="Role has no access token")

    return session, role


@router.post("/add")
def add_vehicle(payload: AddVehicleRequest, db: Session = Depends(get_db)):
    session, role = _get_session_and_role(db, payload.session_id, payload.role_name)

    suffix = f"{int(time.time())}{uuid.uuid4().hex[:8]}"

    vin = f"VIN{suffix[:17]}".upper()
    plate = f"PLT{suffix[-8:]}".upper()

    try:
        notes = json.loads(role.notes) if role.notes else {}
    except Exception:
        notes = {}

    owner_name = notes.get("name", role.role_name)

    endpoint = f"{session.target_url.rstrip('/')}/identity/api/v2/vehicle/add_vehicle"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"{role.token_type or 'Bearer'} {role.access_token}"
    }
    body = build_add_vehicle_body(vin=vin, plate_number=plate, owner_name=owner_name)

    result = send_request(
        method="POST",
        url=endpoint,
        headers=headers,
        json_body=body
    )

    obs = Observation(
        session_id=payload.session_id,
        endpoint=endpoint,
        method="POST",
        role_name=role.role_name,
        request_headers=json.dumps(headers, ensure_ascii=False),
        request_params=json.dumps({}, ensure_ascii=False),
        request_body=json.dumps(body, ensure_ascii=False),
        status_code=result["status_code"],
        response_headers=json.dumps(result["headers"], ensure_ascii=False),
        body_preview=result["text"][:1000]
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)

    return {
        "observation_id": obs.id,
        "status_code": obs.status_code,
        "body_preview": obs.body_preview[:500],
        "vin": vin,
        "plateNumber": plate
    }


@router.post("/list")
def list_vehicles(payload: ListVehiclesRequest, db: Session = Depends(get_db)):
    session, role = _get_session_and_role(db, payload.session_id, payload.role_name)

    endpoint = f"{session.target_url.rstrip('/')}/identity/api/v2/vehicle/vehicles"
    headers = {
        "Authorization": f"{role.token_type or 'Bearer'} {role.access_token}"
    }

    result = send_request(
        method="GET",
        url=endpoint,
        headers=headers
    )

    obs = Observation(
        session_id=payload.session_id,
        endpoint=endpoint,
        method="GET",
        role_name=role.role_name,
        request_headers=json.dumps(headers, ensure_ascii=False),
        request_params=json.dumps({}, ensure_ascii=False),
        request_body=json.dumps({}, ensure_ascii=False),
        status_code=result["status_code"],
        response_headers=json.dumps(result["headers"], ensure_ascii=False),
        body_preview=result["text"][:1000]
    )
    db.add(obs)
    db.commit()
    db.refresh(obs)

    vehicle_ids = try_extract_vehicle_ids(result["text"])

    return {
        "observation_id": obs.id,
        "status_code": obs.status_code,
        "vehicle_ids": vehicle_ids,
        "body_preview": obs.body_preview[:700]
    }