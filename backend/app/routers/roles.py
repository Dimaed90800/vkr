import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, RoleCredential, Observation
from ..schemas import CreateRoleRequest, RegisterRoleRequest, LoginRoleRequest
from ..services.http_service import send_request
from ..services.role_service import generate_unique_identity, extract_tokens_from_response_text

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/create")
def create_role(payload: CreateRoleRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    existing = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id,
        RoleCredential.role_name == payload.role_name
    ).first()
    if existing:
        return {
            "id": existing.id,
            "role_name": existing.role_name,
            "email": existing.email,
            "status": existing.status
        }

    identity = generate_unique_identity(payload.role_name)

    role = RoleCredential(
        session_id=payload.session_id,
        role_name=payload.role_name,
        email=identity["email"],
        password=identity["password"],
        phone_number=identity["phone_number"],
        status="created",
        notes=json.dumps({"name": identity["name"]}, ensure_ascii=False)
    )
    db.add(role)
    db.commit()
    db.refresh(role)

    return {
        "id": role.id,
        "role_name": role.role_name,
        "email": role.email,
        "phone_number": role.phone_number,
        "status": role.status
    }


@router.post("/register")
def register_role(payload: RegisterRoleRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    role = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id,
        RoleCredential.role_name == payload.role_name
    ).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    notes = {}
    if role.notes:
        try:
            notes = json.loads(role.notes)
        except Exception:
            notes = {}

    signup_url = f"{session.target_url.rstrip('/')}/identity/api/auth/signup"
    body = {
        "name": notes.get("name", payload.role_name),
        "email": role.email,
        "password": role.password,
        "number": role.phone_number
    }

    result = send_request(
        method="POST",
        url=signup_url,
        headers={"Content-Type": "application/json"},
        json_body=body
    )

    obs = Observation(
        session_id=payload.session_id,
        endpoint=signup_url,
        method="POST",
        role_name=role.role_name,
        request_headers=json.dumps({"Content-Type": "application/json"}, ensure_ascii=False),
        request_params=json.dumps({}, ensure_ascii=False),
        request_body=json.dumps(body, ensure_ascii=False),
        status_code=result["status_code"],
        response_headers=json.dumps(result["headers"], ensure_ascii=False),
        body_preview=result["text"][:1000]
    )
    db.add(obs)

    if result["status_code"] == 200:
        role.status = "registered"
    else:
        role.status = "failed"
    role.last_auth_status = result["status_code"]

    db.commit()
    db.refresh(obs)
    db.refresh(role)

    return {
        "role_name": role.role_name,
        "status": role.status,
        "http_status": result["status_code"],
        "body_preview": result["text"][:300]
    }


@router.post("/login")
def login_role(payload: LoginRoleRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    role = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id,
        RoleCredential.role_name == payload.role_name
    ).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")

    login_url = f"{session.target_url.rstrip('/')}/identity/api/auth/login"
    body = {
        "email": role.email,
        "password": role.password
    }

    result = send_request(
        method="POST",
        url=login_url,
        headers={"Content-Type": "application/json"},
        json_body=body
    )

    obs = Observation(
        session_id=payload.session_id,
        endpoint=login_url,
        method="POST",
        role_name=role.role_name,
        request_headers=json.dumps({"Content-Type": "application/json"}, ensure_ascii=False),
        request_params=json.dumps({}, ensure_ascii=False),
        request_body=json.dumps(body, ensure_ascii=False),
        status_code=result["status_code"],
        response_headers=json.dumps(result["headers"], ensure_ascii=False),
        body_preview=result["text"][:1000]
    )
    db.add(obs)

    tokens = extract_tokens_from_response_text(result["text"])
    if result["status_code"] == 200 and tokens.get("access_token"):
        role.access_token = tokens.get("access_token")
        role.refresh_token = tokens.get("refresh_token")
        role.token_type = tokens.get("token_type") or "Bearer"
        role.status = "authenticated"
    else:
        role.status = "failed"

    role.last_auth_status = result["status_code"]

    db.commit()
    db.refresh(obs)
    db.refresh(role)

    return {
        "role_name": role.role_name,
        "status": role.status,
        "http_status": result["status_code"],
        "has_access_token": bool(role.access_token),
        "body_preview": result["text"][:300]
    }


@router.get("/{session_id}")
def list_roles(session_id: int, db: Session = Depends(get_db)):
    items = db.query(RoleCredential).filter(RoleCredential.session_id == session_id).all()
    return items