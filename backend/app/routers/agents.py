from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession
from ..services.agent_registry_service import (
    build_session_agent_plan,
    get_agent_catalog,
    get_logical_agent_catalog,
)

router = APIRouter(prefix="/agents", tags=["agents"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/catalog")
def get_agents_catalog():
    catalog = get_agent_catalog()
    logical_catalog = get_logical_agent_catalog()
    return {
        "agents_total": len(catalog),
        "agents": catalog,
        "logical_agents_total": len(logical_catalog),
        "logical_agents": logical_catalog,
    }


@router.get("/session/{session_id}/plan")
def get_session_agent_plan(session_id: int, db: Session = Depends(get_db)):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")
    return build_session_agent_plan(session_obj)
