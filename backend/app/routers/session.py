import json

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import SessionLocal
from ..models import TestSession
from ..schemas import CreateSessionRequest, SessionResponse
from ..services.agent_registry_service import normalize_enabled_agents

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/create")
def create_session(payload: CreateSessionRequest, db: Session = Depends(get_db)):
    enabled_agents = normalize_enabled_agents(payload.enabled_agents)
    strategy_payload = dict(payload.strategy_config or {})
    strategy_payload["enabled_agents"] = enabled_agents
    session = TestSession(
        target_name=payload.target_name,
        target_url=payload.target_url,
        status="created",
        budget_requests_total=payload.budget_requests_total,
        budget_requests_used=0,
        budget_time_total=payload.budget_time_total,
        budget_time_used=0,
        max_rounds=payload.max_rounds,
        rounds_completed=0,
        allowed_test_classes_json=json.dumps(payload.allowed_test_classes or [], ensure_ascii=False),
        last_strategy_json=json.dumps(strategy_payload, ensure_ascii=False),
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return SessionResponse.model_validate(session)

@router.get("/{session_id}")
def get_session(session_id: int, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == session_id).first()
    return SessionResponse.model_validate(session)
