from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..db import SessionLocal
from ..models import TestSession
from ..schemas import CreateSessionRequest

router = APIRouter()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/create")
def create_session(payload: CreateSessionRequest, db: Session = Depends(get_db)):
    session = TestSession(
        target_name=payload.target_name,
        target_url=payload.target_url,
        status="created"
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return {
        "id": session.id,
        "target_name": session.target_name,
        "target_url": session.target_url,
        "status": session.status
    }

@router.get("/{session_id}")
def get_session(session_id: int, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == session_id).first()
    return session