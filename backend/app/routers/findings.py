from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Finding

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/{session_id}")
def list_findings(session_id: int, db: Session = Depends(get_db)):
    return db.query(Finding).filter(Finding.session_id == session_id).all()