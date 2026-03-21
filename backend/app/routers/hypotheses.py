import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, Hypothesis
from ..schemas import GenerateHypothesesRequest
from ..services.hypothesis_service import generate_hypotheses_for_session

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/generate")
def generate_hypotheses(payload: GenerateHypothesesRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    generated = generate_hypotheses_for_session(db, payload.session_id)

    saved = []
    for item in generated:
        h = Hypothesis(
            session_id=payload.session_id,
            agent_name=item["agent_name"],
            hypothesis_type=item["hypothesis_type"],
            target_endpoint=item["target_endpoint"],
            http_method=item["http_method"],
            description=item["description"],
            payload_json=json.dumps(item["payload"], ensure_ascii=False),
            confidence=item["confidence"],
            estimated_cost=item["estimated_cost"],
            false_positive_risk=item["false_positive_risk"],
            coverage_gain=item["coverage_gain"],
            evidence_readiness=item["evidence_readiness"],
            status="candidate"
        )
        db.add(h)
        saved.append(h)

    db.commit()

    result = []
    for h in saved:
        db.refresh(h)
        result.append({
            "id": h.id,
            "type": h.hypothesis_type,
            "target_endpoint": h.target_endpoint,
            "http_method": h.http_method,
            "description": h.description,
            "status": h.status
        })

    return {
        "session_id": payload.session_id,
        "generated_count": len(result),
        "hypotheses": result
    }


@router.get("/{session_id}")
def list_hypotheses(session_id: int, db: Session = Depends(get_db)):
    items = db.query(Hypothesis).filter(Hypothesis.session_id == session_id).all()
    return items