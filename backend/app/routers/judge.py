import json
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import func

from ..db import SessionLocal
from ..models import TestSession, Hypothesis, JudgeDecision
from ..schemas import JudgeSelectRequest
from ..services.judge_service import (
    calculate_priority_score,
    classify_decision_type,
    build_reasoning_summary,
    build_required_evidence,
    build_stop_condition,
)

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/select-next")
def select_next(payload: JudgeSelectRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    candidates = db.query(Hypothesis).filter(
        Hypothesis.session_id == payload.session_id,
        Hypothesis.status == "candidate"
    ).all()

    if not candidates:
        raise HTTPException(status_code=400, detail="No candidate hypotheses available")

    scored = []
    for h in candidates:
        score = calculate_priority_score(h)
        scored.append((h, score))

    scored.sort(key=lambda x: x[1], reverse=True)
    selected, score = scored[0]

    selected.status = "selected"

    round_no = (
        db.query(func.count(JudgeDecision.id))
        .filter(JudgeDecision.session_id == payload.session_id)
        .scalar()
    ) + 1

    decision = JudgeDecision(
        session_id=payload.session_id,
        round_no=round_no,
        selected_hypothesis_id=selected.id,
        decision_type=classify_decision_type(selected.hypothesis_type),
        priority_score=score,
        reasoning_summary=build_reasoning_summary(selected, score),
        required_evidence_json=json.dumps(build_required_evidence(selected), ensure_ascii=False),
        stop_condition_json=json.dumps(build_stop_condition(selected), ensure_ascii=False)
    )

    db.add(decision)
    db.commit()
    db.refresh(decision)

    return {
        "session_id": payload.session_id,
        "round_no": decision.round_no,
        "selected_hypothesis": {
            "id": selected.id,
            "type": selected.hypothesis_type,
            "target_endpoint": selected.target_endpoint,
            "http_method": selected.http_method,
            "description": selected.description
        },
        "decision_type": decision.decision_type,
        "priority_score": decision.priority_score,
        "reasoning_summary": decision.reasoning_summary
    }


@router.get("/{session_id}")
def list_decisions(session_id: int, db: Session = Depends(get_db)):
    items = db.query(JudgeDecision).filter(JudgeDecision.session_id == session_id).all()
    return items