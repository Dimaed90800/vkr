from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Observation, Hypothesis, JudgeDecision, Finding

router = APIRouter(prefix="/metrics", tags=["metrics"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/session/{session_id}")
def get_session_metrics(session_id: int, db: Session = Depends(get_db)):
    observations = db.query(Observation).filter(Observation.session_id == session_id).count()
    hypotheses = db.query(Hypothesis).filter(Hypothesis.session_id == session_id).count()
    decisions = db.query(JudgeDecision).filter(JudgeDecision.session_id == session_id).count()
    findings = db.query(Finding).filter(Finding.session_id == session_id).count()

    bola_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bola"
    ).count()

    bopla_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bopla"
    ).count()

    return {
        "session_id": session_id,
        "metrics": {
            "observations": observations,
            "hypotheses_generated": hypotheses,
            "judge_decisions": decisions,
            "findings_total": findings,
            "bola_findings": bola_findings,
            "bopla_findings": bopla_findings,
        }
    }


@router.get("/session/{session_id}/judge-comparison")
def compare_judges(session_id: int, db: Session = Depends(get_db)):
    decisions = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).all()

    dify = [d for d in decisions if getattr(d, "judge_mode", None) == "dify"]
    rule = [d for d in decisions if getattr(d, "judge_mode", "rule_based") == "rule_based"]

    return {
        "session_id": session_id,
        "comparison": {
            "total_decisions": len(decisions),
            "dify_decisions": len(dify),
            "rule_based_decisions": len(rule),
            "avg_dify_score": sum(float(d.priority_score or 0) for d in dify) / len(dify) if dify else 0,
            "avg_rule_score": sum(float(d.priority_score or 0) for d in rule) / len(rule) if rule else 0,
        }
    }