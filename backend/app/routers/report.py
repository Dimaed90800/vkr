from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import (
    TestSession,
    RoleCredential,
    Finding,
    JudgeDecision,
    Observation,
    Hypothesis,
    AgentStrategyMemory,
    AgentJudgeFeedback,
)
from ..services.report_service import (
    build_session_report,
    build_session_summary_text,
    build_session_executive_summary,
    build_final_session_report,
    build_session_markdown_report,
    build_agent_activity_summary,
    build_logical_agent_activity_summary,
)
from ..services.llm_report_service import build_session_llm_report
from ..services.replay_service import replay_unified_for_session

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _load_session_bundle(db: Session, session_id: int):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")

    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == session_id
    ).order_by(RoleCredential.id.asc()).all()

    findings = db.query(Finding).filter(
        Finding.session_id == session_id
    ).order_by(Finding.id.asc()).all()

    judge_decisions = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).order_by(JudgeDecision.round_no.asc()).all()

    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).order_by(Observation.id.asc()).all()

    hypotheses = db.query(Hypothesis).filter(
        Hypothesis.session_id == session_id
    ).order_by(Hypothesis.id.asc()).all()

    agent_memory_rows = db.query(AgentStrategyMemory).filter(
        AgentStrategyMemory.session_id == session_id
    ).order_by(AgentStrategyMemory.agent_name.asc(), AgentStrategyMemory.id.asc()).all()
    agent_judge_feedback_rows = db.query(AgentJudgeFeedback).filter(
        AgentJudgeFeedback.session_id == session_id
    ).order_by(AgentJudgeFeedback.round_no.asc(), AgentJudgeFeedback.id.asc()).all()

    return (
        session_obj,
        roles,
        findings,
        judge_decisions,
        observations,
        hypotheses,
        agent_memory_rows,
        agent_judge_feedback_rows,
    )


@router.get("/session/{session_id}")
def get_session_report(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return build_session_report(
        session_obj=session_obj,
        roles=roles,
        findings=findings,
        judge_decisions=judge_decisions,
        observations=observations,
        hypotheses=hypotheses,
        agent_memory_rows=agent_memory_rows,
        agent_judge_feedback_rows=agent_judge_feedback_rows,
    )


@router.get("/session/{session_id}/summary-text")
def get_session_summary_text(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "summary_text": build_session_summary_text(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
        )
    }


@router.get("/session/{session_id}/executive-summary")
def get_session_executive_summary(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "executive_summary": build_session_executive_summary(
            session_obj=session_obj,
            findings=findings,
        )
    }


@router.get("/session/{session_id}/final")
def get_session_final_report(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "final_report": build_final_session_report(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_memory_rows=agent_memory_rows,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
        )
    }


@router.get("/session/{session_id}/markdown")
def get_session_markdown_report(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "markdown_report": build_session_markdown_report(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_memory_rows=agent_memory_rows,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
        )
    }


@router.get("/session/{session_id}/llm-report")
def get_session_llm_report(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "llm_report": build_session_llm_report(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_memory_rows=agent_memory_rows,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
        ),
    }


@router.get("/session/{session_id}/agent-summary")
def get_session_agent_summary(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "logical_agent_activity_summary": build_logical_agent_activity_summary(
            hypotheses=hypotheses,
            judge_decisions=judge_decisions,
        ),
        "internal_agent_activity_summary": build_agent_activity_summary(
            hypotheses=hypotheses,
            judge_decisions=judge_decisions,
        ),
    }


@router.get("/session/{session_id}/replay-unified")
def replay_unified_session(session_id: int, db: Session = Depends(get_db)):
    session_obj, roles, findings, judge_decisions, observations, hypotheses, agent_memory_rows, agent_judge_feedback_rows = _load_session_bundle(db, session_id)

    return {
        "session_id": session_id,
        "replay": replay_unified_for_session(
            session_obj=session_obj,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
        ),
    }
