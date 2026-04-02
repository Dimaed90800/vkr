from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Observation, Hypothesis, JudgeDecision, Finding, TestSession, AgentStrategyMemory, AgentJudgeFeedback
from ..services.agent_judge_feedback_service import build_agent_judge_feedback_summary
from ..services.judge_trace_service import classify_dify_issue
from ..services.report_service import (
    build_agent_activity_summary,
    build_agent_effectiveness_summary,
    build_agent_learning_summary,
    build_logical_agent_activity_summary,
    build_logical_agent_effectiveness_summary,
    build_logical_agent_judge_feedback_summary,
    build_logical_agent_learning_summary,
)

router = APIRouter(prefix="/metrics", tags=["metrics"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/session/{session_id}")
def get_session_metrics(session_id: int, db: Session = Depends(get_db)):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()

    observations = db.query(Observation).filter(
        Observation.session_id == session_id
    ).count()

    hypotheses = db.query(Hypothesis).filter(
        Hypothesis.session_id == session_id
    ).count()

    decisions = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).count()
    judge_decision_rows = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).all()
    hypothesis_rows = db.query(Hypothesis).filter(
        Hypothesis.session_id == session_id
    ).all()
    agent_memory_rows = db.query(AgentStrategyMemory).filter(
        AgentStrategyMemory.session_id == session_id
    ).all()
    agent_judge_feedback_rows = db.query(AgentJudgeFeedback).filter(
        AgentJudgeFeedback.session_id == session_id
    ).all()

    findings = db.query(Finding).filter(
        Finding.session_id == session_id
    ).count()

    bola_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bola"
    ).count()

    bopla_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bopla"
    ).count()
    auth_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type.in_(["possible_authentication_bypass", "auth_boundary_signal"])
    ).count()
    auth_boundary_signals = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "auth_boundary_signal"
    ).count()

    confirmed_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "confirmed"
    ).count()

    confirmed_bola = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bola",
        Finding.verification_status == "confirmed"
    ).count()

    confirmed_bopla = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bopla",
        Finding.verification_status == "confirmed"
    ).count()
    confirmed_auth_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type.in_(["possible_authentication_bypass", "auth_boundary_signal"]),
        Finding.verification_status == "confirmed"
    ).count()
    confirmed_auth_boundary_signals = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "auth_boundary_signal",
        Finding.verification_status == "confirmed"
    ).count()

    candidate_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "candidate"
    ).count()

    rejected_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "rejected"
    ).count()

    dify_issue_counts = {
        "provider_credit_limit": 0,
        "empty_outputs": 0,
        "invalid_candidate_key": 0,
        "provider_timeout": 0,
        "provider_error": 0,
        "exception_fallback_other": 0,
    }
    for decision in judge_decision_rows:
        issue_type = classify_dify_issue(
            getattr(decision, "resolution_mode", None),
            getattr(decision, "raw_reason", None),
            getattr(decision, "reasoning_summary", None),
        )
        if issue_type in dify_issue_counts:
            dify_issue_counts[issue_type] += 1

    return {
        "session_id": session_id,
        "metrics": {
            "observations": observations,
            "hypotheses_generated": hypotheses,
            "judge_decisions": decisions,
            "dify_direct_matches": len([
                d for d in judge_decision_rows
                if (d.resolution_mode or "") in {"dify_direct_match", "unified_direct_match"}
            ]),
            "dify_recoveries": len([
                d for d in judge_decision_rows
                if (
                    ((d.resolution_mode or "").startswith("dify_") or (d.resolution_mode or "").startswith("unified_"))
                    and "recovery" in (d.resolution_mode or "")
                )
            ]),
            "dify_fallbacks": len([
                d for d in judge_decision_rows
                if (d.resolution_mode or "") in {
                    "dify_exception_fallback",
                    "dify_rule_based_fallback",
                    "unified_no_dify_fallback",
                    "unified_invalid_selection_fallback",
                }
            ]),
            "rule_based_overrides": len([
                d for d in judge_decision_rows
                if (d.resolution_mode or "") == "unified_rule_based_override"
            ]),
            "findings_total": findings,
            "bola_findings": bola_findings,
            "bopla_findings": bopla_findings,
            "auth_findings": auth_findings,
            "auth_boundary_signals": auth_boundary_signals,
            "confirmed_findings": confirmed_findings,
            "confirmed_bola": confirmed_bola,
            "confirmed_bopla": confirmed_bopla,
            "confirmed_auth_findings": confirmed_auth_findings,
            "confirmed_auth_boundary_signals": confirmed_auth_boundary_signals,
            "candidate_findings": candidate_findings,
            "rejected_findings": rejected_findings,
            "dify_issue_breakdown": dify_issue_counts,
            "rounds_completed": getattr(session_obj, "rounds_completed", 0),
            "max_rounds": getattr(session_obj, "max_rounds", None),
            "budget_requests_used": getattr(session_obj, "budget_requests_used", 0),
            "budget_requests_total": getattr(session_obj, "budget_requests_total", None),
            "session_status": getattr(session_obj, "status", None),
            "stop_reason": getattr(session_obj, "stop_reason", None),
            "agent_activity_summary": build_agent_activity_summary(hypothesis_rows, judge_decision_rows),
            "logical_agent_activity_summary": build_logical_agent_activity_summary(
                hypothesis_rows,
                judge_decision_rows,
            ),
            "agent_learning_summary": build_agent_learning_summary(agent_memory_rows),
            "logical_agent_learning_summary": build_logical_agent_learning_summary(agent_memory_rows),
            "agent_judge_feedback_summary": build_agent_judge_feedback_summary(agent_judge_feedback_rows),
            "logical_agent_judge_feedback_summary": build_logical_agent_judge_feedback_summary(
                agent_judge_feedback_rows
            ),
            "agent_effectiveness_summary": build_agent_effectiveness_summary(
                hypothesis_rows,
                judge_decision_rows,
                db.query(Finding).filter(Finding.session_id == session_id).all(),
                memory_rows=agent_memory_rows,
            ),
            "logical_agent_effectiveness_summary": build_logical_agent_effectiveness_summary(
                hypothesis_rows,
                judge_decision_rows,
                db.query(Finding).filter(Finding.session_id == session_id).all(),
                memory_rows=agent_memory_rows,
            ),
        }
    }


@router.get("/session/{session_id}/agents")
def get_session_agent_metrics(session_id: int, db: Session = Depends(get_db)):
    hypotheses = db.query(Hypothesis).filter(
        Hypothesis.session_id == session_id
    ).all()
    judge_decisions = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).all()
    findings = db.query(Finding).filter(
        Finding.session_id == session_id
    ).all()
    memory_rows = db.query(AgentStrategyMemory).filter(
        AgentStrategyMemory.session_id == session_id
    ).all()
    judge_feedback_rows = db.query(AgentJudgeFeedback).filter(
        AgentJudgeFeedback.session_id == session_id
    ).all()

    return {
        "session_id": session_id,
        "agent_activity_summary": build_agent_activity_summary(hypotheses, judge_decisions),
        "logical_agent_activity_summary": build_logical_agent_activity_summary(hypotheses, judge_decisions),
        "agent_learning_summary": build_agent_learning_summary(memory_rows),
        "logical_agent_learning_summary": build_logical_agent_learning_summary(memory_rows),
        "agent_judge_feedback_summary": build_agent_judge_feedback_summary(judge_feedback_rows),
        "logical_agent_judge_feedback_summary": build_logical_agent_judge_feedback_summary(judge_feedback_rows),
        "agent_effectiveness_summary": build_agent_effectiveness_summary(
            hypotheses,
            judge_decisions,
            findings,
            memory_rows=memory_rows,
        ),
        "logical_agent_effectiveness_summary": build_logical_agent_effectiveness_summary(
            hypotheses,
            judge_decisions,
            findings,
            memory_rows=memory_rows,
        ),
    }


@router.get("/session/{session_id}/judge-comparison")
def compare_judges(session_id: int, db: Session = Depends(get_db)):
    decisions = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).all()

    dify = [d for d in decisions if getattr(d, "judge_mode", None) == "dify"]
    rule = [d for d in decisions if getattr(d, "judge_mode", "rule_based") == "rule_based"]
    unified = [d for d in decisions if getattr(d, "judge_mode", None) == "unified"]

    return {
        "session_id": session_id,
        "comparison": {
            "total_decisions": len(decisions),
            "dify_decisions": len(dify),
            "rule_based_decisions": len(rule),
            "unified_decisions": len(unified),
            "dify_direct_matches": len([d for d in dify if (d.resolution_mode or "") == "dify_direct_match"]),
            "dify_recoveries": len([d for d in dify if (d.resolution_mode or "").startswith("dify_") and "recovery" in (d.resolution_mode or "")]),
            "dify_fallbacks": len([d for d in dify if (d.resolution_mode or "") in {"dify_exception_fallback", "dify_rule_based_fallback"}]),
            "unified_direct_matches": len([d for d in unified if (d.resolution_mode or "") == "unified_direct_match"]),
            "unified_recoveries": len([d for d in unified if (d.resolution_mode or "").startswith("unified_") and "recovery" in (d.resolution_mode or "")]),
            "unified_fallbacks": len([
                d for d in unified
                if (d.resolution_mode or "") in {
                    "unified_no_dify_fallback",
                    "unified_invalid_selection_fallback",
                }
            ]),
            "unified_rule_based_overrides": len([
                d for d in unified
                if (d.resolution_mode or "") == "unified_rule_based_override"
            ]),
            "avg_dify_score": (
                sum(float(d.priority_score or 0) for d in dify) / len(dify)
                if dify else 0
            ),
            "avg_rule_score": (
                sum(float(d.priority_score or 0) for d in rule) / len(rule)
                if rule else 0
            ),
            "avg_unified_score": (
                sum(float(d.priority_score or 0) for d in unified) / len(unified)
                if unified else 0
            ),
        }
    }
