from __future__ import annotations

import json

from sqlalchemy.orm import Session

from ..models import (
    TestSession,
    Observation,
    Hypothesis,
    JudgeDecision,
    Finding,
    RoleCredential,
    AgentStrategyMemory,
    AgentJudgeFeedback,
)
from .agent_registry_service import normalize_enabled_agents
from .judge_trace_service import classify_dify_issue
from .report_service import build_session_report, extract_runtime_summaries


def create_campaign_session(
    db: Session,
    *,
    target_name: str,
    target_url: str,
    user_prompt: str | None,
    budget_requests_total: int | None,
    budget_time_total: int | None,
    max_rounds: int | None,
    allowed_test_classes: list[str] | None,
    enabled_agents: list[str] | None = None,
):
    normalized_agents = normalize_enabled_agents(enabled_agents)
    strategy_payload = {"enabled_agents": normalized_agents, "orchestration_mode": "agentic"}
    if user_prompt:
        strategy_payload["user_prompt"] = user_prompt
    session_obj = TestSession(
        target_name=target_name,
        target_url=target_url,
        status="created",
        budget_requests_total=budget_requests_total,
        budget_requests_used=0,
        budget_time_total=budget_time_total,
        budget_time_used=0,
        max_rounds=max_rounds,
        rounds_completed=0,
        allowed_test_classes_json=json.dumps(allowed_test_classes or [], ensure_ascii=False),
        last_strategy_json=json.dumps(strategy_payload, ensure_ascii=False),
    )
    db.add(session_obj)
    db.commit()
    db.refresh(session_obj)
    return session_obj


def collect_session_metrics(db: Session, session_id: int):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    observation_rows = db.query(Observation).filter(Observation.session_id == session_id).all()
    finding_rows = db.query(Finding).filter(Finding.session_id == session_id).all()

    observations = len(observation_rows)
    hypotheses = db.query(Hypothesis).filter(Hypothesis.session_id == session_id).count()
    judge_decision_rows = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == session_id
    ).all()

    findings_total = len(finding_rows)
    bola_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bola",
    ).count()
    bopla_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bopla",
    ).count()
    auth_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type.in_(["possible_authentication_bypass", "auth_boundary_signal"]),
    ).count()
    auth_boundary_signals = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "auth_boundary_signal",
    ).count()
    confirmed_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "confirmed",
    ).count()
    confirmed_bola = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bola",
        Finding.verification_status == "confirmed",
    ).count()
    confirmed_bopla = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "possible_bopla",
        Finding.verification_status == "confirmed",
    ).count()
    confirmed_auth_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type.in_(["possible_authentication_bypass", "auth_boundary_signal"]),
        Finding.verification_status == "confirmed",
    ).count()
    confirmed_auth_boundary_signals = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.finding_type == "auth_boundary_signal",
        Finding.verification_status == "confirmed",
    ).count()
    candidate_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "candidate",
    ).count()
    rejected_findings = db.query(Finding).filter(
        Finding.session_id == session_id,
        Finding.verification_status == "rejected",
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
    runtime_summaries = extract_runtime_summaries(
        session_obj,
        observations=observation_rows,
        findings=finding_rows,
    )
    exploitation_queue_summary = runtime_summaries["exploitation_queue_summary"]
    terminal_reverification_summary = runtime_summaries["terminal_reverification_summary"]

    return {
        "session_id": session_id,
        "metrics": {
            "observations": observations,
            "hypotheses_generated": hypotheses,
            "judge_decisions": len(judge_decision_rows),
            "dify_direct_matches": len(
                [
                    d for d in judge_decision_rows
                    if (d.resolution_mode or "") in {"dify_direct_match", "unified_direct_match"}
                ]
            ),
            "dify_recoveries": len(
                [
                    d for d in judge_decision_rows
                    if (
                        ((d.resolution_mode or "").startswith("dify_") or (d.resolution_mode or "").startswith("unified_"))
                        and "recovery" in (d.resolution_mode or "")
                    )
                ]
            ),
            "dify_fallbacks": len(
                [
                    d for d in judge_decision_rows
                    if (d.resolution_mode or "") in {
                        "dify_exception_fallback",
                        "dify_rule_based_fallback",
                        "unified_no_dify_fallback",
                        "unified_invalid_selection_fallback",
                    }
                ]
            ),
            "rule_based_overrides": len(
                [
                    d for d in judge_decision_rows
                    if (d.resolution_mode or "") == "unified_rule_based_override"
                ]
            ),
            "findings_total": findings_total,
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
            "coverage_summary": runtime_summaries["coverage_summary"],
            "exploitation_queue_summary": exploitation_queue_summary,
            "exploitation_queue_promoted_total": int(
                exploitation_queue_summary.get("promoted_total", 0) or 0
            ),
            "terminal_reverification_summary": terminal_reverification_summary,
            "terminal_reverification_attempted": int(
                terminal_reverification_summary.get("attempted", 0) or 0
            ),
            "terminal_reverification_completed": int(
                terminal_reverification_summary.get("completed", 0) or 0
            ),
            "rounds_completed": getattr(session_obj, "rounds_completed", 0),
            "max_rounds": getattr(session_obj, "max_rounds", None),
            "budget_requests_used": getattr(session_obj, "budget_requests_used", 0),
            "budget_requests_total": getattr(session_obj, "budget_requests_total", None),
            "session_status": getattr(session_obj, "status", None),
            "stop_reason": getattr(session_obj, "stop_reason", None),
        },
    }


def collect_session_report(db: Session, session_id: int):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
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
