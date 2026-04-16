from __future__ import annotations

import json
from typing import Any

from ..models import (
    AgentJudgeFeedback,
    AgentStrategyMemory,
    Finding,
    Hypothesis,
    JudgeDecision,
    Observation,
    RoleCredential,
    TestSession,
)
from .agent_registry_service import build_session_agent_plan, get_logical_agent_name
from .agentic_cycle_service import (
    choose_agentic_candidate,
    ensure_agentic_state,
    extract_prompt_focus,
    get_candidate_key,
    get_user_prompt_from_strategy,
)
from .agentic_orchestrator_service import build_orchestrator_plan
from .campaign_run_service import create_campaign_session
from .report_service import build_final_session_report
from .session_state_service import can_continue_session
from .session_state_service import deserialize_strategy_state


def _safe_json_load(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _safe_json_list(value: str | None) -> list[Any]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    return parsed if isinstance(parsed, list) else []


def _load_session_bundle(db, session_id: int) -> dict[str, Any] | None:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        return None

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

    return {
        "session": session_obj,
        "roles": roles,
        "findings": findings,
        "judge_decisions": judge_decisions,
        "observations": observations,
        "hypotheses": hypotheses,
        "agent_memory_rows": agent_memory_rows,
        "agent_judge_feedback_rows": agent_judge_feedback_rows,
    }


def start_agentic_session(
    db,
    *,
    target_name: str,
    target_url: str,
    user_prompt: str,
    budget_requests_total: int | None,
    budget_time_total: int | None,
    max_rounds: int | None,
    allowed_test_classes: list[str] | None,
    enabled_agents: list[str] | None,
    strategy_config: dict[str, Any] | None,
) -> dict[str, Any]:
    session_obj = create_campaign_session(
        db,
        target_name=target_name,
        target_url=target_url,
        user_prompt=user_prompt,
        budget_requests_total=budget_requests_total,
        budget_time_total=budget_time_total,
        max_rounds=max_rounds,
        allowed_test_classes=allowed_test_classes,
        enabled_agents=enabled_agents,
    )
    if strategy_config:
        strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
        strategy_state["strategy_config"] = dict(strategy_config)
        session_obj.last_strategy_json = json.dumps(strategy_state, ensure_ascii=False)
        db.commit()
        db.refresh(session_obj)

    return build_agentic_session_bootstrap(db, session_obj.id)


def build_agentic_session_bootstrap(db, session_id: int) -> dict[str, Any]:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return {}

    session_obj = bundle["session"]
    strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    user_prompt = get_user_prompt_from_strategy(strategy_state)
    allowed_test_classes = _safe_json_list(getattr(session_obj, "allowed_test_classes_json", None))

    return {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
            "status": session_obj.status,
            "max_rounds": session_obj.max_rounds,
            "budget_requests_total": session_obj.budget_requests_total,
            "budget_time_total": session_obj.budget_time_total,
            "allowed_test_classes": allowed_test_classes,
        },
        "agentic": {
            "user_prompt": user_prompt,
            "prompt_focus": extract_prompt_focus(user_prompt, allowed_test_classes),
            "strategy_config": strategy_state.get("strategy_config", {}),
            "agent_plan": build_session_agent_plan(session_obj),
            "orchestrator_plan": build_orchestrator_plan(session_obj),
        },
        "next_endpoints": {
            "session_context": f"/agentic/session/{session_obj.id}/context",
            "orchestrator_plan": f"/agentic/session/{session_obj.id}/orchestrator-plan",
            "router_plan": f"/agentic/session/{session_obj.id}/router-plan",
            "judge_state": f"/agentic/session/{session_obj.id}/judge-state",
            "loop_state": f"/agentic/session/{session_obj.id}/loop-state",
            "report_package": f"/agentic/session/{session_obj.id}/report-package",
            "run_round": f"/agentic/session/{session_obj.id}/run-round",
            "bola_worker_tasks": f"/agentic/session/{session_obj.id}/worker-tasks/bola",
            "tool_execute": "/agentic/tools/execute",
            "campaign_step": "/campaign/step",
        },
    }


def build_agentic_router_plan(db, session_id: int) -> dict[str, Any] | None:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return None

    session_obj = bundle["session"]
    strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    user_prompt = get_user_prompt_from_strategy(strategy_state)
    allowed_test_classes = _safe_json_list(getattr(session_obj, "allowed_test_classes_json", None))

    from .hypothesis_service import generate_hypotheses_runtime_for_session

    runtime = generate_hypotheses_runtime_for_session(db, session_id)
    hypotheses = runtime.get("hypotheses", [])
    selected_task = None
    selected_trace = None

    if hypotheses:
        transient_candidates = []
        for index, item in enumerate(hypotheses, start=1):
            transient_candidates.append(
                type(
                    "TransientHypothesis",
                    (),
                    {
                        "id": index,
                        "agent_name": item.get("agent_name"),
                        "hypothesis_type": item.get("hypothesis_type"),
                        "target_endpoint": item.get("target_endpoint"),
                        "http_method": item.get("http_method"),
                        "description": item.get("description"),
                        "confidence": item.get("confidence"),
                        "estimated_cost": item.get("estimated_cost"),
                        "false_positive_risk": item.get("false_positive_risk"),
                        "coverage_gain": item.get("coverage_gain"),
                        "evidence_readiness": item.get("evidence_readiness"),
                        "payload_json": json.dumps(
                            {
                                **(item.get("payload") or {}),
                                "candidate_key": item.get("candidate_key"),
                            },
                            ensure_ascii=False,
                        ),
                    },
                )()
            )

        selected_task, selected_trace = choose_agentic_candidate(
            transient_candidates,
            user_prompt=user_prompt,
            allowed_test_classes=allowed_test_classes,
            strategy_state=strategy_state,
        )

    tasks = []
    for item in hypotheses[:20]:
        logical_agent_name = get_logical_agent_name(item.get("agent_name"))
        tasks.append(
            {
                "candidate_key": item.get("candidate_key"),
                "logical_agent": logical_agent_name,
                "worker_agent": item.get("agent_name"),
                "task_type": item.get("hypothesis_type"),
                "goal": item.get("description"),
                "target": {
                    "endpoint": item.get("target_endpoint"),
                    "method": item.get("http_method"),
                },
                "scoring": {
                    "confidence": item.get("confidence"),
                    "coverage_gain": item.get("coverage_gain"),
                    "evidence_readiness": item.get("evidence_readiness"),
                    "false_positive_risk": item.get("false_positive_risk"),
                    "estimated_cost": item.get("estimated_cost"),
                },
                "inputs": item.get("payload") or {},
            }
        )

    return {
        "session_id": session_id,
        "user_prompt": user_prompt,
        "prompt_focus": extract_prompt_focus(user_prompt, allowed_test_classes),
        "agent_plan": build_session_agent_plan(session_obj),
        "orchestrator_plan": build_orchestrator_plan(session_obj),
        "router_selection": (
            {
                **(selected_trace or {}),
                "selected_candidate_key": get_candidate_key(selected_task) if selected_task else None,
                "selected_task_type": getattr(selected_task, "hypothesis_type", None) if selected_task else None,
            }
            if (selected_task or selected_trace)
            else None
        ),
        "tasks_total": len(tasks),
        "tasks": tasks,
    }


def build_agentic_orchestrator_plan(db, session_id: int) -> dict[str, Any] | None:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return None
    return build_orchestrator_plan(bundle["session"])


def build_agentic_judge_state(db, session_id: int) -> dict[str, Any] | None:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return None

    session_obj = bundle["session"]
    strategy_state = ensure_agentic_state(
        deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    )
    findings = bundle["findings"]
    confirmed_findings = [
        item for item in findings if getattr(item, "verification_status", None) == "confirmed"
    ]
    candidate_findings = [
        item for item in findings if getattr(item, "verification_status", None) == "candidate"
    ]

    return {
        "session_id": session_id,
        "judge_loop": {
            "state": strategy_state.get("agentic_state", {}),
            "decisions_total": len(bundle["judge_decisions"]),
            "confirmed_findings_total": len(confirmed_findings),
            "candidate_findings_total": len(candidate_findings),
        },
        "confirmed_findings": [
            {
                "id": item.id,
                "type": item.finding_type,
                "title": item.title,
                "endpoint": item.endpoint,
                "severity": item.severity,
            }
            for item in confirmed_findings[:20]
        ],
        "candidate_findings": [
            {
                "id": item.id,
                "type": item.finding_type,
                "title": item.title,
                "endpoint": item.endpoint,
                "severity": item.severity,
            }
            for item in candidate_findings[:20]
        ],
    }


def build_agentic_loop_state(db, session_id: int) -> dict[str, Any] | None:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return None

    session_obj = bundle["session"]
    strategy_state = ensure_agentic_state(
        deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    )
    can_continue, stop_reason = can_continue_session(session_obj)
    confirmed_findings = [
        item for item in bundle["findings"] if getattr(item, "verification_status", None) == "confirmed"
    ]
    candidate_findings = [
        item for item in bundle["findings"] if getattr(item, "verification_status", None) == "candidate"
    ]
    effective_stop_reason = getattr(session_obj, "stop_reason", None) or stop_reason
    should_continue = bool(can_continue and not effective_stop_reason and getattr(session_obj, "status", None) != "stopped")

    return {
        "session_id": session_id,
        "should_continue": should_continue,
        "stop_reason": effective_stop_reason,
        "session_state": {
            "status": session_obj.status,
            "rounds_completed": session_obj.rounds_completed,
            "max_rounds": session_obj.max_rounds,
            "budget_requests_used": session_obj.budget_requests_used,
            "budget_requests_total": session_obj.budget_requests_total,
            "budget_time_used": session_obj.budget_time_used,
            "budget_time_total": session_obj.budget_time_total,
        },
        "judge_loop": {
            "decisions_total": len(bundle["judge_decisions"]),
            "confirmed_findings_total": len(confirmed_findings),
            "candidate_findings_total": len(candidate_findings),
            "state": strategy_state.get("agentic_state", {}),
        },
        "next_action": "run_round" if should_continue else "report",
    }


def build_agentic_report_package(db, session_id: int) -> dict[str, Any] | None:
    bundle = _load_session_bundle(db, session_id)
    if not bundle:
        return None

    final_report = build_final_session_report(
        session_obj=bundle["session"],
        roles=bundle["roles"],
        findings=bundle["findings"],
        judge_decisions=bundle["judge_decisions"],
        observations=bundle["observations"],
        hypotheses=bundle["hypotheses"],
        agent_memory_rows=bundle["agent_memory_rows"],
        agent_judge_feedback_rows=bundle["agent_judge_feedback_rows"],
    )

    confirmed_top_findings = [
        item
        for item in (final_report.get("top_findings") or [])
        if item.get("verification_status") == "confirmed"
    ]

    return {
        "session_id": session_id,
        "target": {
            "name": bundle["session"].target_name,
            "url": bundle["session"].target_url,
        },
        "report_inputs": {
            "executive_summary": final_report.get("executive_summary", {}),
            "risk_summary": final_report.get("risk_summary", {}),
            "key_conclusion": final_report.get("key_conclusion", {}),
            "confirmed_top_findings": confirmed_top_findings,
        },
        "final_report": final_report,
    }
