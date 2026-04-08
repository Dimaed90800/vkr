from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, Hypothesis, JudgeDecision, Finding
from ..schemas import CampaignStepRequest, CampaignRunRequest
from ..services.campaign_execution_service import execute_hypothesis
from ..services.campaign_run_service import (
    create_campaign_session,
    collect_session_metrics,
    collect_session_report,
)
from ..services.dify_service import call_dify_judge
from ..services.evidence_service import maybe_create_finding_from_comparison
from ..services.evidence_service import maybe_create_auth_finding_from_execution
from ..services.agent_judge_feedback_service import record_judge_feedback
from ..services.hypothesis_service import generate_hypotheses_runtime_for_session
from ..services.agent_memory_service import record_agent_result
from ..services.judge_service import (
    calculate_dynamic_priority,
    calculate_priority_score,
    classify_decision_type,
    build_reasoning_summary,
    build_required_evidence,
    build_stop_condition,
    serialize_hypothesis,
)
from ..services.unified_judge_service import choose_unified_candidate
from ..services.session_state_service import (
    can_continue_session,
    deserialize_strategy_state,
    register_requests,
    register_round,
    update_strategy_state,
)
from ..services.terminal_reverification_service import run_terminal_reverification_pass

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _save_generated_hypotheses(db: Session, session_id: int, generated: list[dict]):
    saved_candidates = []
    for item in generated:
        h = Hypothesis(
            session_id=session_id,
            agent_name=item["agent_name"],
            hypothesis_type=item["hypothesis_type"],
            target_endpoint=item["target_endpoint"],
            http_method=item["http_method"],
            description=item["description"],
            payload_json=json.dumps(
                {
                    **item["payload"],
                    "roles_state": item["payload"].get("roles_state", {}),
                    "candidate_key": item["candidate_key"],
                },
                ensure_ascii=False,
            ),
            confidence=item["confidence"],
            estimated_cost=item["estimated_cost"],
            false_positive_risk=item["false_positive_risk"],
            coverage_gain=item["coverage_gain"],
            evidence_readiness=item["evidence_readiness"],
            status="candidate",
        )
        db.add(h)
        saved_candidates.append(h)

    db.commit()
    for item in saved_candidates:
        db.refresh(item)
    return saved_candidates


def _select_hypothesis(payload: CampaignStepRequest, saved_candidates, db: Session):
    if not saved_candidates:
        raise HTTPException(status_code=400, detail="No hypotheses generated")

    judge_mode = getattr(payload, "judge_mode", "rule_based")

    from ..models import Observation, RoleCredential

    recent_observations = db.query(Observation).filter(
        Observation.session_id == payload.session_id
    ).order_by(Observation.id.asc()).all()
    session_obj = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    strategy_config = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    unified_weights = strategy_config.get("unified_weights") if isinstance(strategy_config, dict) else None

    roles = db.query(RoleCredential).filter(
        RoleCredential.session_id == payload.session_id
    ).all()

    for candidate in saved_candidates:
        payload_json = {}
        if candidate.payload_json:
            try:
                payload_json = json.loads(candidate.payload_json)
            except Exception:
                payload_json = {}
        payload_json["roles_state"] = {role.role_name: role.status for role in roles}
        candidate.payload_json = json.dumps(payload_json, ensure_ascii=False)

    if judge_mode == "unified":
        hypotheses_json = [serialize_hypothesis(h) for h in saved_candidates]
        recent_selected_keys = [
            item[0]
            for item in db.query(JudgeDecision.raw_selected_key)
            .filter(JudgeDecision.session_id == payload.session_id)
            .order_by(JudgeDecision.round_no.asc())
            .all()
            if item[0]
        ]
        recent_selected_hypothesis_types = [
            item[0]
            for item in db.query(Hypothesis.hypothesis_type)
            .join(JudgeDecision, JudgeDecision.selected_hypothesis_id == Hypothesis.id)
            .filter(JudgeDecision.session_id == payload.session_id)
            .order_by(JudgeDecision.round_no.asc())
            .all()
            if item[0]
        ]
        context = {
            "session_id": payload.session_id,
            "round_no": db.query(JudgeDecision)
            .filter(JudgeDecision.session_id == payload.session_id)
            .count() + 1,
            "recent_findings_count": db.query(Finding)
            .filter(Finding.session_id == payload.session_id)
            .count(),
            "candidate_count": len(saved_candidates),
            "valid_candidate_keys": [h["candidate_key"] for h in hypotheses_json],
            "orchestration_mode": "unified",
        }

        dify_response = None
        dify_error = None
        try:
            dify_response = call_dify_judge(hypotheses_json, context)
        except Exception as exc:
            dify_error = str(exc)

        selected, score, resolution_mode, resolution_note = choose_unified_candidate(
            saved_candidates,
            hypotheses_json,
            dify_response,
            recent_observations=recent_observations,
            recent_selected_keys=recent_selected_keys,
            recent_selected_hypothesis_types=recent_selected_hypothesis_types,
            weight_config=unified_weights,
        )
        reasoning_summary = (
            f"{resolution_note} "
            f"Selected hypothesis '{selected.hypothesis_type}' from agent '{selected.agent_name}'."
        )
        return selected, score, reasoning_summary, {
            "raw_selected_key": (dify_response or {}).get("selected_key") if dify_response else None,
            "raw_score": (dify_response or {}).get("score") if dify_response else None,
            "raw_reason": dify_error or ((dify_response or {}).get("reason")),
            "resolution_mode": resolution_mode,
        }

    if judge_mode == "dify":
        hypotheses_json = [serialize_hypothesis(h) for h in saved_candidates]

        context = {
            "session_id": payload.session_id,
            "round_no": db.query(JudgeDecision)
            .filter(JudgeDecision.session_id == payload.session_id)
            .count() + 1,
            "recent_findings_count": db.query(Finding)
            .filter(Finding.session_id == payload.session_id)
            .count(),
            "candidate_count": len(saved_candidates),
            "valid_candidate_keys": [h["candidate_key"] for h in hypotheses_json],
        }

        try:
            dify_response = call_dify_judge(hypotheses_json, context)
        except Exception as exc:
            scored = [(h, calculate_dynamic_priority(h)) for h in saved_candidates]
            scored.sort(key=lambda x: x[1], reverse=True)
            selected, score = scored[0]
            reasoning_summary = (
                f"Dify unavailable or invalid response. "
                f"Fallback to rule-based selection. Error: {str(exc)}"
            )
            return selected, score, reasoning_summary, {
                "raw_selected_key": None,
                "raw_score": None,
                "raw_reason": str(exc),
                "resolution_mode": "dify_exception_fallback",
            }
        selected_key = dify_response.get("selected_key")
        selected = None

        if selected_key is not None:
            for h, serialized in zip(saved_candidates, hypotheses_json):
                if serialized["candidate_key"] == selected_key:
                    selected = h
                    break

        def _normalized(value):
            return str(value or "").strip().lower()

        def _safe_score():
            try:
                raw_score = float(dify_response.get("score", 0.5))
            except (TypeError, ValueError):
                raw_score = 0.5
            if raw_score == 0:
                return 0.5
            return raw_score

        def _match_by_type_or_prefix(raw_key):
            key_norm = _normalized(raw_key)
            if not key_norm:
                return None

            # exact hypothesis type returned instead of candidate_key
            type_matches = [
                h for h, s in zip(saved_candidates, hypotheses_json)
                if _normalized(s["type"]) == key_norm
            ]
            if type_matches:
                ranked = [(h, calculate_dynamic_priority(h)) for h in type_matches]
                ranked.sort(key=lambda x: x[1], reverse=True)
                return ranked[0][0]

            # prefixed labels like verify_bola_1 / bola_probe_1 / hypothesis_3
            known_type_prefixes = [
                "bootstrap_roles",
                "discovery",
                "register_role",
                "login_role",
                "authenticated_probe",
                "anonymous_probe",
                "tokenless_replay_probe",
                "auth_boundary_probe",
                "compare_roles",
                "bola_probe",
                "verify_bola",
                "bopla_probe",
                "verify_bopla",
            ]
            for prefix in known_type_prefixes:
                if key_norm.startswith(prefix):
                    type_matches = [
                        h for h, s in zip(saved_candidates, hypotheses_json)
                        if _normalized(s["type"]) == prefix
                    ]
                    if type_matches:
                        ranked = [(h, calculate_dynamic_priority(h)) for h in type_matches]
                        ranked.sort(key=lambda x: x[1], reverse=True)
                        return ranked[0][0]
            return None

        if selected is None:
            selected = _match_by_type_or_prefix(selected_key)
            if selected is not None:
                score = _safe_score()
                reasoning_summary = (
                    f"Dify returned non-canonical candidate key '{selected_key}', "
                    f"resolved to matching candidate type '{selected.hypothesis_type}'. "
                    f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                )
                return selected, score, reasoning_summary, {
                    "raw_selected_key": selected_key,
                    "raw_score": dify_response.get("score"),
                    "raw_reason": dify_response.get("reason"),
                    "resolution_mode": "dify_type_recovery",
                }

        reason_text = str(dify_response.get("reason", "")).lower()

        if selected is None:
            if "bootstrap" in reason_text:
                bootstrap_candidates = [
                    h for h, s in zip(saved_candidates, hypotheses_json)
                    if s["type"] == "bootstrap_roles"
                ]
                if bootstrap_candidates:
                    selected = bootstrap_candidates[0]
                    return selected, _safe_score(), (
                        f"Dify returned invalid candidate key '{selected_key}', "
                        f"but reasoning indicated bootstrap intent. "
                        f"Resolved to bootstrap_roles candidate. "
                        f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                    ), {
                        "raw_selected_key": selected_key,
                        "raw_score": dify_response.get("score"),
                        "raw_reason": dify_response.get("reason"),
                        "resolution_mode": "dify_reason_bootstrap_recovery",
                    }

        if selected is None:
            if "login" in reason_text or "authentication" in reason_text or "token" in reason_text:
                auth_candidates = [
                    h for h, s in zip(saved_candidates, hypotheses_json)
                    if s["type"] in {
                        "login_role",
                        "register_role",
                        "anonymous_probe",
                        "tokenless_replay_probe",
                        "auth_boundary_probe",
                    }
                ]
                if auth_candidates:
                    ranked = [(h, calculate_dynamic_priority(h)) for h in auth_candidates]
                    ranked.sort(key=lambda x: x[1], reverse=True)
                    selected = ranked[0][0]
                    return selected, _safe_score(), (
                        f"Dify returned invalid candidate key '{selected_key}', "
                        f"but reasoning indicated auth intent. "
                        f"Resolved to best auth candidate '{selected.hypothesis_type}'. "
                        f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                    ), {
                        "raw_selected_key": selected_key,
                        "raw_score": dify_response.get("score"),
                        "raw_reason": dify_response.get("reason"),
                        "resolution_mode": "dify_reason_auth_recovery",
                    }

        if selected is None:
            if "verify" in reason_text:
                verify_candidates = [
                    h for h, s in zip(saved_candidates, hypotheses_json)
                    if s["type"] in {"verify_bola", "verify_bopla"}
                ]
                if verify_candidates:
                    ranked = [(h, calculate_dynamic_priority(h)) for h in verify_candidates]
                    ranked.sort(key=lambda x: x[1], reverse=True)
                    selected = ranked[0][0]
                    return selected, _safe_score(), (
                        f"Dify returned invalid candidate key '{selected_key}', "
                        f"but reasoning indicated verification intent. "
                        f"Resolved to best verify candidate '{selected.hypothesis_type}'. "
                        f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                    ), {
                        "raw_selected_key": selected_key,
                        "raw_score": dify_response.get("score"),
                        "raw_reason": dify_response.get("reason"),
                        "resolution_mode": "dify_reason_verify_recovery",
                    }

        if selected is None:
            bola_candidates = [
                h for h, s in zip(saved_candidates, hypotheses_json)
                if s["type"] == "bola_probe"
            ]
            if (
                "bola" in reason_text
                or "object" in reason_text
                or "authorization" in reason_text
            ) and bola_candidates:
                selected = bola_candidates[0]
                score = _safe_score()
                reasoning_summary = (
                    f"Dify returned invalid candidate key '{selected_key}', "
                    f"but reasoning indicated BOLA-like intent. "
                    f"Resolved to first matching bola_probe candidate. "
                    f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                )
                return selected, score, reasoning_summary, {
                    "raw_selected_key": selected_key,
                    "raw_score": dify_response.get("score"),
                    "raw_reason": dify_response.get("reason"),
                    "resolution_mode": "dify_reason_bola_recovery",
                }

        if selected is None:
            bopla_candidates = [
                h for h, s in zip(saved_candidates, hypotheses_json)
                if s["type"] == "bopla_probe"
            ]
            if (
                "bopla" in reason_text
                or "property" in reason_text
                or "field" in reason_text
                or "fields" in reason_text
                or "sensitive" in reason_text
                or "exposure" in reason_text
                or "data exposure" in reason_text
            ) and bopla_candidates:
                selected = bopla_candidates[0]
                score = _safe_score()
                reasoning_summary = (
                    f"Dify returned invalid candidate key '{selected_key}', "
                    f"but reasoning indicated BOPLA-like intent. "
                    f"Resolved to first matching bopla_probe candidate. "
                    f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
                )
                return selected, score, reasoning_summary, {
                    "raw_selected_key": selected_key,
                    "raw_score": dify_response.get("score"),
                    "raw_reason": dify_response.get("reason"),
                    "resolution_mode": "dify_reason_bopla_recovery",
                }

        if selected is not None:
            score = _safe_score()
            reasoning_summary = str(dify_response.get("reason", "Dify selection"))
            return selected, score, reasoning_summary, {
                "raw_selected_key": selected_key,
                "raw_score": dify_response.get("score"),
                "raw_reason": dify_response.get("reason"),
                "resolution_mode": "dify_direct_match",
            }

        scored = [(h, calculate_dynamic_priority(h)) for h in saved_candidates]
        scored.sort(key=lambda x: x[1], reverse=True)
        selected, score = scored[0]
        reasoning_summary = (
            f"Dify returned invalid candidate key '{selected_key}' and no semantic recovery matched. "
            f"Fallback to rule-based selection. "
            f"Original Dify reason: {dify_response.get('reason', 'N/A')}"
        )
        return selected, score, reasoning_summary, {
            "raw_selected_key": selected_key,
            "raw_score": dify_response.get("score"),
            "raw_reason": dify_response.get("reason"),
            "resolution_mode": "dify_rule_based_fallback",
        }

    scored = [(h, calculate_dynamic_priority(h, recent_observations=recent_observations)) for h in saved_candidates]
    scored.sort(key=lambda x: x[1], reverse=True)
    selected, score = scored[0]
    reasoning_summary = build_reasoning_summary(selected, score)
    return selected, score, reasoning_summary, {
        "raw_selected_key": None,
        "raw_score": score,
        "raw_reason": reasoning_summary,
        "resolution_mode": "rule_based_direct",
    }


@router.post("/step")
def campaign_step(payload: CampaignStepRequest, db: Session = Depends(get_db)):
    session_obj = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")

    can_continue, stop_reason = can_continue_session(session_obj)
    if not can_continue:
        session_obj.status = "stopped"
        session_obj.stop_reason = stop_reason
        db.commit()
        return {
            "session_id": payload.session_id,
            "status": "stopped",
            "stop_reason": stop_reason,
        }

    runtime = generate_hypotheses_runtime_for_session(db, payload.session_id)
    generated = runtime["hypotheses"]
    agent_invocations = runtime["agent_invocations"]
    saved_candidates = _save_generated_hypotheses(db, payload.session_id, generated)

    selected, score, reasoning_summary, judge_trace = _select_hypothesis(payload, saved_candidates, db)
    selected.status = "selected"

    previous_rounds = db.query(JudgeDecision).filter(
        JudgeDecision.session_id == payload.session_id
    ).count()

    decision = JudgeDecision(
        session_id=payload.session_id,
        round_no=previous_rounds + 1,
        selected_hypothesis_id=selected.id,
        decision_type=classify_decision_type(selected.hypothesis_type),
        priority_score=score,
        judge_mode=getattr(payload, "judge_mode", "rule_based"),
        raw_selected_key=judge_trace.get("raw_selected_key"),
        raw_score=judge_trace.get("raw_score"),
        raw_reason=judge_trace.get("raw_reason"),
        resolution_mode=judge_trace.get("resolution_mode"),
        reasoning_summary=reasoning_summary,
        required_evidence_json=json.dumps(build_required_evidence(selected), ensure_ascii=False),
        stop_condition_json=json.dumps(build_stop_condition(selected), ensure_ascii=False),
    )
    db.add(decision)
    record_judge_feedback(
        db,
        session_id=payload.session_id,
        round_no=previous_rounds + 1,
        judge_mode=getattr(payload, "judge_mode", "rule_based"),
        candidates=saved_candidates,
        selected_hypothesis=selected,
        selected_score=score,
        reasoning_summary=reasoning_summary,
    )

    register_round(session_obj)
    update_strategy_state(
        session_obj,
        {
            "judge_mode": getattr(payload, "judge_mode", "rule_based"),
            "round_no": decision.round_no,
            "selected_hypothesis_type": selected.hypothesis_type,
            "selected_hypothesis_id": selected.id,
            "selected_agent": selected.agent_name,
            "agents_invoked": [item["agent_name"] for item in agent_invocations],
            "active_agents": [
                item["agent_name"]
                for item in agent_invocations
                if item.get("participated")
            ],
        },
    )
    db.commit()
    db.refresh(decision)

    execution_result, request_count = execute_hypothesis(db, session_obj, selected)
    register_requests(session_obj, request_count)

    if execution_result.get("action_executed") == "compare_roles":
        created_finding = maybe_create_finding_from_comparison(
            db=db,
            session_id=payload.session_id,
            selected_id=selected.id,
            comparison=execution_result.get("comparison", {}),
            endpoint=selected.target_endpoint,
        )
        if created_finding is not None:
            execution_result["generated_finding_id"] = created_finding.id
            execution_result["generated_finding_type"] = created_finding.finding_type
            execution_result["generated_finding_status"] = created_finding.verification_status

    if execution_result.get("action_executed") in {
        "anonymous_probe",
        "tokenless_replay_probe",
        "auth_boundary_probe",
    }:
        selected_payload = {}
        try:
            selected_payload = json.loads(selected.payload_json or "{}")
        except Exception:
            selected_payload = {}
        created_finding = maybe_create_auth_finding_from_execution(
            db=db,
            session_id=payload.session_id,
            selected_id=selected.id,
            action_executed=execution_result.get("action_executed"),
            status_code=execution_result.get("status_code"),
            endpoint=selected.target_endpoint,
            observation_id=execution_result.get("observation_id"),
            source_role=execution_result.get("source_role"),
            source_observation_id=selected_payload.get("source_observation_id"),
        )
        if created_finding is not None:
            execution_result["generated_finding_id"] = created_finding.id
            execution_result["generated_finding_type"] = created_finding.finding_type
            execution_result["generated_finding_status"] = created_finding.verification_status

    record_agent_result(
        db,
        session_id=payload.session_id,
        agent_name=selected.agent_name,
        hypothesis=selected,
        execution_result=execution_result,
        request_count=request_count,
    )

    can_continue_after, stop_reason_after = can_continue_session(session_obj)
    terminal_reverification = None
    if not can_continue_after:
        terminal_reverification = run_terminal_reverification_pass(db, session_obj)
        session_obj.status = "stopped"
        session_obj.stop_reason = stop_reason_after

    db.commit()

    return {
        "session_id": payload.session_id,
        "round_no": decision.round_no,
        "judge_mode": getattr(payload, "judge_mode", "rule_based"),
        "selected_hypothesis": {
            "id": selected.id,
            "type": selected.hypothesis_type,
            "agent_name": selected.agent_name,
            "target_endpoint": selected.target_endpoint,
            "http_method": selected.http_method,
            "description": selected.description,
        },
        "judge": {
            "decision_type": decision.decision_type,
            "priority_score": decision.priority_score,
            "reasoning_summary": decision.reasoning_summary,
            "resolution_mode": decision.resolution_mode,
            "raw_selected_key": decision.raw_selected_key,
            "raw_score": decision.raw_score,
        },
        "agent_orchestration": {
            "enabled_agents": runtime["enabled_agents"],
            "enabled_logical_agents": runtime.get("enabled_logical_agents", []),
            "exploitation_queue_summary": runtime.get("exploitation_queue_summary", {}),
            "agents_invoked": [item["agent_name"] for item in agent_invocations],
            "active_agents": [
                item["agent_name"]
                for item in agent_invocations
                if item.get("participated")
            ],
            "selected_agent": selected.agent_name,
            "selected_logical_agent": next(
                (
                    item.get("logical_agent_name")
                    for item in agent_invocations
                    if item.get("agent_name") == selected.agent_name
                ),
                None,
            ),
            "agent_invocations": agent_invocations,
            "logical_agent_summary": runtime.get("logical_agent_summary", {}),
        },
        "session_state": {
            "status": session_obj.status,
            "rounds_completed": session_obj.rounds_completed,
            "max_rounds": session_obj.max_rounds,
            "budget_requests_used": session_obj.budget_requests_used,
            "budget_requests_total": session_obj.budget_requests_total,
            "stop_reason": session_obj.stop_reason,
        },
        "execution_result": execution_result,
        "terminal_reverification": terminal_reverification,
    }


@router.post("/run")
def campaign_run(payload: CampaignRunRequest, db: Session = Depends(get_db)):
    session_obj = create_campaign_session(
        db,
        target_name=payload.target_name,
        target_url=payload.target_url,
        budget_requests_total=payload.budget_requests_total,
        budget_time_total=payload.budget_time_total,
        max_rounds=payload.max_rounds,
        allowed_test_classes=payload.allowed_test_classes,
        enabled_agents=payload.enabled_agents,
    )

    step_results = []
    for _ in range(payload.max_rounds or 0):
        step_result = campaign_step(
            CampaignStepRequest(
                session_id=session_obj.id,
                judge_mode=payload.judge_mode,
            ),
            db=db,
        )
        step_results.append(step_result)

        session_state = step_result.get("session_state", {})
        if step_result.get("status") == "stopped" or session_state.get("status") == "stopped":
            break

    metrics = collect_session_metrics(db, session_obj.id)
    report = collect_session_report(db, session_obj.id)

    return {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
            "judge_mode": payload.judge_mode,
            "status": report["session"]["status"],
        },
        "steps_executed": len(step_results),
        "last_step": step_results[-1] if step_results else None,
        "metrics": metrics["metrics"],
        "report": report,
    }
