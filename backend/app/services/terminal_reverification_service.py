from __future__ import annotations

import json

from ..models import Finding, Hypothesis
from .agent_hypothesis_service import generate_verifier_agent_hypotheses
from .agent_memory_service import record_agent_result
from .campaign_execution_service import execute_hypothesis
from .session_state_service import deserialize_strategy_state, register_requests, update_strategy_state


def _verifier_priority(candidate: dict) -> tuple:
    hypothesis_type = str(candidate.get("hypothesis_type") or "")
    type_rank = {
        "verify_bola": 3,
        "verify_bopla": 2,
        "verify_auth_boundary": 1,
    }.get(hypothesis_type, 0)
    return (
        type_rank,
        float(candidate.get("evidence_readiness", 0.0) or 0.0),
        float(candidate.get("confidence", 0.0) or 0.0),
        -float(candidate.get("false_positive_risk", 0.0) or 0.0),
    )


def rank_verifier_candidates(candidates: list[dict]) -> list[dict]:
    return sorted(candidates or [], key=_verifier_priority, reverse=True)


def run_terminal_reverification_pass(db, session_obj) -> dict:
    strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    strategy_config = strategy_state.get("strategy_config") if isinstance(strategy_state, dict) else {}
    strategy_config = strategy_config if isinstance(strategy_config, dict) else {}

    if strategy_config.get("disable_terminal_reverification"):
        return {
            "executed": False,
            "reason": "disabled_by_strategy_config",
            "attempted": 0,
            "completed": 0,
            "results": [],
        }

    if strategy_state.get("terminal_reverification_done"):
        return {
            "executed": False,
            "reason": "already_completed",
            "attempted": 0,
            "completed": 0,
            "results": [],
        }

    candidate_findings = db.query(Finding).filter(
        Finding.session_id == session_obj.id,
        Finding.verification_status == "candidate",
    ).all()
    verifier_candidates = rank_verifier_candidates(
        generate_verifier_agent_hypotheses(candidate_findings)
    )

    max_actions = int(strategy_config.get("terminal_reverification_max_actions", 2) or 2)
    selected_candidates = verifier_candidates[:max_actions]

    if not selected_candidates:
        update_strategy_state(
            session_obj,
            {
                "terminal_reverification_done": True,
                "terminal_reverification_summary": {
                    "executed": False,
                    "reason": "no_candidates",
                    "attempted": 0,
                    "completed": 0,
                    "results": [],
                },
            },
        )
        return {
            "executed": False,
            "reason": "no_candidates",
            "attempted": 0,
            "completed": 0,
            "results": [],
        }

    results = []
    completed = 0
    for candidate in selected_candidates:
        hypothesis = Hypothesis(
            session_id=session_obj.id,
            agent_name=str(candidate.get("agent_name") or "rule_based_verifier_agent"),
            hypothesis_type=str(candidate.get("hypothesis_type") or "verify_bola"),
            target_endpoint=candidate.get("target_endpoint"),
            http_method=candidate.get("http_method"),
            description=str(candidate.get("description") or "Terminal reverification action"),
            payload_json=json.dumps(
                {
                    **(candidate.get("payload") or {}),
                    "candidate_key": candidate.get("candidate_key"),
                },
                ensure_ascii=False,
            ),
            confidence=float(candidate.get("confidence", 0.0) or 0.0),
            estimated_cost=float(candidate.get("estimated_cost", 0.0) or 0.0),
            false_positive_risk=float(candidate.get("false_positive_risk", 0.0) or 0.0),
            coverage_gain=float(candidate.get("coverage_gain", 0.0) or 0.0),
            evidence_readiness=float(candidate.get("evidence_readiness", 0.0) or 0.0),
            status="selected",
        )
        db.add(hypothesis)
        db.commit()
        db.refresh(hypothesis)

        execution_result, request_count = execute_hypothesis(db, session_obj, hypothesis)
        register_requests(session_obj, request_count)
        record_agent_result(
            db,
            session_id=session_obj.id,
            agent_name=hypothesis.agent_name,
            hypothesis=hypothesis,
            execution_result=execution_result,
            request_count=request_count,
        )
        completed += 1
        results.append(
            {
                "hypothesis_id": hypothesis.id,
                "hypothesis_type": hypothesis.hypothesis_type,
                "target_endpoint": hypothesis.target_endpoint,
                "verification_status": execution_result.get("verification_status"),
                "finding_id": execution_result.get("finding_id"),
                "request_count": request_count,
            }
        )

    summary = {
        "executed": True,
        "reason": "completed",
        "attempted": len(selected_candidates),
        "completed": completed,
        "results": results,
    }
    update_strategy_state(
        session_obj,
        {
            "terminal_reverification_done": True,
            "terminal_reverification_summary": summary,
        },
    )
    return summary
