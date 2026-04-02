from typing import Optional

import requests
from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..models import ExperimentRun, ExperimentResult
from .judge_trace_service import classify_dify_issue


def extract_logical_agent_summary(agent_metrics: Optional[dict]) -> dict:
    agent_metrics = agent_metrics or {}
    return {
        "logical_agent_activity_summary": agent_metrics.get("logical_agent_activity_summary", {}),
        "logical_agent_learning_summary": agent_metrics.get("logical_agent_learning_summary", {}),
        "logical_agent_judge_feedback_summary": agent_metrics.get("logical_agent_judge_feedback_summary", {}),
        "logical_agent_effectiveness_summary": agent_metrics.get("logical_agent_effectiveness_summary", {}),
    }


def post_json(url: str, payload: dict, timeout: int = 60):
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Request failed: {url} -> {resp.status_code} {resp.text}",
        )
    return resp.json()


def get_json(url: str, timeout: int = 60):
    resp = requests.get(url, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Request failed: {url} -> {resp.status_code} {resp.text}",
        )
    return resp.json()


def bootstrap_session(session_id: int, profile: str = "mixed"):
    post_json("http://localhost:8000/roles/create", {
        "session_id": session_id,
        "role_name": "user_a",
    })
    post_json("http://localhost:8000/roles/create", {
        "session_id": session_id,
        "role_name": "user_b",
    })

    post_json("http://localhost:8000/roles/register", {
        "session_id": session_id,
        "role_name": "user_a",
    })
    post_json("http://localhost:8000/roles/register", {
        "session_id": session_id,
        "role_name": "user_b",
    })

    post_json("http://localhost:8000/roles/login", {
        "session_id": session_id,
        "role_name": "user_a",
    })
    post_json("http://localhost:8000/roles/login", {
        "session_id": session_id,
        "role_name": "user_b",
    })

    if profile in {"bola", "mixed"}:
        post_json("http://localhost:8000/observations/probe", {
            "session_id": session_id,
            "role_name": "user_a",
            "endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            "method": "GET",
            "use_role_token": True,
        })

    if profile in {"bopla", "mixed"}:
        post_json("http://localhost:8000/observations/probe", {
            "session_id": session_id,
            "role_name": "user_a",
            "endpoint": "http://host.docker.internal:8888/identity/api/v2/user/dashboard",
            "method": "GET",
            "use_role_token": True,
        })


def run_experiment_scenario(
    db: Session,
    *,
    target_name: str,
    target_url: str,
    judge_mode: str = "rule_based",
    max_rounds: int = 5,
    profile: str = "mixed",
):
    experiment = ExperimentRun(
        target_name=target_name,
        target_url=target_url,
        judge_mode=judge_mode,
        profile=profile,
        max_rounds=max_rounds,
    )
    db.add(experiment)
    db.commit()
    db.refresh(experiment)

    session_data = post_json("http://localhost:8000/session/create", {
        "target_name": target_name,
        "target_url": target_url,
        "max_rounds": max_rounds,
        "allowed_test_classes": ["discovery", "bola", "bopla", "auth"],
    })
    session_id = session_data["id"]

    bootstrap_session(session_id, profile=profile)

    fallback_count = 0
    rule_based_override_count = 0
    scores = []
    step_error = None

    for _ in range(max_rounds):
        try:
            step = post_json("http://localhost:8000/campaign/step", {
                "session_id": session_id,
                "judge_mode": judge_mode,
            })
        except HTTPException as exc:
            step_error = str(getattr(exc, "detail", exc))
            break

        if step.get("status") == "stopped":
            break

        judge = step.get("judge", {})

        try:
            scores.append(float(judge.get("priority_score", 0)))
        except (TypeError, ValueError):
            scores.append(0)

        resolution_mode = str(judge.get("resolution_mode", "") or "")
        reasoning = str(judge.get("reasoning_summary", "") or "")
        raw_reason = str(judge.get("raw_reason", "") or "")
        issue_type = classify_dify_issue(
            resolution_mode,
            raw_reason=raw_reason,
            reasoning_summary=reasoning,
        )
        if issue_type == "rule_based_override":
            rule_based_override_count += 1
        if issue_type in {
            "provider_credit_limit",
            "empty_outputs",
            "invalid_candidate_key",
            "provider_timeout",
            "provider_error",
            "exception_fallback_other",
            "fallback_other",
        }:
            fallback_count += 1

    metrics = get_json(f"http://localhost:8000/metrics/session/{session_id}")["metrics"]
    agent_metrics = get_json(f"http://localhost:8000/metrics/session/{session_id}/agents")

    result = ExperimentResult(
        experiment_id=experiment.id,
        total_rounds=max_rounds,
        findings_total=metrics["findings_total"],
        bola_findings=metrics["bola_findings"],
        bopla_findings=metrics["bopla_findings"],
        confirmed_findings=metrics["confirmed_findings"],
        confirmed_bola=metrics["confirmed_bola"],
        confirmed_bopla=metrics["confirmed_bopla"],
        judge_decisions=metrics["judge_decisions"],
        fallback_count=fallback_count,
        avg_score=(sum(scores) / len(scores)) if scores else 0,
    )

    db.add(result)
    db.commit()
    db.refresh(result)

    return {
        "experiment_id": experiment.id,
        "session_id": session_id,
        "judge_mode": judge_mode,
        "profile": profile,
        "result": {
            "findings_total": result.findings_total,
            "bola_findings": result.bola_findings,
            "bopla_findings": result.bopla_findings,
            "auth_findings": metrics.get("auth_findings", 0),
            "auth_boundary_signals": metrics.get("auth_boundary_signals", 0),
            "confirmed_findings": result.confirmed_findings,
            "confirmed_bola": result.confirmed_bola,
            "confirmed_bopla": result.confirmed_bopla,
            "confirmed_auth_findings": metrics.get("confirmed_auth_findings", 0),
            "confirmed_auth_boundary_signals": metrics.get("confirmed_auth_boundary_signals", 0),
            "fallback_count": result.fallback_count,
            "rule_based_override_count": rule_based_override_count,
            "avg_score": result.avg_score,
        },
        "agent_summary": agent_metrics,
        "logical_agent_summary": extract_logical_agent_summary(agent_metrics),
        "step_error": step_error,
    }


def normalize_judge_modes(judge_modes=None) -> list[str]:
    normalized = []
    seen = set()
    source = judge_modes or ["rule_based", "dify", "unified"]

    for item in source:
        mode = str(item or "").strip().lower()
        if mode not in {"rule_based", "dify", "unified"}:
            continue
        if mode in seen:
            continue
        seen.add(mode)
        normalized.append(mode)

    return normalized or ["rule_based", "dify", "unified"]
