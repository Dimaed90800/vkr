import os
from typing import Any, Dict, List, Optional

import requests
from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..models import ExperimentRun, ExperimentResult
from .agent_registry_service import resolve_experiment_enabled_agents
from .judge_trace_service import classify_dify_issue


DEFAULT_BOOTSTRAP_BY_TARGET = {
    "crapi": {
        "bola": [
            {
                "role_name": "user_a",
                "endpoint_template": "{target_url}/community/api/v2/community/posts/recent",
                "method": "GET",
                "use_role_token": True,
            }
        ],
        "bopla": [
            {
                "role_name": "user_a",
                "endpoint_template": "{target_url}/identity/api/v2/user/dashboard",
                "method": "GET",
                "use_role_token": True,
            }
        ],
    }
}


DEFAULT_INTERNAL_HTTP_TIMEOUT = int(os.getenv("EXPERIMENT_INTERNAL_HTTP_TIMEOUT", "60"))
DEFAULT_INTERNAL_STEP_TIMEOUT = int(os.getenv("EXPERIMENT_INTERNAL_STEP_TIMEOUT", "180"))
DEFAULT_INTERNAL_METRICS_TIMEOUT = int(os.getenv("EXPERIMENT_INTERNAL_METRICS_TIMEOUT", "120"))


def extract_logical_agent_summary(agent_metrics: Optional[dict]) -> dict:
    agent_metrics = agent_metrics or {}
    return {
        "logical_agent_activity_summary": agent_metrics.get("logical_agent_activity_summary", {}),
        "logical_agent_learning_summary": agent_metrics.get("logical_agent_learning_summary", {}),
        "logical_agent_judge_feedback_summary": agent_metrics.get("logical_agent_judge_feedback_summary", {}),
        "logical_agent_effectiveness_summary": agent_metrics.get("logical_agent_effectiveness_summary", {}),
    }


def post_json(url: str, payload: dict, timeout: int = DEFAULT_INTERNAL_HTTP_TIMEOUT):
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Request failed: {url} -> {resp.status_code} {resp.text}",
        )
    return resp.json()


def get_json(url: str, timeout: int = DEFAULT_INTERNAL_HTTP_TIMEOUT):
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

    return None


def _normalize_target_name(value: Optional[str]) -> str:
    return str(value or "").strip().lower().replace("owasp_", "").replace("owasp-", "")


def _resolve_bootstrap_probes(
    *,
    target_name: str,
    target_url: str,
    profile: str,
    bootstrap_profile: Optional[str] = None,
    bootstrap_probes: Optional[List[dict]] = None,
) -> List[dict]:
    if bootstrap_probes:
        probes = []
        for item in bootstrap_probes:
            if not isinstance(item, dict):
                continue
            endpoint = str(item.get("endpoint") or "").strip()
            endpoint_template = str(item.get("endpoint_template") or "").strip()
            if not endpoint and endpoint_template:
                endpoint = endpoint_template.format(target_url=target_url.rstrip("/"))
            if not endpoint:
                continue
            probes.append(
                {
                    "role_name": str(item.get("role_name") or "user_a"),
                    "endpoint": endpoint,
                    "method": str(item.get("method") or "GET"),
                    "use_role_token": bool(item.get("use_role_token", True)),
                    "headers": item.get("headers"),
                    "params": item.get("params"),
                    "json_body": item.get("json_body"),
                }
            )
        return probes

    normalized_target = _normalize_target_name(target_name)
    target_bootstrap = DEFAULT_BOOTSTRAP_BY_TARGET.get(normalized_target, {})
    selected_profile = str(bootstrap_profile or profile or "mixed").strip().lower()

    profile_keys = []
    if selected_profile == "mixed":
        profile_keys = ["bola", "bopla"]
    elif selected_profile in {"bola", "bopla", "auth"}:
        profile_keys = [selected_profile]

    probes = []
    for key in profile_keys:
        for item in target_bootstrap.get(key, []):
            endpoint_template = str(item.get("endpoint_template") or "").strip()
            endpoint = endpoint_template.format(target_url=target_url.rstrip("/")) if endpoint_template else str(item.get("endpoint") or "").strip()
            if not endpoint:
                continue
            probes.append(
                {
                    "role_name": str(item.get("role_name") or "user_a"),
                    "endpoint": endpoint,
                    "method": str(item.get("method") or "GET"),
                    "use_role_token": bool(item.get("use_role_token", True)),
                    "headers": item.get("headers"),
                    "params": item.get("params"),
                    "json_body": item.get("json_body"),
                }
            )
    return probes


def bootstrap_session_with_probes(
    *,
    session_id: int,
    profile: str,
    target_name: str,
    target_url: str,
    bootstrap_profile: Optional[str] = None,
    bootstrap_probes: Optional[List[dict]] = None,
):
    bootstrap_session(session_id, profile=profile)
    probes = _resolve_bootstrap_probes(
        target_name=target_name,
        target_url=target_url,
        profile=profile,
        bootstrap_profile=bootstrap_profile,
        bootstrap_probes=bootstrap_probes,
    )

    for probe in probes:
        post_json("http://localhost:8000/observations/probe", {
            "session_id": session_id,
            "role_name": probe.get("role_name"),
            "endpoint": probe.get("endpoint"),
            "method": probe.get("method", "GET"),
            "use_role_token": probe.get("use_role_token", True),
            "headers": probe.get("headers"),
            "params": probe.get("params"),
            "json_body": probe.get("json_body"),
        })

    return probes


def run_experiment_scenario(
    db: Session,
    *,
    target_name: str,
    target_url: str,
    judge_mode: str = "rule_based",
    max_rounds: int = 5,
    profile: str = "mixed",
    budget_requests_total: Optional[int] = 200,
    budget_time_total: Optional[int] = 1800,
    enabled_agents: Optional[List[str]] = None,
    enabled_logical_agents: Optional[List[str]] = None,
    disabled_logical_agents: Optional[List[str]] = None,
    bootstrap_profile: Optional[str] = None,
    bootstrap_probes: Optional[List[dict]] = None,
    strategy_config: Optional[Dict[str, Any]] = None,
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

    resolved_enabled_agents = resolve_experiment_enabled_agents(
        enabled_agents=enabled_agents,
        enabled_logical_agents=enabled_logical_agents,
        disabled_logical_agents=disabled_logical_agents,
    )
    session_strategy_config = dict(strategy_config or {})

    session_data = post_json("http://localhost:8000/session/create", {
        "target_name": target_name,
        "target_url": target_url,
        "budget_requests_total": budget_requests_total,
        "budget_time_total": budget_time_total,
        "max_rounds": max_rounds,
        "allowed_test_classes": ["discovery", "bola", "bopla", "auth"],
        "enabled_agents": resolved_enabled_agents,
        "strategy_config": session_strategy_config,
    })
    session_id = session_data["id"]

    resolved_bootstrap_probes = bootstrap_session_with_probes(
        session_id=session_id,
        profile=profile,
        target_name=target_name,
        target_url=target_url,
        bootstrap_profile=bootstrap_profile,
        bootstrap_probes=bootstrap_probes,
    )

    fallback_count = 0
    rule_based_override_count = 0
    scores = []
    step_error = None

    for _ in range(max_rounds):
        try:
            step = post_json(
                "http://localhost:8000/campaign/step",
                {
                    "session_id": session_id,
                    "judge_mode": judge_mode,
                },
                timeout=DEFAULT_INTERNAL_STEP_TIMEOUT,
            )
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

    metrics = get_json(
        f"http://localhost:8000/metrics/session/{session_id}",
        timeout=DEFAULT_INTERNAL_METRICS_TIMEOUT,
    )["metrics"]
    agent_metrics = get_json(
        f"http://localhost:8000/metrics/session/{session_id}/agents",
        timeout=DEFAULT_INTERNAL_METRICS_TIMEOUT,
    )
    resource_metrics = {
        "rounds_completed": metrics.get("rounds_completed", 0),
        "max_rounds": metrics.get("max_rounds"),
        "budget_requests_used": metrics.get("budget_requests_used", 0),
        "budget_requests_total": metrics.get("budget_requests_total"),
        "request_budget_utilization": metrics.get("request_budget_utilization", 0.0),
        "budget_time_used": metrics.get("budget_time_used", 0),
        "budget_time_total": metrics.get("budget_time_total"),
        "time_budget_utilization": metrics.get("time_budget_utilization", 0.0),
        "rate_limit_responses": metrics.get("rate_limit_responses", 0),
        "selected_estimated_cost_total": metrics.get("selected_estimated_cost_total", 0.0),
        "avg_selected_estimated_cost": metrics.get("avg_selected_estimated_cost", 0.0),
        "requests_per_confirmed_finding": metrics.get("requests_per_confirmed_finding", 0.0),
        "time_per_confirmed_finding": metrics.get("time_per_confirmed_finding", 0.0),
    }

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
        "target_name": target_name,
        "target_url": target_url,
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
            **resource_metrics,
        },
        "agent_summary": agent_metrics,
        "logical_agent_summary": extract_logical_agent_summary(agent_metrics),
        "experiment_design": {
            "enabled_agents": resolved_enabled_agents,
            "enabled_logical_agents": sorted({item.get("logical_agent_name") for item in (agent_metrics.get("logical_agent_activity_summary", {}) or {}).get("logical_agents", []) if item.get("logical_agent_name")}),
            "disabled_logical_agents": [str(item) for item in (disabled_logical_agents or []) if str(item or "").strip()],
            "bootstrap_profile": bootstrap_profile or profile,
            "bootstrap_probes_total": len(resolved_bootstrap_probes),
            "bootstrap_probes": resolved_bootstrap_probes,
            "strategy_config": session_strategy_config,
        },
        "step_error": step_error,
    }


def normalize_judge_modes(judge_modes=None) -> List[str]:
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
