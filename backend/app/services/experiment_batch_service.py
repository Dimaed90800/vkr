from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import HTTPException
from sqlalchemy.orm import Session

from ..models import (
    AgentJudgeFeedback,
    AgentStrategyMemory,
    ExperimentRun,
    ExperimentResult,
    Finding,
    Hypothesis,
    JudgeDecision,
    Observation,
    RoleCredential,
    TestSession,
)
from .experiment_report_service import (
    build_experiment_comparison_report,
    build_run_batch_logical_agent_rows,
    build_run_batch_logical_agent_summary,
)
from .experiment_run_service import normalize_judge_modes, run_experiment_scenario
from .llm_report_service import build_session_llm_report


def load_session_bundle(db: Session, session_id: int):
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")

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


def build_run_batch_response(db: Session, payload: Dict[str, Any]) -> Dict[str, Any]:
    target_name = payload.get("target_name")
    target_url = payload.get("target_url")
    max_rounds = payload.get("max_rounds", 5)
    profile = payload.get("profile", "mixed")
    judge_modes = normalize_judge_modes(payload.get("judge_modes"))
    targets = payload.get("targets")
    enabled_agents = payload.get("enabled_agents")
    enabled_logical_agents = payload.get("enabled_logical_agents")
    disabled_logical_agents = payload.get("disabled_logical_agents")
    bootstrap_profile = payload.get("bootstrap_profile")
    bootstrap_probes = payload.get("bootstrap_probes")
    strategy_config = payload.get("strategy_config") or {}
    budget_requests_total = payload.get("budget_requests_total", 200)
    budget_time_total = payload.get("budget_time_total", 1800)
    external_baselines = payload.get("external_baselines") or []

    if not targets:
        if not target_name or not target_url:
            raise HTTPException(status_code=400, detail="target_name and target_url are required")
        targets = [
            {
                "target_name": target_name,
                "target_url": target_url,
                "profile": profile,
                "bootstrap_profile": bootstrap_profile,
                "bootstrap_probes": bootstrap_probes,
            }
        ]

    runs = []
    experiment_ids = []
    for target in targets:
        current_target_name = target.get("target_name")
        current_target_url = target.get("target_url")
        current_profile = target.get("profile", profile)
        if not current_target_name or not current_target_url:
            raise HTTPException(status_code=400, detail="Each target requires target_name and target_url")

        for judge_mode in judge_modes:
            result = run_experiment_scenario(
                db=db,
                target_name=current_target_name,
                target_url=current_target_url,
                judge_mode=judge_mode,
                max_rounds=max_rounds,
                profile=current_profile,
                budget_requests_total=budget_requests_total,
                budget_time_total=budget_time_total,
                enabled_agents=enabled_agents,
                enabled_logical_agents=enabled_logical_agents,
                disabled_logical_agents=disabled_logical_agents,
                bootstrap_profile=target.get("bootstrap_profile", bootstrap_profile),
                bootstrap_probes=target.get("bootstrap_probes", bootstrap_probes),
                strategy_config=strategy_config,
            )
            runs.append(result)
            experiment_ids.append(result["experiment_id"])

    experiment_rows = db.query(ExperimentRun).filter(
        ExperimentRun.id.in_(experiment_ids)
    ).all()
    result_rows = db.query(ExperimentResult).filter(
        ExperimentResult.experiment_id.in_(experiment_ids)
    ).all()
    by_experiment_id = {row.experiment_id: row for row in result_rows}

    comparison_report = build_experiment_comparison_report(
        runs=runs,
        by_experiment_id=by_experiment_id,
        filters={
            "target_name": target_name,
            "target_url": target_url,
            "targets": targets,
            "profile": profile,
            "judge_modes": judge_modes,
            "max_rounds": max_rounds,
            "batch_experiment_ids": sorted(experiment_ids),
            "enabled_agents": enabled_agents,
            "enabled_logical_agents": enabled_logical_agents,
            "disabled_logical_agents": disabled_logical_agents,
            "strategy_config": strategy_config,
            "external_baselines": external_baselines,
            "budget_requests_total": budget_requests_total,
            "budget_time_total": budget_time_total,
        },
    )

    return {
        "batch": {
            "target_name": target_name,
            "target_url": target_url,
            "targets": targets,
            "targets_total": len(targets),
            "profile": profile,
            "judge_modes": judge_modes,
            "max_rounds": max_rounds,
            "budget_requests_total": budget_requests_total,
            "budget_time_total": budget_time_total,
            "enabled_agents": enabled_agents,
            "enabled_logical_agents": enabled_logical_agents,
            "disabled_logical_agents": disabled_logical_agents,
            "strategy_config": strategy_config,
            "experiment_ids": sorted(experiment_ids),
            "runs_total": len(runs),
        },
        "runs": runs,
        "batch_logical_agent_summary": build_run_batch_logical_agent_summary(runs),
        "batch_logical_agent_rows": build_run_batch_logical_agent_rows(runs),
        "comparison_report": comparison_report,
    }


def build_run_batch_with_reports_response(
    db: Session,
    payload: Dict[str, Any],
    *,
    reports_export_root: Optional[Path] = None,
) -> Dict[str, Any]:
    batch_response = build_run_batch_response(db, payload)

    session_reports = []
    for run in batch_response["runs"]:
        session_id = run.get("session_id")
        if not session_id:
            continue

        (
            session_obj,
            roles,
            findings,
            judge_decisions,
            observations,
            hypotheses,
            agent_memory_rows,
            agent_judge_feedback_rows,
        ) = load_session_bundle(db, session_id)

        llm_report = build_session_llm_report(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_memory_rows=agent_memory_rows,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
            export_root=reports_export_root,
        )

        session_reports.append(
            {
                "session_id": session_id,
                "judge_mode": run.get("judge_mode"),
                "profile": run.get("profile"),
                "provider": llm_report.get("provider"),
                "used_fallback": llm_report.get("used_fallback"),
                "saved_report_path": llm_report.get("saved_report_path"),
                "report_preview": str(llm_report.get("report_text", ""))[:1200],
            }
        )

    return {
        **batch_response,
        "session_reports": session_reports,
    }


def get_jobs_export_root(export_root: Optional[Path] = None) -> Path:
    if export_root is not None:
        return export_root
    return Path("/app/exports/jobs")


def _write_json(path: Path, payload: Any) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def _render_job_summary_markdown(job_id: str, batch_result: Dict[str, Any], artifact_paths: Dict[str, str]) -> str:
    batch = batch_result.get("batch", {})
    session_reports = batch_result.get("session_reports", [])
    lines = [
        f"# Automation Job {job_id}",
        "",
        f"- Target: {batch.get('target_name')} ({batch.get('target_url')})",
        f"- Profile: {batch.get('profile')}",
        f"- Judge modes: {', '.join(batch.get('judge_modes', []))}",
        f"- Runs total: {batch.get('runs_total', 0)}",
        "",
        "## Session Reports",
        "",
    ]
    for item in session_reports:
        lines.extend(
            [
                f"### {item.get('judge_mode')} / session {item.get('session_id')}",
                "",
                f"- Provider: {item.get('provider')}",
                f"- Used fallback: {item.get('used_fallback')}",
                f"- Saved report path: {item.get('saved_report_path')}",
                "",
            ]
        )

    lines.extend(
        [
            "## Artifacts",
            "",
            f"- Batch result JSON: {artifact_paths.get('batch_result_json')}",
            f"- Comparison report JSON: {artifact_paths.get('comparison_report_json')}",
            f"- Session reports JSON: {artifact_paths.get('session_reports_json')}",
            "",
        ]
    )
    return "\n".join(lines).strip()


def export_batch_job_artifacts(
    *,
    job_id: str,
    batch_result: Dict[str, Any],
    export_root: Optional[Path] = None,
) -> Dict[str, str]:
    job_dir = get_jobs_export_root(export_root) / job_id
    reports_dir = job_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    batch_result_path = job_dir / "batch_result.json"
    comparison_report_path = job_dir / "comparison_report.json"
    session_reports_path = job_dir / "session_reports.json"
    summary_path = job_dir / "summary.md"

    _write_json(batch_result_path, batch_result)
    _write_json(comparison_report_path, batch_result.get("comparison_report", {}))
    _write_json(session_reports_path, batch_result.get("session_reports", []))

    artifact_paths = {
        "job_dir": str(job_dir),
        "reports_dir": str(reports_dir),
        "batch_result_json": str(batch_result_path),
        "comparison_report_json": str(comparison_report_path),
        "session_reports_json": str(session_reports_path),
        "summary_markdown": str(summary_path),
    }
    summary_path.write_text(
        _render_job_summary_markdown(job_id, batch_result, artifact_paths),
        encoding="utf-8",
    )
    return artifact_paths
