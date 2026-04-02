from __future__ import annotations

import csv
import io

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response
from sqlalchemy.orm import Session

from ..db import SessionLocal
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
from ..services.llm_report_service import build_session_llm_report
from ..services.experiment_report_service import (
    build_experiment_comparison_markdown,
    build_experiment_comparison_report,
    build_run_batch_logical_agent_rows,
    build_run_batch_logical_agent_summary,
)
from ..services.experiment_run_service import run_experiment_scenario, normalize_judge_modes

router = APIRouter(prefix="/experiments", tags=["experiments"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _build_filtered_experiment_dataset(
    db: Session,
    min_experiment_id: int | None = None,
    max_experiment_id: int | None = None,
    last_n_runs: int | None = None,
    max_fallback_count: int | None = None,
    judge_mode: str | None = None,
    profile: str | None = None,
    target_name: str | None = None,
):
    runs_query = db.query(ExperimentRun)

    if min_experiment_id is not None:
        runs_query = runs_query.filter(ExperimentRun.id >= min_experiment_id)
    if max_experiment_id is not None:
        runs_query = runs_query.filter(ExperimentRun.id <= max_experiment_id)
    if judge_mode:
        runs_query = runs_query.filter(ExperimentRun.judge_mode == judge_mode)
    if profile:
        runs_query = runs_query.filter(ExperimentRun.profile == profile)
    if target_name:
        runs_query = runs_query.filter(ExperimentRun.target_name == target_name)

    runs = runs_query.order_by(ExperimentRun.id.desc()).all()
    if last_n_runs is not None:
        runs = runs[:last_n_runs]

    experiment_ids = [run.id for run in runs]
    if not experiment_ids:
        return [], {}

    results_query = db.query(ExperimentResult).filter(
        ExperimentResult.experiment_id.in_(experiment_ids)
    )
    if max_fallback_count is not None:
        results_query = results_query.filter(
            ExperimentResult.fallback_count <= max_fallback_count
        )

    results = results_query.all()
    by_experiment_id = {r.experiment_id: r for r in results}
    return runs, by_experiment_id


def _load_session_bundle(db: Session, session_id: int):
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


@router.post("/run")
def run_experiment(payload: dict, db: Session = Depends(get_db)):
    target_name = payload.get("target_name")
    target_url = payload.get("target_url")
    judge_mode = payload.get("judge_mode", "rule_based")
    max_rounds = payload.get("max_rounds", 5)
    profile = payload.get("profile", "mixed")

    if not target_name or not target_url:
        raise HTTPException(status_code=400, detail="target_name and target_url are required")

    return run_experiment_scenario(
        db=db,
        target_name=target_name,
        target_url=target_url,
        judge_mode=judge_mode,
        max_rounds=max_rounds,
        profile=profile,
    )


@router.post("/run-summary")
def run_experiment_summary(payload: dict, db: Session = Depends(get_db)):
    experiment_response = run_experiment(payload, db=db)

    export_payload = export_experiments(
        db=db,
        last_n_runs=5,
        judge_mode=experiment_response["judge_mode"],
        profile=experiment_response["profile"],
        target_name=payload.get("target_name"),
    )

    return {
        "experiment": experiment_response,
        "export_summary": export_payload["summary"],
        "recent_rows": export_payload["rows"],
    }


@router.post("/run-batch")
def run_experiment_batch(payload: dict, db: Session = Depends(get_db)):
    target_name = payload.get("target_name")
    target_url = payload.get("target_url")
    max_rounds = payload.get("max_rounds", 5)
    profile = payload.get("profile", "mixed")
    judge_modes = normalize_judge_modes(payload.get("judge_modes"))

    if not target_name or not target_url:
        raise HTTPException(status_code=400, detail="target_name and target_url are required")

    runs = []
    experiment_ids = []
    for judge_mode in judge_modes:
        result = run_experiment_scenario(
            db=db,
            target_name=target_name,
            target_url=target_url,
            judge_mode=judge_mode,
            max_rounds=max_rounds,
            profile=profile,
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
        runs=experiment_rows,
        by_experiment_id=by_experiment_id,
        filters={
            "target_name": target_name,
            "target_url": target_url,
            "profile": profile,
            "judge_modes": judge_modes,
            "max_rounds": max_rounds,
            "batch_experiment_ids": sorted(experiment_ids),
        },
    )

    return {
        "batch": {
            "target_name": target_name,
            "target_url": target_url,
            "profile": profile,
            "judge_modes": judge_modes,
            "max_rounds": max_rounds,
            "experiment_ids": sorted(experiment_ids),
            "runs_total": len(runs),
        },
        "runs": runs,
        "batch_logical_agent_summary": build_run_batch_logical_agent_summary(runs),
        "batch_logical_agent_rows": build_run_batch_logical_agent_rows(runs),
        "comparison_report": comparison_report,
    }


@router.post("/run-batch-with-reports")
def run_experiment_batch_with_reports(payload: dict, db: Session = Depends(get_db)):
    batch_response = run_experiment_batch(payload, db=db)

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
        ) = _load_session_bundle(db, session_id)

        llm_report = build_session_llm_report(
            session_obj=session_obj,
            roles=roles,
            findings=findings,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=hypotheses,
            agent_memory_rows=agent_memory_rows,
            agent_judge_feedback_rows=agent_judge_feedback_rows,
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


@router.get("/comparison")
def compare_experiments(
    db: Session = Depends(get_db),
    min_experiment_id: int | None = Query(default=None),
    max_experiment_id: int | None = Query(default=None),
    last_n_runs: int | None = Query(default=None, ge=1),
    max_fallback_count: int | None = Query(default=None, ge=0),
    judge_mode: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    target_name: str | None = Query(default=None),
):
    runs, by_experiment_id = _build_filtered_experiment_dataset(
        db=db,
        min_experiment_id=min_experiment_id,
        max_experiment_id=max_experiment_id,
        last_n_runs=last_n_runs,
        max_fallback_count=max_fallback_count,
        judge_mode=judge_mode,
        profile=profile,
        target_name=target_name,
    )
    experiment_ids = [run.id for run in runs]
    if not experiment_ids:
        return {
            "filters": {
                "min_experiment_id": min_experiment_id,
                "max_experiment_id": max_experiment_id,
                "last_n_runs": last_n_runs,
                "max_fallback_count": max_fallback_count,
                "judge_mode": judge_mode,
                "profile": profile,
                "target_name": target_name,
            },
            "summary": {},
        }

    summary = {}
    included_runs = 0

    for run in runs:
        res = by_experiment_id.get(run.id)
        if not res:
            continue

        included_runs += 1

        profile = getattr(run, "profile", "mixed")
        key = f"{run.judge_mode}:{profile}"

        summary.setdefault(key, {
            "judge_mode": run.judge_mode,
            "profile": profile,
            "runs": 0,
            "findings": 0,
            "bola": 0,
            "bopla": 0,
            "confirmed_findings": 0,
            "confirmed_bola": 0,
            "confirmed_bopla": 0,
            "fallback": 0,
            "avg_score_sum": 0.0,
        })

        summary[key]["runs"] += 1
        summary[key]["findings"] += int(res.findings_total or 0)
        summary[key]["bola"] += int(res.bola_findings or 0)
        summary[key]["bopla"] += int(res.bopla_findings or 0)
        summary[key]["confirmed_findings"] += int(getattr(res, "confirmed_findings", 0) or 0)
        summary[key]["confirmed_bola"] += int(getattr(res, "confirmed_bola", 0) or 0)
        summary[key]["confirmed_bopla"] += int(getattr(res, "confirmed_bopla", 0) or 0)
        summary[key]["fallback"] += int(res.fallback_count or 0)
        summary[key]["avg_score_sum"] += float(res.avg_score or 0)

    for key in summary:
        runs_count = summary[key]["runs"]
        summary[key]["avg_score"] = (
            summary[key]["avg_score_sum"] / runs_count if runs_count else 0
        )
        del summary[key]["avg_score_sum"]

    return {
        "filters": {
            "min_experiment_id": min_experiment_id,
            "max_experiment_id": max_experiment_id,
            "last_n_runs": last_n_runs,
            "max_fallback_count": max_fallback_count,
            "judge_mode": judge_mode,
            "profile": profile,
            "target_name": target_name,
        },
        "totals": {
            "candidate_runs": len(runs),
            "included_runs": included_runs,
        },
        "summary": summary,
    }


@router.get("/diploma-summary")
def diploma_experiment_summary(
    db: Session = Depends(get_db),
    min_experiment_id: int | None = Query(default=None),
    max_experiment_id: int | None = Query(default=None),
    last_n_runs: int | None = Query(default=None, ge=1),
    max_fallback_count: int | None = Query(default=None, ge=0),
    judge_mode: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    target_name: str | None = Query(default=None),
):
    filters = {
        "min_experiment_id": min_experiment_id,
        "max_experiment_id": max_experiment_id,
        "last_n_runs": last_n_runs,
        "max_fallback_count": max_fallback_count,
        "judge_mode": judge_mode,
        "profile": profile,
        "target_name": target_name,
    }
    runs, by_experiment_id = _build_filtered_experiment_dataset(
        db=db,
        min_experiment_id=min_experiment_id,
        max_experiment_id=max_experiment_id,
        last_n_runs=last_n_runs,
        max_fallback_count=max_fallback_count,
        judge_mode=judge_mode,
        profile=profile,
        target_name=target_name,
    )
    return build_experiment_comparison_report(
        runs=runs,
        by_experiment_id=by_experiment_id,
        filters=filters,
    )


@router.get("/diploma-summary/markdown")
def diploma_experiment_summary_markdown(
    db: Session = Depends(get_db),
    min_experiment_id: int | None = Query(default=None),
    max_experiment_id: int | None = Query(default=None),
    last_n_runs: int | None = Query(default=None, ge=1),
    max_fallback_count: int | None = Query(default=None, ge=0),
    judge_mode: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    target_name: str | None = Query(default=None),
):
    report = diploma_experiment_summary(
        db=db,
        min_experiment_id=min_experiment_id,
        max_experiment_id=max_experiment_id,
        last_n_runs=last_n_runs,
        max_fallback_count=max_fallback_count,
        judge_mode=judge_mode,
        profile=profile,
        target_name=target_name,
    )
    markdown = build_experiment_comparison_markdown(report)
    return Response(content=markdown, media_type="text/markdown; charset=utf-8")


@router.get("/export")
def export_experiments(
    db: Session = Depends(get_db),
    min_experiment_id: int | None = Query(default=None),
    max_experiment_id: int | None = Query(default=None),
    last_n_runs: int | None = Query(default=None, ge=1),
    max_fallback_count: int | None = Query(default=None, ge=0),
    judge_mode: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    target_name: str | None = Query(default=None),
):
    runs, by_experiment_id = _build_filtered_experiment_dataset(
        db=db,
        min_experiment_id=min_experiment_id,
        max_experiment_id=max_experiment_id,
        last_n_runs=last_n_runs,
        max_fallback_count=max_fallback_count,
        judge_mode=judge_mode,
        profile=profile,
        target_name=target_name,
    )

    rows = []
    summary = {}

    for run in runs:
        res = by_experiment_id.get(run.id)
        if not res:
            continue

        row = {
            "experiment_id": run.id,
            "created_at": str(getattr(run, "created_at", "")),
            "judge_mode": run.judge_mode,
            "profile": getattr(run, "profile", "mixed"),
            "target_name": run.target_name,
            "target_url": run.target_url,
            "max_rounds": run.max_rounds,
            "total_rounds": getattr(res, "total_rounds", None),
            "findings_total": int(res.findings_total or 0),
            "bola_findings": int(res.bola_findings or 0),
            "bopla_findings": int(res.bopla_findings or 0),
            "confirmed_findings": int(getattr(res, "confirmed_findings", 0) or 0),
            "confirmed_bola": int(getattr(res, "confirmed_bola", 0) or 0),
            "confirmed_bopla": int(getattr(res, "confirmed_bopla", 0) or 0),
            "judge_decisions": int(getattr(res, "judge_decisions", 0) or 0),
            "fallback_count": int(res.fallback_count or 0),
            "avg_score": float(res.avg_score or 0),
        }
        rows.append(row)

        key = f"{row['judge_mode']}:{row['profile']}"
        summary.setdefault(key, {
            "judge_mode": row["judge_mode"],
            "profile": row["profile"],
            "runs": 0,
            "findings": 0,
            "bola": 0,
            "bopla": 0,
            "confirmed_findings": 0,
            "confirmed_bola": 0,
            "confirmed_bopla": 0,
            "fallback": 0,
            "avg_score_sum": 0.0,
        })
        summary[key]["runs"] += 1
        summary[key]["findings"] += row["findings_total"]
        summary[key]["bola"] += row["bola_findings"]
        summary[key]["bopla"] += row["bopla_findings"]
        summary[key]["confirmed_findings"] += row["confirmed_findings"]
        summary[key]["confirmed_bola"] += row["confirmed_bola"]
        summary[key]["confirmed_bopla"] += row["confirmed_bopla"]
        summary[key]["fallback"] += row["fallback_count"]
        summary[key]["avg_score_sum"] += row["avg_score"]

    for key in summary:
        runs_count = summary[key]["runs"]
        summary[key]["avg_score"] = (
            summary[key]["avg_score_sum"] / runs_count if runs_count else 0
        )
        del summary[key]["avg_score_sum"]

    return {
        "filters": {
            "min_experiment_id": min_experiment_id,
            "max_experiment_id": max_experiment_id,
            "last_n_runs": last_n_runs,
            "max_fallback_count": max_fallback_count,
            "judge_mode": judge_mode,
            "profile": profile,
            "target_name": target_name,
        },
        "count": len(rows),
        "rows": rows,
        "summary": summary,
    }


@router.get("/export.csv")
def export_experiments_csv(
    db: Session = Depends(get_db),
    min_experiment_id: int | None = Query(default=None),
    max_experiment_id: int | None = Query(default=None),
    last_n_runs: int | None = Query(default=None, ge=1),
    max_fallback_count: int | None = Query(default=None, ge=0),
    judge_mode: str | None = Query(default=None),
    profile: str | None = Query(default=None),
    target_name: str | None = Query(default=None),
    view: str = Query(default="rows"),
):
    payload = export_experiments(
        db=db,
        min_experiment_id=min_experiment_id,
        max_experiment_id=max_experiment_id,
        last_n_runs=last_n_runs,
        max_fallback_count=max_fallback_count,
        judge_mode=judge_mode,
        profile=profile,
        target_name=target_name,
    )

    rows = payload["rows"]
    summary = payload["summary"]

    buffer = io.StringIO()
    writer = csv.writer(buffer)

    if view == "summary":
        writer.writerow([
            "judge_mode",
            "profile",
            "runs",
            "findings",
            "bola",
            "bopla",
            "confirmed_findings",
            "confirmed_bola",
            "confirmed_bopla",
            "fallback",
            "avg_score",
        ])
        for item in summary.values():
            writer.writerow([
                item["judge_mode"],
                item["profile"],
                item["runs"],
                item["findings"],
                item["bola"],
                item["bopla"],
                item["confirmed_findings"],
                item["confirmed_bola"],
                item["confirmed_bopla"],
                item["fallback"],
                item["avg_score"],
            ])
        filename = "experiments_summary.csv"
    else:
        writer.writerow([
            "experiment_id",
            "created_at",
            "judge_mode",
            "profile",
            "target_name",
            "target_url",
            "max_rounds",
            "total_rounds",
            "findings_total",
            "bola_findings",
            "bopla_findings",
            "confirmed_findings",
            "confirmed_bola",
            "confirmed_bopla",
            "judge_decisions",
            "fallback_count",
            "avg_score",
        ])
        for row in rows:
            writer.writerow([
                row["experiment_id"],
                row["created_at"],
                row["judge_mode"],
                row["profile"],
                row["target_name"],
                row["target_url"],
                row["max_rounds"],
                row["total_rounds"],
                row["findings_total"],
                row["bola_findings"],
                row["bopla_findings"],
                row["confirmed_findings"],
                row["confirmed_bola"],
                row["confirmed_bopla"],
                row["judge_decisions"],
                row["fallback_count"],
                row["avg_score"],
            ])
        filename = "experiments_rows.csv"

    return Response(
        content=buffer.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        },
    )
