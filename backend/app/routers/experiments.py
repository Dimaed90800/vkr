from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
import requests

from ..db import SessionLocal
from ..models import ExperimentRun, ExperimentResult

router = APIRouter(prefix="/experiments", tags=["experiments"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _post(url: str, payload: dict, timeout: int = 60):
    resp = requests.post(url, json=payload, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Request failed: {url} -> {resp.status_code} {resp.text}"
        )
    return resp.json()


def _get(url: str, timeout: int = 60):
    resp = requests.get(url, timeout=timeout)
    if resp.status_code != 200:
        raise HTTPException(
            status_code=500,
            detail=f"Request failed: {url} -> {resp.status_code} {resp.text}"
        )
    return resp.json()


def _bootstrap_session(session_id: int):
    # 1. Создаём роли
    _post("http://localhost:8000/roles/create", {
        "session_id": session_id,
        "role_name": "user_a"
    })
    _post("http://localhost:8000/roles/create", {
        "session_id": session_id,
        "role_name": "user_b"
    })

    # 2. Регистрируем роли
    _post("http://localhost:8000/roles/register", {
        "session_id": session_id,
        "role_name": "user_a"
    })
    _post("http://localhost:8000/roles/register", {
        "session_id": session_id,
        "role_name": "user_b"
    })

    # 3. Логиним роли
    _post("http://localhost:8000/roles/login", {
        "session_id": session_id,
        "role_name": "user_a"
    })
    _post("http://localhost:8000/roles/login", {
        "session_id": session_id,
        "role_name": "user_b"
    })

    # 4. Seed observation: recent posts
    _post("http://localhost:8000/observations/probe", {
        "session_id": session_id,
        "role_name": "user_a",
        "endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
        "method": "GET",
        "use_role_token": True
    })


@router.post("/run")
def run_experiment(payload: dict, db: Session = Depends(get_db)):
    target_name = payload.get("target_name")
    target_url = payload.get("target_url")
    judge_mode = payload.get("judge_mode", "rule_based")
    max_rounds = payload.get("max_rounds", 5)

    if not target_name or not target_url:
        raise HTTPException(status_code=400, detail="target_name and target_url are required")

    experiment = ExperimentRun(
        target_name=target_name,
        target_url=target_url,
        judge_mode=judge_mode,
        max_rounds=max_rounds
    )
    db.add(experiment)
    db.commit()
    db.refresh(experiment)

    # 1. create session
    session_data = _post("http://localhost:8000/session/create", {
        "target_name": target_name,
        "target_url": target_url
    })
    session_id = session_data["id"]

    # 2. bootstrap
    _bootstrap_session(session_id)

    fallback_count = 0
    scores = []

    # 3. rounds
    for _ in range(max_rounds):
        step = _post("http://localhost:8000/campaign/step", {
            "session_id": session_id,
            "judge_mode": judge_mode
        })

        judge = step.get("judge", {})

        try:
            scores.append(float(judge.get("priority_score", 0)))
        except (TypeError, ValueError):
            scores.append(0)

        reasoning = str(judge.get("reasoning_summary", ""))
        if "Fallback" in reasoning or "fallback" in reasoning:
            fallback_count += 1

    # 4. metrics
    metrics = _get(f"http://localhost:8000/metrics/session/{session_id}")["metrics"]

    result = ExperimentResult(
        experiment_id=experiment.id,
        total_rounds=max_rounds,
        findings_total=metrics["findings_total"],
        bola_findings=metrics["bola_findings"],
        judge_decisions=metrics["judge_decisions"],
        fallback_count=fallback_count,
        avg_score=(sum(scores) / len(scores)) if scores else 0
    )

    db.add(result)
    db.commit()
    db.refresh(result)

    return {
        "experiment_id": experiment.id,
        "session_id": session_id,
        "result": {
            "findings_total": result.findings_total,
            "bola_findings": result.bola_findings,
            "fallback_count": result.fallback_count,
            "avg_score": result.avg_score
        }
    }


@router.get("/comparison")
def compare_experiments(db: Session = Depends(get_db)):
    runs = db.query(ExperimentRun).all()
    results = db.query(ExperimentResult).all()

    by_experiment_id = {r.experiment_id: r for r in results}
    summary = {}

    for run in runs:
        res = by_experiment_id.get(run.id)
        if not res:
            continue

        mode = run.judge_mode
        summary.setdefault(mode, {
            "runs": 0,
            "findings": 0,
            "bola": 0,
            "fallback": 0,
            "avg_score_sum": 0.0,
        })

        summary[mode]["runs"] += 1
        summary[mode]["findings"] += res.findings_total
        summary[mode]["bola"] += res.bola_findings
        summary[mode]["fallback"] += res.fallback_count
        summary[mode]["avg_score_sum"] += float(res.avg_score or 0)

    for mode in summary:
        runs_count = summary[mode]["runs"]
        summary[mode]["avg_score"] = summary[mode]["avg_score_sum"] / runs_count if runs_count else 0
        del summary[mode]["avg_score_sum"]

    return summary