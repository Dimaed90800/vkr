from __future__ import annotations

import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import AutomationJob
from .experiment_batch_service import (
    build_run_batch_with_reports_response,
    export_batch_job_artifacts,
    get_jobs_export_root,
)


def _serialize_job(job: AutomationJob) -> dict[str, Any]:
    result = {}
    if job.result_json:
        try:
            result = json.loads(job.result_json)
        except Exception:
            result = {}

    return {
        "job_id": job.job_id,
        "job_type": job.job_type,
        "status": job.status,
        "artifact_dir": job.artifact_dir,
        "error_text": job.error_text,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "started_at": job.started_at.isoformat() if job.started_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
        "result": result if job.status == "finished" else None,
    }


def create_batch_job(db: Session, payload: dict[str, Any]) -> dict[str, Any]:
    job = AutomationJob(
        job_id=f"batch-{uuid.uuid4().hex[:12]}",
        job_type="batch_experiments",
        status="queued",
        payload_json=json.dumps(payload, ensure_ascii=False),
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return _serialize_job(job)


def get_job(db: Session, job_id: str) -> AutomationJob | None:
    return db.query(AutomationJob).filter(AutomationJob.job_id == job_id).first()


def get_job_response(db: Session, job_id: str) -> dict[str, Any] | None:
    job = get_job(db, job_id)
    if not job:
        return None
    return _serialize_job(job)


def _run_batch_job(job_id: str) -> None:
    db = SessionLocal()
    try:
        job = get_job(db, job_id)
        if not job:
            return

        payload = {}
        if job.payload_json:
            try:
                payload = json.loads(job.payload_json)
            except Exception:
                payload = {}

        job.status = "running"
        job.started_at = datetime.utcnow()
        db.commit()

        job_export_root = get_jobs_export_root() / job_id
        reports_export_root = job_export_root / "reports"
        batch_result = build_run_batch_with_reports_response(
            db,
            payload,
            reports_export_root=reports_export_root,
        )
        artifact_paths = export_batch_job_artifacts(
            job_id=job_id,
            batch_result=batch_result,
            export_root=get_jobs_export_root(),
        )

        job.result_json = json.dumps(
            {
                **batch_result,
                "artifact_paths": artifact_paths,
            },
            ensure_ascii=False,
        )
        job.artifact_dir = artifact_paths.get("job_dir")
        job.status = "finished"
        job.finished_at = datetime.utcnow()
        db.commit()
    except Exception as exc:
        job = get_job(db, job_id)
        if job:
            job.status = "failed"
            job.error_text = str(exc)
            job.finished_at = datetime.utcnow()
            db.commit()
    finally:
        db.close()


def start_batch_job(job_id: str) -> None:
    thread = threading.Thread(target=_run_batch_job, args=(job_id,), daemon=True)
    thread.start()
