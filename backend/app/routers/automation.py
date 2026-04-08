from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..services.automation_job_service import (
    create_batch_job,
    get_job_response,
    start_batch_job,
)

router = APIRouter(prefix="/automation", tags=["automation"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/run-batch-job")
def run_batch_job(payload: dict, db: Session = Depends(get_db)):
    job = create_batch_job(db, payload)
    start_batch_job(job["job_id"])
    return job


@router.get("/jobs/{job_id}")
def get_automation_job(job_id: str, db: Session = Depends(get_db)):
    job = get_job_response(db, job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Automation job {job_id} not found")
    return job
