from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..schemas import (
    AgenticJudgeVerdictRequest,
    AgenticPrepareAuthRequest,
    AgenticPrepareProbeRequest,
    AgenticRunRoundRequest,
    AgenticWorkerResultRequest,
    CampaignStepRequest,
    CreateSessionRequest,
)
from ..schemas import AgenticToolCommandRequest
from ..services.agentic_auth_service import prepare_auth_state
from ..services.agentic_judge_service import apply_judge_verdict, build_judge_package, ingest_worker_result
from ..services.agentic_probe_service import prepare_probe_seeds
from ..services.agentic_api_service import (
    build_agentic_judge_state,
    build_agentic_loop_state,
    build_agentic_orchestrator_plan,
    build_agentic_report_package,
    build_agentic_router_plan,
    start_agentic_session,
)
from ..services.agentic_tool_service import build_agentic_session_context, execute_agentic_tool_command
from ..services.agentic_worker_service import build_worker_task_bundle

router = APIRouter(prefix="/agentic", tags=["agentic"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/start")
def start_agentic(payload: CreateSessionRequest, db: Session = Depends(get_db)):
    if not payload.user_prompt:
        raise HTTPException(status_code=400, detail="user_prompt is required for agentic start")

    return start_agentic_session(
        db,
        target_name=payload.target_name,
        target_url=payload.target_url,
        user_prompt=payload.user_prompt,
        budget_requests_total=payload.budget_requests_total,
        budget_time_total=payload.budget_time_total,
        max_rounds=payload.max_rounds,
        allowed_test_classes=payload.allowed_test_classes,
        enabled_agents=payload.enabled_agents,
        strategy_config=payload.strategy_config,
    )


@router.get("/session/{session_id}/router-plan")
def get_router_plan(session_id: int, db: Session = Depends(get_db)):
    payload = build_agentic_router_plan(db, session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return payload


@router.get("/session/{session_id}/orchestrator-plan")
def get_orchestrator_plan(session_id: int, db: Session = Depends(get_db)):
    payload = build_agentic_orchestrator_plan(db, session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return payload


@router.get("/session/{session_id}/context")
def get_session_context(session_id: int, db: Session = Depends(get_db)):
    return build_agentic_session_context(db, session_id)


@router.get("/session/{session_id}/worker-tasks/{worker_family}")
def get_worker_tasks(session_id: int, worker_family: str, db: Session = Depends(get_db)):
    return build_worker_task_bundle(db, session_id, worker_family)


@router.get("/session/{session_id}/judge-state")
def get_judge_state(session_id: int, db: Session = Depends(get_db)):
    payload = build_agentic_judge_state(db, session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return payload


@router.get("/session/{session_id}/judge-package/{finding_id}")
def get_judge_package(session_id: int, finding_id: int, db: Session = Depends(get_db)):
    return build_judge_package(db, session_id=session_id, finding_id=finding_id)


@router.get("/session/{session_id}/loop-state")
def get_loop_state(session_id: int, db: Session = Depends(get_db)):
    payload = build_agentic_loop_state(db, session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return payload


@router.get("/session/{session_id}/report-package")
def get_report_package(session_id: int, db: Session = Depends(get_db)):
    payload = build_agentic_report_package(db, session_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return payload


@router.post("/tools/execute")
def execute_tool(payload: AgenticToolCommandRequest, db: Session = Depends(get_db)):
    result = execute_agentic_tool_command(
        db,
        tool_name=payload.tool_name,
        arguments=payload.arguments,
    )
    return {
        "tool_name": payload.tool_name,
        "status": "ok",
        "result": result,
    }


@router.post("/session/{session_id}/worker-result")
def save_worker_result(
    session_id: int,
    payload: AgenticWorkerResultRequest,
    db: Session = Depends(get_db),
):
    return ingest_worker_result(
        db,
        session_id=session_id,
        worker_type=payload.worker_type,
        tool_name=payload.tool_name,
        result=payload.result,
        task_id=payload.task_id,
        vulnerability_class=payload.vulnerability_class,
    )


@router.post("/session/{session_id}/judge-verdict")
def save_judge_verdict(
    session_id: int,
    payload: AgenticJudgeVerdictRequest,
    db: Session = Depends(get_db),
):
    return apply_judge_verdict(
        db,
        session_id=session_id,
        finding_id=payload.finding_id,
        status=payload.status,
        reason=payload.reason,
        finding_type=payload.finding_type,
        next_action=payload.next_action,
    )


@router.post("/session/{session_id}/prepare-auth")
def prepare_auth(
    session_id: int,
    payload: AgenticPrepareAuthRequest,
    db: Session = Depends(get_db),
):
    return prepare_auth_state(
        db,
        session_id,
        max_steps=payload.max_steps or 6,
    )


@router.post("/session/{session_id}/prepare-probe-seeds")
def prepare_probe_state(
    session_id: int,
    payload: AgenticPrepareProbeRequest,
    db: Session = Depends(get_db),
):
    return prepare_probe_seeds(
        db,
        session_id,
        max_steps=payload.max_steps or 4,
    )


@router.post("/session/{session_id}/run-round")
def run_round(
    session_id: int,
    payload: AgenticRunRoundRequest,
    db: Session = Depends(get_db),
):
    from .campaign import campaign_step

    return campaign_step(
        CampaignStepRequest(
            session_id=session_id,
            judge_mode="agentic",
            user_prompt=payload.user_prompt,
        ),
        db,
    )
