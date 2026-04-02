from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import Observation, RoleCredential, TestSession
from ..schemas import ProbeRequest, ParseOpenAPIRequest, RunSpiderRequest
from ..services.analysis_service import compare_observations
from ..services.bola_service import infer_bola_from_observations
from ..services.bopla_service import analyze_bopla_observation
from ..services.http_service import send_request
from ..services.openapi_service import fetch_openapi_document, parse_openapi_spec, find_openapi_document
from ..services.zap_service import run_ajax_spider_and_wait, run_spider_and_wait

router = APIRouter(prefix="/tools", tags=["tools"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.post("/parse-openapi")
def parse_openapi_tool(payload: ParseOpenAPIRequest):
    spec = fetch_openapi_document(payload.openapi_url)
    return {
        "session_id": payload.session_id,
        "tool": "parse_openapi",
        "endpoints": parse_openapi_spec(spec),
    }


@router.post("/discover-openapi")
def discover_openapi_tool(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    openapi_url, spec = find_openapi_document(session.target_url)
    if not openapi_url or not spec:
        return {
            "session_id": payload.session_id,
            "tool": "discover_openapi",
            "discovered": False,
            "openapi_url": None,
            "result": [],
        }

    return {
        "session_id": payload.session_id,
        "tool": "discover_openapi",
        "discovered": True,
        "openapi_url": openapi_url,
        "result": parse_openapi_spec(spec),
    }


@router.post("/run-zap-spider")
def run_zap_spider_tool(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": payload.session_id,
        "tool": "run_zap_spider",
        "result": run_spider_and_wait(session.target_url),
    }


@router.post("/run-zap-ajax-spider")
def run_zap_ajax_spider_tool(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": payload.session_id,
        "tool": "run_zap_ajax_spider",
        "result": run_ajax_spider_and_wait(session.target_url),
    }


@router.post("/send-api-request")
def send_api_request_tool(payload: ProbeRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    final_headers = dict(payload.headers or {})
    if payload.use_role_token:
        if not payload.role_name:
            raise HTTPException(status_code=400, detail="role_name is required when use_role_token=true")
        role = db.query(RoleCredential).filter(
            RoleCredential.session_id == payload.session_id,
            RoleCredential.role_name == payload.role_name
        ).first()
        if not role or not role.access_token:
            raise HTTPException(status_code=400, detail="Role token unavailable")
        final_headers["Authorization"] = f"{role.token_type or 'Bearer'} {role.access_token}"

    result = send_request(
        method=payload.method,
        url=payload.endpoint,
        headers=final_headers,
        params=payload.params,
        json_body=payload.json_body,
    )
    return {
        "session_id": payload.session_id,
        "tool": "send_api_request",
        "result": result,
    }


@router.get("/compare-observations/{observation_a_id}/{observation_b_id}")
def compare_observations_tool(observation_a_id: int, observation_b_id: int, db: Session = Depends(get_db)):
    obs_a = db.query(Observation).filter(Observation.id == observation_a_id).first()
    obs_b = db.query(Observation).filter(Observation.id == observation_b_id).first()
    if not obs_a or not obs_b:
        raise HTTPException(status_code=404, detail="One or both observations not found")
    return {
        "tool": "compare_observations",
        "result": compare_observations(obs_a, obs_b),
    }


@router.get("/bola-infer/{owner_observation_id}/{other_observation_id}")
def bola_infer_tool(owner_observation_id: int, other_observation_id: int, db: Session = Depends(get_db)):
    obs_owner = db.query(Observation).filter(Observation.id == owner_observation_id).first()
    obs_other = db.query(Observation).filter(Observation.id == other_observation_id).first()
    if not obs_owner or not obs_other:
        raise HTTPException(status_code=404, detail="Observations not found")
    return {
        "tool": "bola_infer",
        "result": infer_bola_from_observations(obs_owner, obs_other),
    }


@router.get("/bopla-infer/{observation_id}")
def bopla_infer_tool(observation_id: int, db: Session = Depends(get_db)):
    observation = db.query(Observation).filter(Observation.id == observation_id).first()
    if not observation:
        raise HTTPException(status_code=404, detail="Observation not found")
    return {
        "tool": "bopla_infer",
        "result": analyze_bopla_observation(observation),
    }
