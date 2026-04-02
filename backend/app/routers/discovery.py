from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, SurfaceInventory
from ..schemas import RunSpiderRequest, ParseOpenAPIRequest
from ..services.discovery_service import classify_asset, persist_discovery_results, save_openapi_endpoints
from ..services.openapi_service import fetch_openapi_document, parse_openapi_spec, find_openapi_document
from ..services.zap_service import run_spider_and_wait, run_ajax_spider_and_wait

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@router.post("/run-spider")
def run_spider(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    results = run_spider_and_wait(session.target_url)
    urls = results.get("urls", [])
    persisted = persist_discovery_results(
        db=db,
        session_obj=session,
        urls=urls,
        source_type="zap_spider",
        confidence=0.7,
    )

    return {
        "session_id": session.id,
        "saved_urls": persisted["saved_urls"],
        "source_type": "zap_spider",
        "urls": persisted["scoped_urls"][:20],
        "api_urls": persisted["api_urls"][:20],
        "js_discovered_urls": persisted["js_discovered_urls"][:20],
    }


@router.post("/run-ajax-spider")
def run_ajax_spider(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    results = run_ajax_spider_and_wait(session.target_url)
    urls = results.get("urls", [])
    persisted = persist_discovery_results(
        db=db,
        session_obj=session,
        urls=urls,
        source_type="zap_ajax_spider",
        confidence=0.75,
    )

    return {
        "session_id": session.id,
        "saved_urls": persisted["saved_urls"],
        "source_type": "zap_ajax_spider",
        "urls": persisted["scoped_urls"][:20],
        "api_urls": persisted["api_urls"][:20],
        "js_discovered_urls": persisted["js_discovered_urls"][:20],
    }


@router.post("/parse-openapi")
def parse_openapi(payload: ParseOpenAPIRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    spec = fetch_openapi_document(payload.openapi_url)
    endpoints = parse_openapi_spec(spec)

    saved = save_openapi_endpoints(db, session.id, endpoints, source_type="openapi")
    db.commit()

    return {
        "session_id": session.id,
        "saved_endpoints": saved,
        "sample": endpoints[:10]
    }


@router.post("/discover-openapi")
def discover_openapi(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    openapi_url, spec = find_openapi_document(session.target_url)
    if not openapi_url or not spec:
        return {
            "session_id": session.id,
            "discovered": False,
            "saved_endpoints": 0,
            "openapi_url": None,
            "sample": [],
        }

    endpoints = parse_openapi_spec(spec)
    saved = save_openapi_endpoints(db, session.id, endpoints, source_type="openapi_autodiscovery")
    session.status = "discovered"
    db.commit()

    return {
        "session_id": session.id,
        "discovered": True,
        "saved_endpoints": saved,
        "openapi_url": openapi_url,
        "sample": endpoints[:10],
    }


@router.get("/inventory/{session_id}")
def get_inventory(session_id: int, db: Session = Depends(get_db)):
    items = db.query(SurfaceInventory).filter(SurfaceInventory.session_id == session_id).all()
    return items


@router.get("/inventory/{session_id}/api")
def get_api_inventory(session_id: int, db: Session = Depends(get_db)):
    items = db.query(SurfaceInventory).filter(
        SurfaceInventory.session_id == session_id,
        SurfaceInventory.asset_type == "api"
    ).all()
    return items
