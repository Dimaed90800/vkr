import json
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, SurfaceInventory
from ..schemas import RunSpiderRequest, ParseOpenAPIRequest
from ..services.zap_service import run_spider_and_wait
from ..services.openapi_service import fetch_openapi_document, parse_openapi_spec

router = APIRouter()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def classify_asset(url_or_path: str) -> str:
    value = url_or_path.lower()

    static_suffixes = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".map", ".txt", ".xml"
    )

    if value.endswith(static_suffixes):
        return "static"

    if "/api/" in value:
        return "api"

    if any(x in value for x in ["/static", "/images", "/assets", "/fonts"]):
        return "static"

    parsed = urlparse(value)
    path = parsed.path if parsed.scheme else value

    if path in ("", "/"):
        return "frontend"

    return "unknown"


@router.post("/run-spider")
def run_spider(payload: RunSpiderRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    results = run_spider_and_wait(session.target_url)
    urls = results.get("urls", [])

    saved = 0
    for url in urls:
        item = SurfaceInventory(
            session_id=session.id,
            path=url,
            method="GET",
            source_type="zap_spider",
            asset_type=classify_asset(url),
            confidence=0.7,
            raw_json=url
        )
        db.add(item)
        saved += 1

    session.status = "discovered"
    db.commit()

    return {
        "session_id": session.id,
        "saved_urls": saved,
        "urls": urls[:20]
    }


@router.post("/parse-openapi")
def parse_openapi(payload: ParseOpenAPIRequest, db: Session = Depends(get_db)):
    session = db.query(TestSession).filter(TestSession.id == payload.session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    spec = fetch_openapi_document(payload.openapi_url)
    endpoints = parse_openapi_spec(spec)

    saved = 0
    for ep in endpoints:
        item = SurfaceInventory(
            session_id=session.id,
            path=ep["path"],
            method=ep["method"],
            source_type="openapi",
            asset_type="api",
            confidence=0.95,
            content_type=ep["content_type"],
            auth_hint=ep["auth_hint"],
            parameters_json=json.dumps(ep["parameters"], ensure_ascii=False),
            raw_json=json.dumps(ep["raw"], ensure_ascii=False)
        )
        db.add(item)
        saved += 1

    db.commit()

    return {
        "session_id": session.id,
        "saved_endpoints": saved,
        "sample": endpoints[:10]
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