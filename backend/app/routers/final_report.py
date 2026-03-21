from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import Session as SessionModel, Finding

router = APIRouter(prefix="/final-report", tags=["report"])


@router.get("/session/{session_id}")
def final_report(session_id: int, db: Session = Depends(get_db)):
    session = db.query(SessionModel).filter_by(id=session_id).first()

    findings = db.query(Finding).filter_by(session_id=session_id).all()

    return {
        "session_id": session_id,
        "target": session.target_name,
        "base_url": session.base_url,
        "risk_summary": {
            "total_findings": len(findings),
            "high": sum(1 for f in findings if f.severity == "high"),
            "medium": sum(1 for f in findings if f.severity == "medium"),
            "low": sum(1 for f in findings if f.severity == "low"),
        },
        "findings": [
            {
                "type": f.type,
                "severity": f.severity,
                "endpoint": f.endpoint,
                "description": f.description,
            }
            for f in findings
        ]
    }