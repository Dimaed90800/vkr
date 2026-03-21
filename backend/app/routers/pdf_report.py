from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..db import SessionLocal
from ..models import TestSession, Finding

router = APIRouter(prefix="/pdf-report", tags=["report"])


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@router.get("/session/{session_id}")
def generate_pdf(session_id: int, db: Session = Depends(get_db)):
    # Локальный импорт, чтобы backend не падал при старте,
    # если reportlab ещё не установлен
    try:
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
        from reportlab.lib.styles import getSampleStyleSheet
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="reportlab is not installed in backend container"
        )

    session = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    findings = db.query(Finding).filter(Finding.session_id == session_id).all()

    file_path = f"/tmp/report_session_{session_id}.pdf"

    doc = SimpleDocTemplate(file_path)
    styles = getSampleStyleSheet()
    content = []

    content.append(Paragraph("Pentest Report", styles["Title"]))
    content.append(Spacer(1, 10))

    content.append(Paragraph(f"Target: {session.target_name}", styles["Normal"]))
    content.append(Paragraph(f"Base URL: {session.target_url}", styles["Normal"]))
    content.append(Spacer(1, 10))

    content.append(Paragraph("Findings:", styles["Heading2"]))

    for f in findings:
        content.append(Spacer(1, 8))
        content.append(Paragraph(f"Type: {f.finding_type}", styles["Normal"]))
        content.append(Paragraph(f"Severity: {f.severity}", styles["Normal"]))
        content.append(Paragraph(f"Endpoint: {f.endpoint}", styles["Normal"]))
        content.append(Paragraph(f"Description: {f.description}", styles["Normal"]))

    doc.build(content)

    return FileResponse(file_path, filename=f"report_{session_id}.pdf")