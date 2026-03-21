from fastapi import FastAPI
from .db import Base, engine
from .routers import (
    session,
    discovery,
    observations,
    hypotheses,
    judge,
    campaign,
    roles,
    analysis,
    bola,
    vehicles,
    findings,
    report,
    metrics,
    experiments
    # pdf_report
)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="REST API Agentic Pentest Backend")

app.include_router(session.router, prefix="/session", tags=["session"])
app.include_router(discovery.router, prefix="/discovery", tags=["discovery"])
app.include_router(observations.router, prefix="/observations", tags=["observations"])
app.include_router(hypotheses.router, prefix="/hypotheses", tags=["hypotheses"])
app.include_router(judge.router, prefix="/judge", tags=["judge"])
app.include_router(campaign.router, prefix="/campaign", tags=["campaign"])
app.include_router(roles.router, prefix="/roles", tags=["roles"])
app.include_router(analysis.router, prefix="/analysis", tags=["analysis"])
app.include_router(bola.router, prefix="/bola", tags=["bola"])
app.include_router(vehicles.router, prefix="/vehicles", tags=["vehicles"])
app.include_router(findings.router, prefix="/findings", tags=["findings"])
app.include_router(report.router, prefix="/report", tags=["report"])
app.include_router(metrics.router)
# app.include_router(pdf_report.router)
app.include_router(experiments.router)