"""Phase Report-0 — report-context routes."""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

try:
    from backend.models.report_context import ReportContextRequest
    from backend.services.report_artifact_writer import ReportArtifactWriter
    from backend.services.report_context_builder import ReportContextBuilder
except ModuleNotFoundError:  # pragma: no cover
    from models.report_context import ReportContextRequest
    from services.report_artifact_writer import ReportArtifactWriter
    from services.report_context_builder import ReportContextBuilder


reports_router = APIRouter(prefix="/v1/reports", tags=["reports"])
_builder = ReportContextBuilder()
_artifact_writer = ReportArtifactWriter()


@reports_router.get("/{campaign_id}/context")
async def get_report_context(campaign_id: str) -> JSONResponse:
    context, error = _builder.build(campaign_id=campaign_id, runtime_state_snapshot=None)
    if error == "campaign_not_found":
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found", "message": f"Campaign '{campaign_id}' not found."},
        )
    return JSONResponse(status_code=200, content=context)


@reports_router.post("/{campaign_id}/context")
async def post_report_context(campaign_id: str, body: ReportContextRequest) -> JSONResponse:
    context, error = _builder.build(
        campaign_id=campaign_id,
        runtime_state_snapshot=body.runtime_state_snapshot,
    )
    if error == "campaign_not_found":
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found", "message": f"Campaign '{campaign_id}' not found."},
        )
    return JSONResponse(status_code=200, content=context)


@reports_router.post("/{campaign_id}/write-artifacts")
async def write_report_artifacts(campaign_id: str, body: ReportContextRequest) -> JSONResponse:
    result = _artifact_writer.write(
        campaign_id=campaign_id,
        runtime_state_snapshot=body.runtime_state_snapshot,
    )
    if result.get("error") == "campaign_not_found":
        return JSONResponse(
            status_code=404,
            content={"error": "campaign_not_found", "message": f"Campaign '{campaign_id}' not found."},
        )
    return JSONResponse(status_code=200, content=result)
