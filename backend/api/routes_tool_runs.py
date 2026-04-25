"""Phase 5 — ToolRun lifecycle routes.

POST /v1/tools/runs/start           — validate + execute or start async
GET  /v1/tools/runs/{tool_run_id}   — poll ToolRun status
POST /v1/tools/runs/{tool_run_id}/collect — collect finished ToolResult
"""
from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from backend.models.tool_run import ToolRunStartRequest, ToolRunStartResponse
from backend.models.worker_command import WorkerCommand
from backend.services.command_validator import CommandValidator
from backend.services.tool_executor import ToolExecutor, ToolExecutorStartError
from backend.services.tool_registry import ToolRegistry

tool_runs_router = APIRouter(prefix="/v1/tools/runs", tags=["tool-runs"])

_executor = ToolExecutor()
_registry = ToolRegistry()
_validator = CommandValidator()


@tool_runs_router.post("/start")
async def start_tool_run(body: ToolRunStartRequest) -> JSONResponse:
    command = WorkerCommand.model_validate(body.command)

    validation = _validator.validate(command)
    if not validation.valid:
        return JSONResponse(
            status_code=400,
            content=validation.model_dump(mode="json"),
        )

    execution_mode = _registry.resolve_execution_mode(
        command.tool_name, body.execution_mode,
    )

    if execution_mode == "sync":
        result = _executor.execute_sync(command)
        resp = ToolRunStartResponse(
            tool_run_id=result.tool_run_id,
            campaign_id=result.campaign_id,
            task_id=result.task_id,
            command_id=result.command_id,
            tool_name=result.tool_name,
            execution_mode="sync",
            status=result.status,
            result=result,
        )
        return JSONResponse(status_code=201, content=resp.model_dump(mode="json"))

    try:
        run = _executor.start_async(command)
    except ToolExecutorStartError as exc:
        if exc.code == "validation_failed" and exc.validation is not None:
            return JSONResponse(
                status_code=exc.status_code,
                content=exc.validation.model_dump(mode="json"),
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={"error": exc.code, "message": exc.message},
        )
    resp = ToolRunStartResponse(
        tool_run_id=run.tool_run_id,
        campaign_id=run.campaign_id,
        task_id=run.task_id,
        command_id=run.command_id,
        tool_name=run.tool_name,
        execution_mode="async",
        status=run.status,
        tool_run=run,
    )
    return JSONResponse(status_code=202, content=resp.model_dump(mode="json"))


@tool_runs_router.get("/{tool_run_id}")
async def get_tool_run_status(tool_run_id: str) -> JSONResponse:
    run = _executor.get_status(tool_run_id)
    if run is None:
        return JSONResponse(status_code=404, content={"error": "tool_run_not_found"})
    return JSONResponse(status_code=200, content=run.model_dump(mode="json"))


@tool_runs_router.post("/{tool_run_id}/collect")
async def collect_tool_run(tool_run_id: str) -> JSONResponse:
    run = _executor.get_status(tool_run_id)
    if run is None:
        return JSONResponse(status_code=404, content={"error": "tool_run_not_found"})
    if run.status != "finished":
        return JSONResponse(
            status_code=409,
            content={
                "error": "tool_run_not_ready",
                "status": run.status,
                "result_ready": run.result_ready,
            },
        )
    result = _executor.collect(tool_run_id)
    if result is None:
        return JSONResponse(status_code=404, content={"error": "tool_result_not_found"})
    return JSONResponse(status_code=200, content=result.model_dump(mode="json"))
