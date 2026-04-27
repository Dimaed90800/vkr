"""Phase 4 — Worker command validation and submission routes.

POST /v1/workers/command/validate  — dry-run validation, no storage
POST /v1/workers/command           — validate + store accepted command
GET  /v1/workers/capabilities      — Phase 17A.1 read-only capability catalog
GET  /v1/workers/capabilities/{tool_name}
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Response, status
from fastapi.responses import JSONResponse

try:
    from backend.models.worker_command import (
        CommandSubmitResponse,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from backend.models.worker_capability import WorkerCapabilityCatalogResponse
    from backend.services.command_validator import CommandValidator, _command_fingerprint
    from backend.services.worker_capability_catalog import WorkerCapabilityCatalog
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.worker_command import (
        CommandSubmitResponse,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from models.worker_capability import WorkerCapabilityCatalogResponse
    from services.command_validator import CommandValidator, _command_fingerprint
    from services.worker_capability_catalog import WorkerCapabilityCatalog
    from storage.memory_store import memory_store

workers_router = APIRouter(prefix="/v1/workers", tags=["workers"])

_validator = CommandValidator()
_capability_catalog = WorkerCapabilityCatalog()


@workers_router.post("/command/validate", response_model=ValidationResult)
async def validate_command(command: WorkerCommand) -> ValidationResult:
    result = _validator.validate(command)
    return result


@workers_router.get(
    "/capabilities",
    response_model=WorkerCapabilityCatalogResponse,
)
async def list_worker_capabilities() -> WorkerCapabilityCatalogResponse:
    return _capability_catalog.response()


@workers_router.get("/capabilities/{tool_name}")
async def get_worker_capability_by_tool_name(tool_name: str) -> JSONResponse:
    cap = _capability_catalog.get_by_tool_name(tool_name)
    if cap is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"code": "worker_capability_not_found", "tool_name": tool_name},
        )
    return JSONResponse(content=cap.model_dump(mode="json"))


@workers_router.post("/command")
async def submit_command(command: WorkerCommand, response: Response) -> JSONResponse:
    result = _validator.validate(command)

    if not result.valid:
        return JSONResponse(
            status_code=400,
            content=result.model_dump(mode="json"),
        )

    normalized_class = result.normalized_worker_class
    fp = _command_fingerprint(command, normalized_class)

    data = command.model_dump(mode="json")
    data["status"] = "accepted"
    data["normalized_worker_class"] = normalized_class
    data["fingerprint"] = fp

    memory_store.store_command(command.command_id, command.campaign_id, data)
    memory_store.command_fingerprints[command.campaign_id].add(fp)

    submit_response = CommandSubmitResponse(
        command_id=command.command_id,
        campaign_id=command.campaign_id,
        task_id=command.task_id,
        status="accepted",
        validation=result,
    )
    return JSONResponse(
        status_code=201,
        content=submit_response.model_dump(mode="json"),
    )
