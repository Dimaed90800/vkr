"""Phase 4 — Worker command validation and submission routes.

POST /v1/workers/command/validate  — dry-run validation, no storage
POST /v1/workers/command           — validate + store accepted command
"""
from __future__ import annotations

from fastapi import APIRouter, Response
from fastapi.responses import JSONResponse

try:
    from backend.models.worker_command import (
        CommandSubmitResponse,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from backend.services.command_validator import CommandValidator, _command_fingerprint
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.worker_command import (
        CommandSubmitResponse,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from services.command_validator import CommandValidator, _command_fingerprint
    from storage.memory_store import memory_store

workers_router = APIRouter(prefix="/v1/workers", tags=["workers"])

_validator = CommandValidator()


@workers_router.post("/command/validate", response_model=ValidationResult)
async def validate_command(command: WorkerCommand) -> ValidationResult:
    result = _validator.validate(command)
    return result


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
