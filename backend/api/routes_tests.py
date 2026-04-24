import json
import logging
from typing import Any

from fastapi import APIRouter, Body, HTTPException, status

try:
    from backend.models.testing import ToolTestRequest, ToolTestResponse
    from backend.services.testing_service import TestingService
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ToolTestRequest, ToolTestResponse
    from services.testing_service import TestingService
    from services.wrapper_observability import append_run_event


logger = logging.getLogger(__name__)
router = APIRouter(tags=["tests"])
testing_service = TestingService()


TOOL_NAME_ALIASES = {
    "probe_entrypoints": "auth_probe_entrypoints",
    "import_traffic_surface": "import_har_capture",
    "runtime_inventory_discovery": "runtime_inventory",
    "bounded_rate_probe": "bounded_burst_helper",
    "replay_sequence": "replay_http_sequence",
}


def _normalized_request(request: ToolTestRequest) -> ToolTestRequest:
    canonical_tool_name = TOOL_NAME_ALIASES.get(request.tool_name, request.tool_name)
    normalized = request if canonical_tool_name == request.tool_name else request.model_copy(update={"tool_name": canonical_tool_name})
    append_run_event(
        event_name="legacy_tool_dispatch_start",
        run_id=normalized.execution_context.run_id,
        task_id=normalized.task.id,
        worker_role=normalized.task.worker_role or (normalized.task.context_hints or {}).get("router_assigned_worker"),
        tool_name=normalized.tool_name,
        status="started",
        summary="Legacy tool endpoint received a request.",
        target_url=str(normalized.execution_context.target_url),
        reason={"fallback_reason": "legacy_endpoint_selected"},
        extra={
            "preferred_tool": normalized.task.preferred_tool
            or getattr(normalized.task.tool_preference, "preferred_tool", None),
            "used_legacy_path": True,
            "noop_path": normalized.tool_name == "noop_outcome",
            "current_task_missing": normalized.task.id == "__no_task__",
        },
    )
    return normalized


def _coerce_tool_request_payload(payload: Any, *, default_tool_name: str) -> ToolTestRequest:
    if isinstance(payload, ToolTestRequest):
        return _normalized_request(payload)
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Expected object payload for {default_tool_name}, got string") from exc
    if not isinstance(payload, dict):
        raise ValueError(f"Expected object payload for {default_tool_name}, got {type(payload).__name__}")
    normalized = dict(payload)
    nested_request = normalized.get("normalized_backend_request_json") or normalized.get("request_json")
    if isinstance(nested_request, str):
        try:
            nested_payload = json.loads(nested_request)
        except json.JSONDecodeError:
            nested_payload = None
        if isinstance(nested_payload, dict):
            merged = dict(nested_payload)
            merged.update({key: value for key, value in normalized.items() if key not in {"normalized_backend_request_json", "request_json"}})
            normalized = merged
    normalized.setdefault("tool_name", default_tool_name)

    def _object(value: Any) -> dict[str, Any] | None:
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return None
            return parsed if isinstance(parsed, dict) else None
        return None

    arguments = _object(normalized.get("arguments")) or {}
    for alias in ("tool_arguments", "tool_arguments_json", "arguments_json", "worker_arguments", "worker_arguments_json"):
        aliased_arguments = _object(normalized.get(alias))
        if aliased_arguments:
            arguments.update(aliased_arguments)

    if "task" not in normalized:
        for alias in ("current_task", "active_task", "task_json", "active_task_json"):
            task_payload = _object(normalized.get(alias)) or _object(arguments.get(alias))
            if task_payload:
                normalized["task"] = task_payload
                break
        if "task" not in normalized and isinstance(arguments.get("task"), dict):
            normalized["task"] = arguments["task"]

    if "execution_context" not in normalized:
        for alias in ("context", "current_execution_context", "executionContext", "execution_context_json", "current_execution_context_json"):
            context_payload = _object(normalized.get(alias)) or _object(arguments.get(alias))
            if context_payload:
                normalized["execution_context"] = context_payload
                break
    if "execution_context" not in normalized:
        target_url = normalized.get("target_url") or arguments.get("target_url")
        if target_url:
            normalized["execution_context"] = {
                key: normalized.get(key, arguments.get(key))
                for key in (
                    "toolbox_url",
                    "target_url",
                    "run_id",
                    "root_trace_id",
                    "openapi_url",
                    "openapi_spec_text",
                    "roles",
                    "allowed_hosts",
                    "traffic_requests",
                    "max_requests",
                    "max_duration_sec",
                    "max_retries_per_task",
                )
                if normalized.get(key, arguments.get(key)) is not None
            }

    execution_context = normalized.get("execution_context") if isinstance(normalized.get("execution_context"), dict) else {}
    if "task" not in normalized and isinstance(execution_context.get("current_task_snapshot"), dict):
        normalized["task"] = execution_context.get("current_task_snapshot")
    if default_tool_name == "replay_http_sequence" and isinstance(normalized.get("task"), dict):
        sequence = arguments.get("sequence")
        if not isinstance(sequence, list) or not sequence:
            endpoint = normalized.get("endpoint") or arguments.get("endpoint") or normalized["task"].get("endpoint")
            method = normalized.get("method") or arguments.get("method") or normalized["task"].get("method") or "GET"
            if endpoint:
                arguments["sequence"] = [{"method": str(method).upper(), "endpoint": str(endpoint)}]

    if not arguments:
        for key in ("sequence", "steps", "headers", "query_params", "json_body", "endpoint", "method"):
            if key in normalized:
                arguments[key] = normalized[key]
    normalized["arguments"] = arguments
    return _normalized_request(ToolTestRequest.model_validate(normalized))


@router.post(
    "/auth/test-access",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def auth_test_access(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Authorization test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.test_access(request)
    except ValueError as exc:
        logger.warning("Authorization test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_authorization_test", "message": str(exc)},
        ) from exc


@router.post("/auth/auto-provision", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_auto_provision(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.auto_provision(request)
    except ValueError as exc:
        logger.warning("Auth auto-provision rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/probe-entrypoints", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_probe_entrypoints(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.probe_entrypoints(request)
    except ValueError as exc:
        logger.warning("Auth entrypoint probe rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/create-test-object", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_create_test_object(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.create_test_object(request)
    except ValueError as exc:
        logger.warning("Auth create-test-object rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_auth_preparation", "message": str(exc)},
        ) from exc


@router.post("/auth/property-mutation-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def auth_property_mutation_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    try:
        return await testing_service.property_mutation_test(request)
    except ValueError as exc:
        logger.warning("Auth property-mutation test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_property_mutation_test", "message": str(exc)},
        ) from exc


@router.post(
    "/injection/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def injection_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Injection test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.run_injection_test(request)
    except ValueError as exc:
        logger.warning("Injection test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_injection_test", "message": str(exc)},
        ) from exc


@router.post("/injection/input-shape-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_input_shape_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.input_shape_probe(request)


@router.post("/injection/reflection-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_reflection_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.reflection_probe(request)


@router.post("/injection/path-fuzz-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def injection_path_fuzz_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.path_fuzz_probe(request)


@router.post(
    "/logic/test",
    response_model=ToolTestResponse,
    status_code=status.HTTP_200_OK,
)
async def logic_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    logger.info(
        "Business logic test task_id=%s tool_name=%s",
        request.task.id,
        request.tool_name,
    )
    try:
        return await testing_service.run_logic_test(request)
    except ValueError as exc:
        logger.warning("Business logic test rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_logic_test", "message": str(exc)},
        ) from exc


@router.post("/logic/workflow-probe", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def logic_workflow_probe(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.workflow_probe(request)


@router.post("/data/exposure-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def data_exposure_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.data_exposure_test(request)


@router.post("/resource/abuse-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def resource_abuse_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.resource_abuse_test(request)


@router.post("/config/misconfiguration-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def misconfiguration_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.misconfiguration_test(request)


@router.post("/assets/version-diff-test", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def version_diff_test(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.version_diff_test(request)




@router.post("/traffic/import-har", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def import_har_capture(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.import_har_capture(request)


@router.post("/inventory/runtime", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def runtime_inventory(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.runtime_inventory(request)


@router.post("/replay/http-sequence", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def replay_http_sequence(payload: Any = Body(...)) -> ToolTestResponse:
    try:
        request = _coerce_tool_request_payload(payload, default_tool_name="replay_http_sequence")
    except Exception as exc:
        logger.warning("Replay sequence rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_replay_sequence_request", "message": str(exc)},
        ) from exc
    return await testing_service.replay_http_sequence(request)


@router.post("/resource/bounded-burst-helper", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def bounded_burst_helper(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.bounded_burst_helper(request)

@router.post("/recon/capture-authenticated-traffic", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def capture_authenticated_traffic(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.capture_authenticated_traffic(request)


@router.post("/recon/capture-anonymous-traffic", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def capture_anonymous_traffic(request: ToolTestRequest) -> ToolTestResponse:
    request = _normalized_request(request)
    return await testing_service.capture_anonymous_traffic(request)


@router.post("/worker/noop-outcome", response_model=ToolTestResponse, status_code=status.HTTP_200_OK)
async def noop_outcome(payload: Any = Body(default=None)) -> ToolTestResponse:
    try:
        request = _coerce_tool_request_payload(payload, default_tool_name="noop_outcome")
    except Exception as exc:
        logger.info("Noop outcome received invalid payload: %s", exc)
        append_run_event(
            event_name="legacy_tool_dispatch_start",
            run_id=None,
            task_id=None,
            worker_role=None,
            tool_name="noop_outcome",
            status="skipped",
            summary="Noop endpoint received an invalid payload.",
            reason={"fallback_reason": "invalid_noop_request", "exception_type": type(exc).__name__},
            extra={"used_legacy_path": True, "noop_path": True, "current_task_missing": True},
        )
        return ToolTestResponse(
            request_summary={"action": "noop_outcome"},
            response_summary={"status": "skipped", "reason": "invalid_noop_request"},
            raw_status="skipped",
            indicators=["noop_outcome", "invalid_noop_request"],
        )
    return await testing_service.noop_outcome(request)
