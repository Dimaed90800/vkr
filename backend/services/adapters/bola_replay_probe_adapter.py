"""Phase 9A — strict BOLA replay probe adapter."""
from __future__ import annotations

import time
import json
import re
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.auth_materializer import AuthMaterializer
    from backend.services.http.safe_http_client import SafeHttpClient, SafeHttpResult
    from backend.services.request_corpus_service import RequestCorpusService
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.auth_materializer import AuthMaterializer
    from services.http.safe_http_client import SafeHttpClient, SafeHttpResult
    from services.request_corpus_service import RequestCorpusService


class BolaReplayProbeAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._auth = AuthMaterializer()
        self._corpus = RequestCorpusService()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs or {}
        owner_role = str(inputs.get("owner_role") or "")
        attacker_role = str(inputs.get("attacker_role") or "")
        object_id = str(inputs.get("object_id") or "")
        attacker_own_id = str(inputs.get("attacker_own_object_id") or "")
        operation_id = command.operation_id or str(inputs.get("operation_id") or "")
        path_template = str(inputs.get("path_template") or "")
        collection_path_template = str(inputs.get("collection_path_template") or "")
        method = str(inputs.get("method") or "GET")

        steps = [
            ("owner_baseline", owner_role, str(inputs.get("object_url") or ""), object_id, operation_id, path_template),
            ("attacker_attack", attacker_role, str(inputs.get("object_url") or ""), object_id, operation_id, path_template),
            ("attacker_negative_control", attacker_role, str(inputs.get("attacker_own_object_url") or ""), attacker_own_id, operation_id, path_template),
            ("owner_collection", owner_role, str(inputs.get("collection_url") or ""), object_id, str(inputs.get("collection_operation_id") or ""), collection_path_template),
            ("attacker_collection", attacker_role, str(inputs.get("collection_url") or ""), object_id, str(inputs.get("collection_operation_id") or ""), collection_path_template),
        ]

        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        stored: dict[str, tuple[str, SafeHttpResult]] = {}
        errors: list[ToolResultError] = []

        for step_name, role, url, expected_id, step_operation_id, step_path in steps:
            auth, auth_error = self._auth.materialize(campaign, role)
            if auth_error is not None:
                errors.append(ToolResultError(
                    error_type=auth_error.code,
                    message=auth_error.message,
                    recoverable=True,
                ))
                continue

            result = self._http.request(
                campaign,
                method=method,
                url=url,
                headers=auth.headers if auth else {},
                cookies=auth.cookies if auth else {},
                timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
                max_response_bytes=int(inputs.get("max_response_bytes") or 1024 * 1024),
            )
            if result.error is not None:
                errors.append(ToolResultError(
                    error_type=result.error.code,
                    message=f"{step_name}: {result.error.message}",
                    recoverable=True,
                ))
                continue

            item = self._corpus.add_exchange(
                campaign_id=command.campaign_id,
                method=result.method,
                url=result.url,
                headers=result.request_headers_redacted,
                body=result.request_body_redacted,
                status_code=result.status_code,
                response_body=result.response_body,
                response_content_type=result.response_content_type,
                auth_profile=role,
                source="tool:bola_replay_probe",
                source_tool_run_id=tool_run_id,
                operation_id=step_operation_id,
                path_template=step_path,
            )
            stored[step_name] = (item.request_id, result)
            requests.append(ToolResultRequest(
                request_id=item.request_id,
                role=role,
                method=result.method,
                url=result.url,
                path_template=step_path,
            ))
            responses.append(ToolResultResponse(
                request_id=item.request_id,
                status_code=result.status_code,
            ))

        proof_ok = self._proof_ok(stored, object_id, attacker_own_id)
        observations = []
        if proof_ok:
            observations.append(ToolResultObservationLite(
                observation_type="cross_role_access_signal",
                confidence=0.9,
                details={
                    "object_id": object_id,
                    "owner_role": owner_role,
                    "attacker_role": attacker_role,
                    "operation_id": operation_id,
                    "request_id": stored["attacker_attack"][0],
                    "auth_profile": attacker_role,
                    "owner_request_id": stored["owner_baseline"][0],
                    "attack_request_id": stored["attacker_attack"][0],
                    "attacker_own_request_id": stored["attacker_negative_control"][0],
                    "owner_collection_request_id": stored["owner_collection"][0],
                    "attacker_collection_request_id": stored["attacker_collection"][0],
                },
            ))
        else:
            errors.append(ToolResultError(
                error_type="bola_proof_incomplete",
                message="Strict BOLA replay proof did not satisfy all five proof steps.",
                recoverable=True,
            ))

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="bola_replay_summary",
            content={
                "steps": {
                    name: {
                        "request_id": value[0],
                        "method": value[1].method,
                        "url": value[1].url,
                        "status_code": value[1].status_code,
                        "response_body_redacted": value[1].response_body,
                    }
                    for name, value in stored.items()
                },
                "proof_ok": proof_ok,
            },
        )

        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=len(requests),
                success_count=sum(1 for r in responses if 200 <= r.status_code <= 399),
                client_error_count=sum(1 for r in responses if 400 <= r.status_code <= 499),
                server_error_count=sum(1 for r in responses if r.status_code >= 500),
                duration_ms=duration_ms,
            ),
            requests=requests,
            responses=responses,
            observations=observations,
            artifacts=[artifact],
            errors=errors,
        )

    @staticmethod
    def _proof_ok(
        stored: dict[str, tuple[str, SafeHttpResult]],
        object_id: str,
        attacker_own_id: str,
    ) -> bool:
        required = {
            "owner_baseline",
            "attacker_attack",
            "attacker_negative_control",
            "owner_collection",
            "attacker_collection",
        }
        if not required.issubset(stored.keys()):
            return False
        return (
            _success_contains(stored["owner_baseline"][1], object_id)
            and _success_contains(stored["attacker_attack"][1], object_id)
            and _success_contains(stored["attacker_negative_control"][1], attacker_own_id)
            and _success_contains(stored["owner_collection"][1], object_id)
            and _success_excludes(stored["attacker_collection"][1], object_id)
        )


def _success_contains(result: SafeHttpResult, value: str) -> bool:
    return 200 <= result.status_code <= 399 and _contains(result.response_body, value)


def _success_excludes(result: SafeHttpResult, value: str) -> bool:
    return 200 <= result.status_code <= 399 and not _contains(result.response_body, value)


def _contains(body: Any, value: str) -> bool:
    if not value:
        return False
    if isinstance(body, dict):
        return any(_contains(v, value) for v in body.values())
    if isinstance(body, list):
        return any(_contains(v, value) for v in body)
    if isinstance(body, str):
        raw = body.strip()
        if raw == value:
            return True
        if raw and raw[0] in "{[":
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            if parsed is not None:
                return _contains(parsed, value)
        tokens = re.findall(r"[A-Za-z0-9_-]+", raw)
        return value in tokens
    return str(body) == value
