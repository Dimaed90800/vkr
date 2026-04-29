"""Phase 9B — bounded BOLA replay using prepared object_pair_id."""
from __future__ import annotations

import time
from typing import Any
from urllib.parse import quote

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
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.bola_object_pair_store import BolaObjectPairStore
    from backend.services.http.safe_http_client import SafeHttpClient
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.services.resource_instance_store import ResourceInstanceStore
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
    from services.auth_profile_store import AuthProfileStore
    from services.bola_object_pair_store import BolaObjectPairStore
    from services.http.safe_http_client import SafeHttpClient
    from services.request_corpus_service import RequestCorpusService
    from services.resource_instance_store import ResourceInstanceStore


class BolaReplayProbeAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._pairs = BolaObjectPairStore()
        self._instances = ResourceInstanceStore()
        self._profiles = AuthProfileStore()
        self._corpus = RequestCorpusService()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        validation_mode = str(inputs.get("validation_mode") or "bola_replay").strip() or "bola_replay"
        object_pair_id = str(inputs.get("object_pair_id") or "").strip()
        if not object_pair_id:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details={
                    "validation_mode": validation_mode,
                    "object_pair_id": "",
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["object_pair_id_missing"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[ToolResultError(error_type="object_pair_id_missing", message="object_pair_id is required.", recoverable=True)],
            )

        pair = self._pairs.get_bola_object_pair(object_pair_id)
        if pair is None:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details={
                    "validation_mode": validation_mode,
                    "object_pair_id": object_pair_id,
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["object_pair_not_found"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[ToolResultError(error_type="object_pair_not_found", message="Prepared object pair was not found.", recoverable=True)],
            )
        metadata = getattr(pair, "metadata", None) if hasattr(pair, "metadata") else None
        metadata = metadata if isinstance(metadata, dict) else {}
        block_reasons = [str(x) for x in (metadata.get("baseline_block_reasons") or []) if str(x).strip()]
        if block_reasons:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "blocked_before_replay",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["blocked_pair", *block_reasons][:20],
                    "owner_status_code": 0,
                    "owner_result": "skipped",
                    "attacker_status_code": 0,
                    "attacker_result": "skipped",
                    "replay_classification": "blocked_pair",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )

        if str(pair.target_method or "GET").upper() != "GET":
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["target_method_not_supported_mvp"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )

        raw_object_id = self._instances.get_raw_object_id(pair.object_id_ref)
        if raw_object_id in (None, ""):
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["raw_object_id_unavailable"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )

        owner_profile = self._profiles.get_auth_profile(pair.owner_auth_profile_id)
        if owner_profile is None:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["owner_auth_profile_missing"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )
        attacker_profile = self._profiles.get_auth_profile(pair.attacker_auth_profile_id)
        if attacker_profile is None:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["attacker_auth_profile_missing"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )

        owner_headers = self._bearer_headers(owner_profile)
        attacker_headers = self._bearer_headers(attacker_profile)
        if not owner_headers:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["owner_auth_secret_missing"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )
        if not attacker_headers:
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=self._base_details(pair, validation_mode) | {
                    "status_code": 0,
                    "result": "error",
                    "access_granted": False,
                    "response_fingerprint_match": "not_checked",
                    "evidence_strength": "low",
                    "reason_codes": ["attacker_auth_secret_missing"],
                    "owner_status_code": 0,
                    "owner_result": "error",
                    "attacker_status_code": 0,
                    "attacker_result": "error",
                    "replay_classification": "inconclusive",
                    "owner_baseline_valid": False,
                },
                errors=[],
            )

        request_url = self._build_target_url(
            campaign.target_url,
            pair.target_path_template,
            pair.path_param_name,
            str(raw_object_id),
        )
        # For corpus / tool result storage: never persist a substituted URL.
        safe_storage_url = campaign.target_url.rstrip("/") + "/" + str(pair.target_path_template or "").lstrip("/")

        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        errors: list[ToolResultError] = []

        # Owner baseline GET first.
        owner_http = self._http.request(
            campaign,
            method="GET",
            url=request_url,
            headers=owner_headers,
            timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
            max_response_bytes=1024 * 1024,
            follow_same_origin_redirects=False,
            max_redirects=0,
        )
        if owner_http.error is not None:
            status_code = self._extract_status_code(owner_http.error)
            details = self._base_details(pair, validation_mode) | {
                "status_code": status_code,
                "result": "replay_error",
                "access_granted": False,
                "response_fingerprint_match": "not_checked",
                "evidence_strength": "low",
                "reason_codes": [str(owner_http.error.code or "request_error")],
                "owner_status_code": status_code,
                "owner_result": "replay_error",
                "attacker_status_code": 0,
                "attacker_result": "skipped",
                "replay_classification": "inconclusive",
                "owner_baseline_valid": False,
            }
            errors.append(ToolResultError(
                error_type=str(owner_http.error.code or "request_error"),
                message=str(owner_http.error.message or "request failed"),
                recoverable=True,
            ))
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=details,
                errors=errors,
            )

        owner_status = int(owner_http.status_code or 0)
        owner_result, _ = self._classify_status(owner_status)
        owner_baseline_valid = 200 <= owner_status <= 299
        if not owner_baseline_valid:
            # Owner itself cannot access -> invalid object_pair for BOLA evidence; skip attacker replay.
            details = self._base_details(pair, validation_mode) | {
                "status_code": owner_status,
                "result": "invalid_object_pair",
                "access_granted": False,
                "response_fingerprint_match": "not_checked",
                "evidence_strength": "low",
                "reason_codes": ["owner_baseline_failed"],
                "owner_status_code": owner_status,
                "owner_result": owner_result,
                "attacker_status_code": 0,
                "attacker_result": "skipped",
                "replay_classification": "invalid_object_pair",
                "owner_baseline_valid": False,
            }
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=details,
                confidence=0.2,
            )

        # Attacker replay GET only if owner baseline is meaningful (2xx).
        attacker_http = self._http.request(
            campaign,
            method="GET",
            url=request_url,
            headers=attacker_headers,
            timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
            max_response_bytes=1024 * 1024,
            follow_same_origin_redirects=False,
            max_redirects=0,
        )
        if attacker_http.error is not None:
            status_code = self._extract_status_code(attacker_http.error)
            details = self._base_details(pair, validation_mode) | {
                "status_code": status_code,
                "result": "replay_error",
                "access_granted": False,
                "response_fingerprint_match": "not_checked",
                "evidence_strength": "low",
                "reason_codes": [str(attacker_http.error.code or "request_error")],
                "owner_status_code": owner_status,
                "owner_result": owner_result,
                "attacker_status_code": status_code,
                "attacker_result": "replay_error",
                "replay_classification": "inconclusive",
                "owner_baseline_valid": True,
            }
            errors.append(ToolResultError(
                error_type=str(attacker_http.error.code or "request_error"),
                message=str(attacker_http.error.message or "request failed"),
                recoverable=True,
            ))
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=details,
                errors=errors,
            )

        raw_body = attacker_http.get_raw_response_body()
        field_count = self._field_count(raw_body)
        content_type = attacker_http.response_content_type or ""
        status_code = int(attacker_http.status_code or 0)

        corpus_item = self._corpus.add_exchange(
            campaign_id=command.campaign_id,
            method=attacker_http.method,
            url=safe_storage_url,
            headers=attacker_headers,
            body=None,
            status_code=status_code,
            response_body=raw_body,
            response_content_type=attacker_http.response_content_type,
            auth_profile=pair.attacker_auth_profile_id,
            source="tool:bola_replay_probe",
            source_tool_run_id=tool_run_id,
            operation_id=pair.target_operation_id,
            path_template=pair.target_path_template,
        )
        request_id = corpus_item.request_id
        requests.append(ToolResultRequest(
            request_id=request_id,
            role=pair.attacker_auth_profile_id,
            method=attacker_http.method,
            url=safe_storage_url,
            path_template=pair.target_path_template,
        ))
        responses.append(ToolResultResponse(request_id=request_id, status_code=status_code))

        attacker_result, attacker_access_granted = self._classify_status(status_code)
        replay_classification = "inconclusive"
        result = "replay_error"
        access_granted = False
        evidence_strength = "low"
        reason_codes = ["owner_baseline_valid"]
        if attacker_access_granted:
            result = "attacker_access_granted"
            replay_classification = "possible_bola"
            access_granted = True
            evidence_strength = self._evidence_strength(status_code, content_type, field_count)
            reason_codes.append("attacker_access_granted")
        elif status_code in {401, 403}:
            result = "attacker_access_denied"
            replay_classification = "access_denied"
            evidence_strength = "medium"
            reason_codes.append("attacker_denied")
        elif status_code == 404:
            result = "attacker_access_denied_or_not_found"
            replay_classification = "access_denied_or_not_found"
            evidence_strength = "medium"
            reason_codes.append("attacker_not_found")
        else:
            # Other non-2xx while owner baseline valid: keep it non-judge-ready and low evidence.
            result = "replay_error" if status_code == 0 else "attacker_access_denied_or_not_found"
            replay_classification = "inconclusive" if status_code == 0 else "access_denied_or_not_found"
            evidence_strength = "low"
            reason_codes.append(attacker_result)

        details = self._base_details(pair, validation_mode) | {
            "request_id": request_id,
            "auth_profile": pair.attacker_auth_profile_id,
            "status_code": status_code,
            "content_type": content_type,
            "field_count": field_count,
            "result": result,
            "access_granted": access_granted,
            "response_fingerprint_match": "not_checked",
            "evidence_strength": evidence_strength,
            "reason_codes": reason_codes,
            "owner_status_code": owner_status,
            "owner_result": owner_result,
            "attacker_status_code": status_code,
            "attacker_result": attacker_result,
            "replay_classification": replay_classification,
            "owner_baseline_valid": True,
        }
        return self._finish(
            command=command,
            tool_run_id=tool_run_id,
            start_ms=start_ms,
            observation_details=details,
            requests=requests,
            responses=responses,
            errors=errors,
            confidence=0.95 if access_granted else 0.6,
        )

    @staticmethod
    def _base_details(pair: Any, validation_mode: str) -> dict[str, Any]:
        metadata = getattr(pair, "metadata", None) if hasattr(pair, "metadata") else None
        metadata = metadata if isinstance(metadata, dict) else {}
        return {
            "validation_mode": validation_mode,
            "object_pair_id": str(pair.object_pair_id or ""),
            "resource_type": str(pair.resource_type or "unknown"),
            "target_operation_id": str(pair.target_operation_id or ""),
            "target_path_template": str(pair.target_path_template or ""),
            "target_method": str(pair.target_method or "GET").upper(),
            "path_param_name": str(pair.path_param_name or ""),
            "attacker_auth_profile_id": str(pair.attacker_auth_profile_id or ""),
            "owner_auth_profile_id": str(pair.owner_auth_profile_id or ""),
            "baseline_probability_score": float(metadata.get("baseline_probability_score") or 0.0),
            "baseline_probability_reasons": [str(x) for x in (metadata.get("baseline_probability_reasons") or []) if str(x).strip()][:20],
            "baseline_block_reasons": [str(x) for x in (metadata.get("baseline_block_reasons") or []) if str(x).strip()][:20],
            "semantic_id_kind": str(metadata.get("semantic_id_kind") or ""),
            "object_id_field": str(metadata.get("object_id_field") or ""),
            "id_json_path": str(metadata.get("id_json_path") or ""),
            "source_operation_id": str(metadata.get("source_operation_id") or ""),
            "source_status_code": int(metadata.get("source_status_code") or 0),
            "owner_evidence": bool(metadata.get("owner_evidence")),
            "dependency_producer_operation_id": str(metadata.get("dependency_producer_operation_id") or ""),
        }

    @staticmethod
    def _build_target_url(base_url: str, path_template: str, path_param_name: str, raw_object_id: str) -> str:
        replacement = quote(str(raw_object_id), safe="")
        token = "{" + str(path_param_name or "").strip() + "}"
        path = str(path_template or "")
        if token in path:
            path = path.replace(token, replacement, 1)
        return base_url.rstrip("/") + "/" + path.lstrip("/")

    def _bearer_headers(self, profile: Any) -> dict[str, Any]:
        token = self._profiles.get_token_by_ref(getattr(profile, "token_ref", ""))
        if token in (None, ""):
            return {}
        if str(getattr(profile, "auth_type", "") or "").strip().lower() != "bearer":
            return {}
        return {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _classify_status(status_code: int) -> tuple[str, bool]:
        if 200 <= status_code <= 299:
            return "attacker_access_granted", True
        if status_code in {401, 403}:
            return "attacker_access_denied", False
        if status_code == 404:
            return "not_found", False
        return "non_2xx", False

    @staticmethod
    def _evidence_strength(status_code: int, content_type: str, field_count: int) -> str:
        ctype = str(content_type or "").lower()
        if 200 <= status_code <= 299 and ("application/json" in ctype or field_count > 0):
            return "high"
        if 200 <= status_code <= 299:
            return "medium"
        return "low"

    @staticmethod
    def _field_count(body: Any) -> int:
        if isinstance(body, dict):
            return len(body)
        if isinstance(body, list):
            return len(body)
        return 0

    @staticmethod
    def _extract_status_code(error: Any) -> int:
        for attr in ("status_code",):
            value = getattr(error, attr, None)
            if isinstance(value, int):
                return value
        details = getattr(error, "details", None)
        if isinstance(details, dict):
            for key in ("status_code",):
                value = details.get(key)
                if isinstance(value, int):
                    return value
        return 0

    def _finish(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        observation_details: dict[str, Any],
        requests: list[ToolResultRequest] | None = None,
        responses: list[ToolResultResponse] | None = None,
        errors: list[ToolResultError] | None = None,
        confidence: float = 0.5,
    ) -> ToolResult:
        duration_ms = int(time.monotonic() * 1000) - start_ms
        reqs = list(requests or [])
        resps = list(responses or [])
        errs = list(errors or [])
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=len(reqs),
                success_count=sum(1 for r in resps if 200 <= r.status_code <= 299),
                client_error_count=sum(1 for r in resps if 400 <= r.status_code <= 499),
                server_error_count=sum(1 for r in resps if r.status_code >= 500),
                duration_ms=duration_ms,
            ),
            requests=reqs,
            responses=resps,
            observations=[
                ToolResultObservationLite(
                    observation_type="bola_replay_result",
                    confidence=confidence,
                    details=observation_details,
                )
            ],
            artifacts=[],
            errors=errs,
        )
