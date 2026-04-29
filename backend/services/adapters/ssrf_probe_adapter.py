from __future__ import annotations

import hashlib
import os
import time
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
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.http.safe_http_client import SafeHttpClient
    from backend.services.ssrf_callback_store import SsrfCallbackStore
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
    from services.http.safe_http_client import SafeHttpClient
    from services.ssrf_callback_store import SsrfCallbackStore


class SsrfProbeAdapter:
    """Phase API7 — SSRF callback proof probe (1 bounded request)."""

    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._profiles = AuthProfileStore()
        self._callbacks = SsrfCallbackStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        validation_mode = str(inputs.get("validation_mode") or "ssrf_callback_probe").strip() or "ssrf_callback_probe"
        operation_id = str(inputs.get("operation_id") or "").strip()
        method = str(inputs.get("method") or "").strip().upper()
        path = str(inputs.get("path") or "").strip()
        field_name = str(inputs.get("field_name") or "").strip()
        field_path = str(inputs.get("field_path") or "").strip()
        auth_mode = str(inputs.get("auth_mode") or "unauthenticated").strip()
        auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
        role_hint = str(inputs.get("role_hint") or "").strip()
        correlation_id = str(inputs.get("correlation_id") or "").strip()
        request_draft = inputs.get("request_draft") if isinstance(inputs.get("request_draft"), dict) else None
        required_body_fields = [str(x) for x in (inputs.get("required_body_fields") or []) if str(x).strip()]
        allowed_body_fields = [str(x) for x in (inputs.get("allowed_body_fields") or []) if str(x).strip()]
        body_field_summaries = [dict(x) for x in (inputs.get("body_field_summaries") or []) if isinstance(x, dict)]
        schema_summary_source = str(inputs.get("schema_summary_source") or ("api_graph" if body_field_summaries else "none")).strip() or "none"

        if not correlation_id:
            correlation_id = self._make_correlation_id(
                campaign_id=command.campaign_id,
                operation_id=operation_id,
                field_path=field_path or field_name,
            )

        callback_base = str(os.getenv("SSRF_CALLBACK_BASE_URL") or "").strip().rstrip("/")
        if not callback_base:
            # Local-dev default; can be overridden by env in production.
            callback_base = "http://host.docker.internal:8000"
        callback_url = f"{callback_base}/v1/callbacks/ssrf/{correlation_id}"

        self._callbacks.register_probe(
            campaign_id=command.campaign_id,
            operation_id=operation_id,
            field_name=field_name,
            field_path=field_path,
            correlation_id=correlation_id,
            auth_mode=auth_mode,
            auth_profile_id=auth_profile_id,
            role_hint=role_hint,
        )

        headers: dict[str, Any] = {}
        if auth_mode == "authenticated":
            profile = self._profiles.get_auth_profile(auth_profile_id)
            if profile is not None:
                token = self._profiles.get_token_by_ref(profile.token_ref)
                if token not in (None, "") and str(profile.auth_type or "").strip().lower() == "bearer":
                    headers["Authorization"] = f"Bearer {token}"

        body = {field_name: callback_url}
        request_composer = "deterministic"
        request_draft_validated = True
        payload_synthesis_result = "fallback_minimal"
        synthesized_required_fields_count = 1
        filled_required_fields_count = 1
        missing_required_fields_count = 0
        rejected_fields_count = 0
        synthesized_field_count = 1
        reason_codes: list[str] = ["url_like_field_mutated"]
        synthesis_diag = self._synthesize_schema_payload(
            callback_url=callback_url,
            target_field_name=field_name,
            target_field_path=field_path,
            required_body_fields=required_body_fields,
            allowed_body_fields=allowed_body_fields,
            body_field_summaries=body_field_summaries,
        )
        if isinstance(synthesis_diag.get("body"), dict):
            body = synthesis_diag["body"]
            request_composer = "deterministic"
            payload_synthesis_result = "schema_synthesized"
            filled_required_fields_count = int(synthesis_diag.get("filled_required_fields_count") or 0)
            missing_required_fields_count = int(synthesis_diag.get("missing_required_fields_count") or 0)
            rejected_fields_count = int(synthesis_diag.get("rejected_fields_count") or 0)
            synthesized_field_count = int(synthesis_diag.get("synthesized_field_count") or 0)
            synthesized_required_fields_count = filled_required_fields_count

        if request_draft is not None:
            request_composer = "llm"
            draft_validation = self._validate_request_draft_for_ssrf(
                operation_id=operation_id,
                method=method,
                path_template=path,
                field_name=field_name,
                field_path=field_path,
                draft=request_draft,
                required_body_fields=required_body_fields,
                allowed_body_fields=allowed_body_fields,
                body_field_summaries=body_field_summaries,
            )
            request_draft_validated = bool(draft_validation.get("valid"))
            rejected_fields_count = int(draft_validation.get("rejected_fields_count") or 0)
            if request_draft_validated:
                body = self._replace_callback_placeholder(
                    request_draft.get("body_json") if isinstance(request_draft, dict) else {},
                    callback_url=callback_url,
                )
                payload_synthesis_result = "llm_composed"
                filled_required_fields_count = int(draft_validation.get("filled_required_fields_count") or 0)
                missing_required_fields_count = int(draft_validation.get("missing_required_fields_count") or 0)
                synthesized_required_fields_count = filled_required_fields_count
                synthesized_field_count = int(draft_validation.get("synthesized_field_count") or len(body.keys()))
                reason_codes.extend(["llm_payload_composed", "request_draft_validated"])
            else:
                payload_synthesis_result = "draft_rejected_schema_synthesized" if schema_summary_source != "none" else "draft_rejected_fallback_minimal"
                reason_codes.append(str(draft_validation.get("reason_code") or "request_draft_invalid"))
                reason_codes.append("fallback_deterministic_payload")
                if schema_summary_source == "none":
                    body = {field_name: callback_url}
                    filled_required_fields_count = 1
                    missing_required_fields_count = 0
                    synthesized_field_count = 1
                    synthesized_required_fields_count = 1

        # One bounded request only.
        result = self._http.request(
            campaign,
            method=method,
            url=campaign.target_url.rstrip("/") + "/" + path.lstrip("/"),
            headers=headers or None,
            body=body,
            timeout_sec=min(command.budget.timeout_sec, campaign.limits.max_duration_sec),
            max_response_bytes=256 * 1024,
            follow_same_origin_redirects=False,
            max_redirects=0,
        )

        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        errors: list[ToolResultError] = []

        target_status_code = int(result.status_code or 0)
        if result.error is not None:
            errors.append(ToolResultError(
                error_type=str(result.error.code or "probe_error"),
                message=str(result.error.message or "SSRF probe failed"),
                recoverable=True,
            ))
            details = self._details_base(
                validation_mode=validation_mode,
                operation_id=operation_id,
                method=method,
                path=path,
                field_name=field_name,
                field_path=field_path,
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
                correlation_id=correlation_id,
            ) | {
                "target_status_code": target_status_code,
                "callback_received": False,
                "callback_method": "",
                "result": "probe_error",
                "evidence_strength": "low",
                "reason_codes": [str(result.error.code or "probe_error")],
                "callback_correlation_id": correlation_id,
                "request_composer": request_composer,
                "request_draft_validated": request_draft_validated,
                "payload_synthesis_result": payload_synthesis_result,
                "synthesized_required_fields_count": synthesized_required_fields_count,
                "filled_required_fields_count": filled_required_fields_count,
                "missing_required_fields_count": missing_required_fields_count,
                "rejected_fields_count": rejected_fields_count,
                "synthesized_field_count": synthesized_field_count,
                "schema_summary_source": schema_summary_source,
            }
            return self._finish(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                observation_details=details,
                errors=errors,
            )

        # Poll callback store for a short bounded window (no unbounded waiting).
        callback_received = False
        callback_method = ""
        deadline = time.monotonic() + 2.5
        while time.monotonic() < deadline:
            status = self._callbacks.get_status(correlation_id)
            if bool(status.get("received")):
                callback_received = True
                callback_method = str(status.get("callback_method") or "")
                break
            time.sleep(0.25)

        if callback_received:
            reason_codes.extend(["callback_received", "correlation_id_matched"])

        evidence_strength = "high" if callback_received else "low"
        result_label = "callback_received" if callback_received else "no_callback_observed"
        if target_status_code and not (200 <= target_status_code <= 299):
            if callback_received:
                result_label = "callback_received"
            elif 400 <= target_status_code <= 499:
                result_label = "target_4xx"
            elif target_status_code >= 500:
                result_label = "target_5xx"
            else:
                result_label = "target_non_2xx"
            reason_codes.append("target_non_2xx")

        details = self._details_base(
            validation_mode=validation_mode,
            operation_id=operation_id,
            method=method,
            path=path,
            field_name=field_name,
            field_path=field_path,
            auth_mode=auth_mode,
            auth_profile_id=auth_profile_id,
            role_hint=role_hint,
            correlation_id=correlation_id,
        ) | {
            "target_status_code": target_status_code,
            "callback_received": callback_received,
            "callback_method": callback_method,
            "callback_correlation_id": correlation_id,
            "result": result_label,
            "evidence_strength": evidence_strength,
            "reason_codes": reason_codes,
            "request_composer": request_composer,
            "request_draft_validated": request_draft_validated,
            "payload_synthesis_result": payload_synthesis_result,
            "synthesized_required_fields_count": synthesized_required_fields_count,
            "filled_required_fields_count": filled_required_fields_count,
            "missing_required_fields_count": missing_required_fields_count,
            "rejected_fields_count": rejected_fields_count,
            "synthesized_field_count": synthesized_field_count,
            "schema_summary_source": schema_summary_source,
        }

        # ToolResult request/response entries: store only safe URL (already sanitized by SafeHttpClient).
        request_id = ""
        requests.append(ToolResultRequest(
            request_id=request_id,
            role=auth_profile_id if auth_mode == "authenticated" else "",
            method=result.method,
            url=result.url,
            path_template=path,
        ))
        responses.append(ToolResultResponse(request_id=request_id, status_code=target_status_code))

        return self._finish(
            command=command,
            tool_run_id=tool_run_id,
            start_ms=start_ms,
            observation_details=details,
            requests=requests,
            responses=responses,
            errors=errors,
            confidence=0.95 if callback_received else 0.4,
        )

    @staticmethod
    def _make_correlation_id(*, campaign_id: str, operation_id: str, field_path: str) -> str:
        base = "|".join([str(campaign_id or ""), str(operation_id or ""), str(field_path or ""), str(time.time_ns())])
        h = hashlib.sha256(base.encode("utf-8")).hexdigest()[:16]
        camp = hashlib.sha256(str(campaign_id or "").encode("utf-8")).hexdigest()[:6]
        op = hashlib.sha256(str(operation_id or "").encode("utf-8")).hexdigest()[:6]
        fld = hashlib.sha256(str(field_path or "").encode("utf-8")).hexdigest()[:6]
        return f"ssrf_{camp}_{op}_{fld}_{h}"

    @staticmethod
    def _details_base(
        *,
        validation_mode: str,
        operation_id: str,
        method: str,
        path: str,
        field_name: str,
        field_path: str,
        auth_mode: str,
        auth_profile_id: str,
        role_hint: str,
        correlation_id: str,
    ) -> dict[str, Any]:
        return {
            "validation_mode": validation_mode,
            "operation_id": operation_id,
            "method": method,
            "path": path,
            "field_name": field_name,
            "field_path": field_path,
            "auth_mode": auth_mode,
            "auth_profile_id": auth_profile_id,
            "role_hint": role_hint,
            "correlation_id": correlation_id,
        }

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
                    observation_type="ssrf_probe_result",
                    confidence=confidence,
                    details=observation_details,
                )
            ],
            artifacts=[],
            errors=errs,
        )

    @staticmethod
    def _replace_callback_placeholder(body_json: Any, *, callback_url: str) -> dict[str, Any]:
        def _walk(v: Any) -> Any:
            if isinstance(v, str) and v == "{{SSRF_CALLBACK_URL}}":
                return callback_url
            if isinstance(v, dict):
                return {str(k): _walk(val) for k, val in v.items()}
            if isinstance(v, list):
                return [_walk(x) for x in v]
            return v
        if not isinstance(body_json, dict):
            return {}
        return _walk(body_json)

    @staticmethod
    def _validate_request_draft_for_ssrf(
        *,
        operation_id: str,
        method: str,
        path_template: str,
        field_name: str,
        field_path: str,
        draft: dict[str, Any],
        required_body_fields: list[str],
        allowed_body_fields: list[str],
        body_field_summaries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        forbidden_keys = {"authorization", "cookie", "token", "password", "bearer", "secret", "api_key", "raw_body", "raw_headers"}
        forbidden_values = ("localhost", "127.0.0.1", "0.0.0.0", "169.254.169.254", "file://", "gopher://", "ftp://")
        if str(draft.get("operation_id") or "").strip() != operation_id:
            return {"valid": False, "reason_code": "draft_operation_mismatch", "rejected_fields_count": 1}
        if str(draft.get("method") or "").strip().upper() != method:
            return {"valid": False, "reason_code": "draft_method_mismatch", "rejected_fields_count": 1}
        if str(draft.get("path_template") or "").strip() != path_template:
            return {"valid": False, "reason_code": "draft_path_mismatch", "rejected_fields_count": 1}
        if str(draft.get("content_type") or "").strip().lower() != "application/json":
            return {"valid": False, "reason_code": "draft_content_type_invalid", "rejected_fields_count": 1}
        body_json = draft.get("body_json")
        if not isinstance(body_json, dict):
            return {"valid": False, "reason_code": "draft_body_json_invalid", "rejected_fields_count": 1}

        rejected = 0
        found_placeholder = False

        def _walk(value: Any) -> None:
            nonlocal rejected, found_placeholder
            if isinstance(value, dict):
                for k, v in value.items():
                    key = str(k).strip().lower()
                    if key in forbidden_keys:
                        rejected += 1
                    _walk(v)
                return
            if isinstance(value, list):
                for item in value:
                    _walk(item)
                return
            if isinstance(value, str):
                lowered = value.strip().lower()
                if value == "{{SSRF_CALLBACK_URL}}":
                    found_placeholder = True
                for bad in forbidden_values:
                    if bad in lowered:
                        rejected += 1
                        break
                for bad in forbidden_keys:
                    if bad in lowered:
                        rejected += 1
                        break

        _walk(body_json)
        if not SsrfProbeAdapter._field_path_has_placeholder(body_json, field_path=field_path, field_name=field_name):
            return {"valid": False, "reason_code": "draft_missing_callback_placeholder_in_target", "rejected_fields_count": max(1, rejected)}
        if not found_placeholder:
            return {"valid": False, "reason_code": "draft_missing_callback_placeholder", "rejected_fields_count": max(1, rejected)}
        if allowed_body_fields:
            unknown = [k for k in body_json.keys() if str(k) not in set(allowed_body_fields)]
            if unknown:
                return {"valid": False, "reason_code": "draft_unknown_body_field", "rejected_fields_count": len(unknown)}
        summary_by_name = {
            str(item.get("name") or ""): item
            for item in body_field_summaries
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        }
        missing_required = [f for f in required_body_fields if f not in body_json]
        for f in required_body_fields:
            row = summary_by_name.get(f) or {}
            if SsrfProbeAdapter._is_secret_like_field(f) and f in body_json:
                return {"valid": False, "reason_code": "draft_secret_like_field_present", "rejected_fields_count": 1}
            if bool(row.get("unsafe_to_synthesize")) and f in body_json:
                return {"valid": False, "reason_code": "draft_unsafe_field_present", "rejected_fields_count": 1}
        if rejected > 0:
            return {"valid": False, "reason_code": "draft_forbidden_content", "rejected_fields_count": rejected}

        headers = draft.get("headers")
        if headers is not None and (not isinstance(headers, dict) or set(str(k) for k in headers.keys()) - {"Content-Type"}):
            return {"valid": False, "reason_code": "draft_headers_invalid", "rejected_fields_count": 1}
        query_params = draft.get("query_params")
        if query_params is not None and not isinstance(query_params, dict):
            return {"valid": False, "reason_code": "draft_query_invalid", "rejected_fields_count": 1}

        return {
            "valid": True,
            "rejected_fields_count": 0,
            "filled_required_fields_count": len(required_body_fields) - len(missing_required),
            "missing_required_fields_count": len(missing_required),
            "synthesized_field_count": len(body_json.keys()),
        }

    @staticmethod
    def _is_secret_like_field(name: str) -> bool:
        lowered = str(name or "").strip().lower()
        if not lowered:
            return False
        tokens = (
            "password", "pass", "passwd", "token", "access_token", "refresh_token", "secret",
            "api_key", "apikey", "authorization", "cookie", "session", "credential",
        )
        return any(token in lowered for token in tokens) or lowered == "key"

    @staticmethod
    def _field_path_has_placeholder(body_json: dict[str, Any], *, field_path: str, field_name: str) -> bool:
        target_key = str(field_name or "").strip()
        normalized = str(field_path or "").strip()
        if normalized.startswith("$."):
            target_key = normalized[2:].split(".", 1)[0] or target_key
        value = body_json.get(target_key)
        return value == "{{SSRF_CALLBACK_URL}}"

    def _synthesize_schema_payload(
        self,
        *,
        callback_url: str,
        target_field_name: str,
        target_field_path: str,
        required_body_fields: list[str],
        allowed_body_fields: list[str],
        body_field_summaries: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if not body_field_summaries and not required_body_fields:
            return {
                "body": {target_field_name: callback_url},
                "filled_required_fields_count": 1,
                "missing_required_fields_count": 0,
                "rejected_fields_count": 0,
                "synthesized_field_count": 1,
                "reason_codes": ["fallback_minimal_payload"],
            }
        summary_by_name = {
            str(item.get("name") or "").strip(): item
            for item in body_field_summaries
            if isinstance(item, dict) and str(item.get("name") or "").strip()
        }
        allowed = set(allowed_body_fields or list(summary_by_name.keys()) or [target_field_name])
        out: dict[str, Any] = {}
        filled = 0
        missing = 0
        rejected = 0
        reason_codes: list[str] = []
        target_root = str(target_field_name or "").strip()
        if str(target_field_path or "").startswith("$."):
            target_root = str(target_field_path)[2:].split(".", 1)[0] or target_root
        for field in required_body_fields:
            if field not in allowed:
                missing += 1
                continue
            row = summary_by_name.get(field, {})
            if self._is_secret_like_field(field):
                missing += 1
                reason_codes.append("required_secret_like_field_not_synthesized")
                continue
            value, ok = self._safe_default_for_field(row)
            if ok:
                out[field] = value
                filled += 1
            else:
                missing += 1
        if target_root in allowed:
            out[target_root] = callback_url
            if target_root in required_body_fields and target_root not in out:
                filled += 1
        for key in list(out.keys()):
            if key not in allowed:
                out.pop(key, None)
                rejected += 1
        return {
            "body": out or {target_field_name: callback_url},
            "filled_required_fields_count": filled,
            "missing_required_fields_count": missing,
            "rejected_fields_count": rejected,
            "synthesized_field_count": len(out or {target_field_name: callback_url}),
            "reason_codes": reason_codes[:10],
        }

    @staticmethod
    def _safe_default_for_field(summary: dict[str, Any]) -> tuple[Any, bool]:
        schema_type = str(summary.get("schema_type") or "unknown").strip().lower()
        enum_values = summary.get("enum_values_sample")
        if isinstance(enum_values, list) and enum_values:
            first = enum_values[0]
            if isinstance(first, (str, int, float, bool)):
                return first, True
        if schema_type == "string":
            return "test", True
        if schema_type in {"integer", "number"}:
            return 1, True
        if schema_type == "boolean":
            return True, True
        if schema_type == "array":
            return [], True
        if schema_type == "object":
            return {}, True
        return None, False
