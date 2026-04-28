"""Coverage-3A-1 — safe JSON response field inventory (names only, no values)."""
from __future__ import annotations

import json
import re
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
    from backend.services.api_graph_path_matcher import normalize_api_path
    from backend.services.artifact_store import ArtifactStore
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from backend.storage.memory_store import memory_store
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
    from services.api_graph_path_matcher import normalize_api_path
    from services.artifact_store import ArtifactStore
    from services.auth_profile_store import AuthProfileStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from storage.memory_store import memory_store


_SENSITIVE_NAME_PARTS: dict[str, tuple[str, ...]] = {
    "identity": (
        "email", "mail", "phone", "ssn", "passport", "firstname", "lastname",
        "birthday", "dob", "nationalid", "username", "fullname", "displayname",
    ),
    "authorization": (
        "role", "roles", "permission", "permissions", "scope", "isadmin",
        "admin", "authority", "authorities",
    ),
    "financial": (
        "amount", "price", "balance", "currency", "payment", "card", "credit",
        "invoice", "fee", "salary",
    ),
    "vehicle_location": (
        "vehicleid", "vehicle_id", "vin", "latitude", "longitude", "lat", "lng",
        "coordinate", "gps",
    ),
    "internal": (
        "stacktrace", "stack_trace", "debug", "trace", "hostname", "privatekey",
        "secret", "internalid",
    ),
}


def _classify_field(field_name: str) -> str:
    n = re.sub(r"[^a-z0-9]", "", str(field_name or "").lower())
    if not n:
        return "unknown"
    if n in {"password", "passwd", "apitoken", "apikey", "accesstoken", "refreshtoken"}:
        return "identity"
    for cat, needles in _SENSITIVE_NAME_PARTS.items():
        for nd in needles:
            if nd in n or n.endswith(nd) or n.startswith(nd):
                return cat
    return "unknown"


def _display_content_type(raw: str) -> str:
    s = str(raw or "").strip()
    if not s:
        return "unknown"
    return s.split(";", 1)[0].strip().lower()[:120]


def _probe_observation(
    *,
    operation_id: str,
    method: str,
    path_template: str,
    status_code: int,
    content_type_display: str,
    result: str,
    field_count: int,
    sensitive_field_count: int,
    sensitive_categories: list[str],
    reason_codes: list[str],
    auth_mode: str,
    auth_profile_id: str,
    role_hint: str,
) -> ToolResultObservationLite:
    return ToolResultObservationLite(
        observation_type="data_exposure_probe_result",
        confidence=0.12,
        details={
            "source": "data_exposure_validator",
            "operation_id": operation_id,
            "method": method,
            "path": path_template,
            "status_code": status_code,
            "content_type": content_type_display,
            "result": result,
            "field_count": field_count,
            "sensitive_field_count": sensitive_field_count,
            "sensitive_categories": sensitive_categories,
            "reason_codes": reason_codes,
            "auth_mode": auth_mode,
            "auth_profile_id": auth_profile_id,
            "role_hint": role_hint,
        },
    )


def _walk_fields(
    node: Any,
    path: str,
    *,
    depth: int,
    max_depth: int,
    out: list[tuple[str, str]],
    max_fields: int,
) -> None:
    if len(out) >= max_fields:
        return
    if depth >= max_depth:
        return
    if isinstance(node, dict):
        for k, v in node.items():
            if len(out) >= max_fields:
                return
            child = f"{path}.{k}" if path != "$" else f"$.{k}"
            if isinstance(v, dict):
                _walk_fields(v, child, depth=depth + 1, max_depth=max_depth, out=out, max_fields=max_fields)
            elif isinstance(v, list):
                if v and isinstance(v[0], (dict, list)):
                    _walk_fields(v[0], f"{child}[0]", depth=depth + 1, max_depth=max_depth, out=out, max_fields=max_fields)
            else:
                out.append((child, str(k)))
    elif isinstance(node, list) and node:
        if isinstance(node[0], (dict, list)):
            _walk_fields(node[0], f"{path}[0]", depth=depth + 1, max_depth=max_depth, out=out, max_fields=max_fields)


class DataExposureValidatorAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._artifacts = ArtifactStore()
        self._auth_profiles = AuthProfileStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        request_url = str(inputs.get("request_url") or "").strip()
        target_url = str(inputs.get("target_url") or "").strip()
        operation_id = str(inputs.get("operation_id") or command.operation_id or "").strip()
        path_template = normalize_api_path(str(inputs.get("path_template") or ""))
        method = str(inputs.get("method") or "GET").strip().upper() or "GET"
        validation_mode = str(
            inputs.get("validation_mode") or "response_field_inventory_check"
        ).strip() or "response_field_inventory_check"
        max_response_bytes = max(1024, int(inputs.get("max_response_bytes") or 262144))
        max_depth = max(1, int(inputs.get("max_depth") or 6))
        max_fields = max(1, int(inputs.get("max_fields") or 200))
        follow_same_origin_redirects = bool(inputs.get("follow_same_origin_redirects", True))
        max_redirects = max(0, min(int(inputs.get("max_redirects") or 2), 2))
        timeout_sec = min(command.budget.timeout_sec, campaign.limits.max_duration_sec, 15)
        auth_mode = str(inputs.get("auth_mode") or "unauthenticated").strip() or "unauthenticated"
        auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
        role_hint = "unknown"
        headers: dict[str, Any] = {}

        if method != "GET":
            return self._failed(
                command, tool_run_id, start_ms, "method_not_allowed", "data_exposure_validator supports GET only.",
            )
        if not request_url:
            return self._failed(
                command, tool_run_id, start_ms, "missing_request_url", "request_url is required.",
            )
        if auth_mode == "authenticated":
            if not auth_profile_id:
                return self._failed(
                    command, tool_run_id, start_ms, "auth_profile_missing", "auth_profile_id is required for authenticated mode.",
                )
            profile = self._auth_profiles.get_auth_profile(auth_profile_id)
            if profile is None:
                return self._failed(
                    command, tool_run_id, start_ms, "auth_profile_not_found", "Referenced auth_profile_id was not found.",
                )
            role_hint = str(profile.role_hint or "unknown")
            if str(profile.auth_type or "unknown") == "bearer":
                raw_token = self._auth_profiles.get_token_by_ref(profile.token_ref)
                token = str(raw_token or "").strip()
                if not token:
                    return self._failed(
                        command, tool_run_id, start_ms, "auth_profile_token_missing", "Auth profile token secret is missing.",
                    )
                headers["Authorization"] = f"Bearer {token}"
        else:
            auth_mode = "unauthenticated"

        safe_req = sanitize_url_for_storage(request_url)
        result = self._http.request(
            campaign,
            method="GET",
            url=request_url,
            headers=headers or None,
            timeout_sec=timeout_sec,
            max_response_bytes=max_response_bytes,
            follow_redirects=False,
            follow_same_origin_redirects=follow_same_origin_redirects,
            max_redirects=max_redirects,
        )
        status_code = int(result.status_code or 0)
        if result.error is not None and result.error.code in {
            "redirect_not_allowed",
            "redirect_host_not_allowed",
            "redirect_not_supported",
        }:
            reason_codes = ["redirect_response", "redirect_not_followed"]
            if result.error.code == "redirect_host_not_allowed":
                reason_codes.append("redirect_host_not_allowed")
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="redirect_response",
                reason_codes=reason_codes,
                content_type_display=_display_content_type(str(result.response_content_type or "")),
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
                redirect_same_origin=bool(result.redirect_same_origin),
                redirect_followed=bool(result.redirect_followed),
                redirect_count=int(result.redirect_count or 0),
            )
        if result.error is not None and result.error.code != "response_too_large":
            return self._failed(command, tool_run_id, start_ms, result.error.code, result.error.message)

        ct_raw = str(result.response_content_type or "")
        ct_display = _display_content_type(ct_raw)
        ct = ct_raw.lower()

        if status_code != 200:
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="non_200_response",
                reason_codes=["non_200_response"],
                content_type_display=ct_display,
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            )

        body = result.response_body
        if body is None:
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="empty_response",
                reason_codes=["empty_response"],
                content_type_display=ct_display or "application/json",
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            )

        text_body = body if isinstance(body, str) else ""
        looks_json = (
            "json" in ct
            or (isinstance(body, str) and text_body.strip()[:1] in "{[")
            or isinstance(body, (dict, list))
        )
        if not looks_json:
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="non_json_response",
                reason_codes=["non_json_response"],
                content_type_display=ct_display,
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            )

        if isinstance(body, str) and not text_body.strip():
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="empty_response",
                reason_codes=["empty_response"],
                content_type_display=ct_display or "application/json",
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            )

        try:
            parsed = json.loads(text_body) if isinstance(body, str) else body
        except Exception:
            return self._finished_empty(
                command=command,
                tool_run_id=tool_run_id,
                start_ms=start_ms,
                request_url=safe_req,
                path_template=path_template,
                operation_id=operation_id,
                method=method,
                validation_mode=validation_mode,
                status_code=status_code,
                probe_result="json_parse_failed",
                reason_codes=["json_parse_failed"],
                content_type_display=ct_display or "application/json",
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            )

        if auth_mode == "authenticated":
            memory_store.store_runtime_response_json_secret(tool_run_id, parsed)

        fields: list[tuple[str, str]] = []
        if isinstance(parsed, dict):
            _walk_fields(parsed, "$", depth=0, max_depth=max_depth, out=fields, max_fields=max_fields)
        elif isinstance(parsed, list) and parsed and isinstance(parsed[0], (dict, list)):
            _walk_fields(parsed[0], "$[0]", depth=0, max_depth=max_depth, out=fields, max_fields=max_fields)

        classified: list[dict[str, str]] = []
        for fp, fname in fields:
            cat = _classify_field(fname)
            classified.append({"field_name": fname, "field_path": fp, "category": cat})

        sensitive = [x for x in classified if x["category"] != "unknown"]
        sens_cats = sorted({x["category"] for x in sensitive})
        field_names_sample = [x["field_name"] for x in classified[:20]]
        json_ct = "application/json" if "json" in ct else (ct_display if ct_display != "unknown" else "application/json")
        if sensitive:
            probe_result = "sensitive_fields_found"
            probe_reason = ["sensitive_fields_found"]
        elif classified:
            probe_result = "fields_extracted"
            probe_reason = ["fields_extracted"]
        else:
            probe_result = "no_fields_found"
            probe_reason = ["no_fields_found"]

        observations: list[ToolResultObservationLite] = []
        inv_details: dict[str, Any] = {
            "tool_name": "data_exposure_validator",
            "operation_id": operation_id,
            "method": "GET",
            "path": path_template,
            "status_code": status_code,
            "content_type": json_ct,
            "field_count": len(classified),
            "sensitive_field_count": len(sensitive),
            "field_names_sample": field_names_sample,
            "sensitive_fields": sensitive[:50],
            "validation_mode": validation_mode,
            "auth_mode": auth_mode,
            "auth_profile_id": auth_profile_id,
            "role_hint": role_hint,
        }
        observations.append(ToolResultObservationLite(
            observation_type="response_field_inventory",
            confidence=0.35,
            details=inv_details,
        ))

        if sensitive:
            observations.append(ToolResultObservationLite(
                observation_type="data_exposure_signal",
                confidence=0.55,
                details={
                    "tool_name": "data_exposure_validator",
                    "operation_id": operation_id,
                    "method": "GET",
                    "path": path_template,
                    "status_code": status_code,
                    "sensitive_field_count": len(sensitive),
                    "sensitive_categories": sens_cats,
                    "sensitive_fields": sensitive[:50],
                    "security_relevance": "potential_sensitive_property_exposure",
                    "recommended_next_action": "review_response_schema_and_authorization_context",
                    "validation_mode": validation_mode,
                    "auth_mode": auth_mode,
                    "auth_profile_id": auth_profile_id,
                    "role_hint": role_hint,
                },
            ))

        observations.append(
            _probe_observation(
                operation_id=operation_id,
                method=method,
                path_template=path_template,
                status_code=status_code,
                content_type_display=json_ct,
                result=probe_result,
                field_count=len(classified),
                sensitive_field_count=len(sensitive),
                sensitive_categories=sens_cats,
                reason_codes=probe_reason,
                auth_mode=auth_mode,
                auth_profile_id=auth_profile_id,
                role_hint=role_hint,
            ),
        )

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="data_exposure_probe_summary",
            content={
                "result": probe_result,
                "field_count": len(classified),
                "sensitive_field_count": len(sensitive),
                "sensitive_categories": sens_cats,
                "operation_id": operation_id,
                "path": path_template,
                "status_code": status_code,
                "reason_codes": probe_reason,
                "auth_mode": auth_mode,
                "auth_profile_id": auth_profile_id,
                "role_hint": role_hint,
            },
        )

        duration_ms = int(time.monotonic() * 1000) - start_ms
        success = 1 if 200 <= status_code <= 299 else 0
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=1,
                success_count=success,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
            requests=[ToolResultRequest(
                request_id="",
                role=role_hint if auth_mode == "authenticated" else "",
                method="GET",
                url=safe_req,
                path_template=path_template,
            )],
            responses=[ToolResultResponse(request_id="", status_code=status_code)],
            observations=observations,
            artifacts=[artifact],
        )

    def _finished_empty(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        request_url: str,
        path_template: str,
        operation_id: str,
        method: str,
        validation_mode: str,
        status_code: int,
        probe_result: str,
        reason_codes: list[str],
        content_type_display: str,
        auth_mode: str,
        auth_profile_id: str,
        role_hint: str,
        field_count: int = 0,
        sensitive_field_count: int = 0,
        sensitive_categories: list[str] | None = None,
        redirect_same_origin: bool = False,
        redirect_followed: bool = False,
        redirect_count: int = 0,
    ) -> ToolResult:
        sens_cats = list(sensitive_categories or [])
        probe = _probe_observation(
            operation_id=operation_id,
            method=method,
            path_template=path_template,
            status_code=status_code,
            content_type_display=content_type_display,
            result=probe_result,
            field_count=field_count,
            sensitive_field_count=sensitive_field_count,
            sensitive_categories=sens_cats,
            reason_codes=reason_codes,
            auth_mode=auth_mode,
            auth_profile_id=auth_profile_id,
            role_hint=role_hint,
        )
        if probe_result == "redirect_response":
            probe.details["redirect_same_origin"] = bool(redirect_same_origin)
            probe.details["redirect_followed"] = bool(redirect_followed)
            probe.details["redirect_count"] = int(redirect_count or 0)
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="data_exposure_probe_summary",
            content={
                "result": probe_result,
                "field_count": field_count,
                "sensitive_field_count": sensitive_field_count,
                "sensitive_categories": sens_cats,
                "operation_id": operation_id,
                "path": path_template,
                "status_code": status_code,
                "reason_codes": reason_codes,
                "auth_mode": auth_mode,
                "auth_profile_id": auth_profile_id,
                "role_hint": role_hint,
                "redirect_same_origin": bool(redirect_same_origin),
                "redirect_followed": bool(redirect_followed),
                "redirect_count": int(redirect_count or 0),
            },
        )
        duration_ms = int(time.monotonic() * 1000) - start_ms
        success = 1 if 200 <= status_code <= 299 else 0
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=1,
                success_count=success,
                client_error_count=1 if 400 <= status_code <= 499 else 0,
                server_error_count=1 if status_code >= 500 else 0,
                duration_ms=duration_ms,
            ),
            requests=[ToolResultRequest(
                request_id="",
                role=role_hint if auth_mode == "authenticated" else "",
                method=method,
                url=request_url,
                path_template=path_template,
            )],
            responses=[ToolResultResponse(request_id="", status_code=status_code)],
            observations=[probe],
            artifacts=[artifact],
        )

    @staticmethod
    def _failed(
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        error_type: str,
        message: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=int(time.monotonic() * 1000) - start_ms),
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )
