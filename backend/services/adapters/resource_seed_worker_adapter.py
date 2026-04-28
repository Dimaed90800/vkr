"""Diagnostic-only resource seed worker.

Goal: obtain at least one high/medium-confidence object_id_ref in ResourceInstanceStore
using one bounded owner-auth create-like request (and optional one follow-up GET).

This worker must not:
- create findings
- call Judge
- store raw payload/response bodies in observations/artifacts
"""

from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin

try:
    from backend.models.api_graph import Operation
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
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.artifact_store import ArtifactStore
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from backend.services.resource_instance_store import ResourceInstanceStore
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
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
    from services.api_graph_service import ApiGraphService
    from services.artifact_store import ArtifactStore
    from services.auth_profile_store import AuthProfileStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from services.resource_instance_store import ResourceInstanceStore


_FORBIDDEN_PATH_PARTS = (
    "auth",
    "login",
    "signup",
    "register",
    "password",
    "reset",
    "otp",
    "token",
    "refresh",
    "admin",
    "management",
    "internal",
    "moderation",
    "upload",
    "multipart",
    "file",
    "binary",
    "video-upload",
    "payment",
    "coupon",
    "checkout",
    "redeem",
)

_CREATE_HINTS = ("create", "add", "new", "submit")

_URLISH_FIELD_PARTS = ("url", "uri", "link", "callback", "redirect", "webhook", "endpoint", "host", "domain")

_SECRET_FIELD_PARTS = ("password", "passwd", "token", "secret", "authorization", "cookie", "session", "jwt", "refresh")


def _snake_case_name(value: str) -> str:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(value or ""))
    text = re.sub(r"[^a-zA-Z0-9]+", "_", text)
    return text.strip("_").lower()


def _operation_url(target_url: str, path_template: str) -> str:
    return urljoin(str(target_url or "").rstrip("/") + "/", str(path_template or "").lstrip("/"))


def _append_unique(reason_codes: list[str], code: str) -> None:
    if code and code not in reason_codes:
        reason_codes.append(code)


def _value_looks_like_id(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped or len(stripped) > 128:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", stripped))
    return False


def _resource_hint_from_path(path: str) -> str:
    lowered = str(path or "").lower()
    for hint in ("order", "vehicle", "post", "video", "report", "comment"):
        if f"/{hint}" in lowered or f"/{hint}s" in lowered:
            return hint
    return "unknown"


def _classify_id_field(field_name: str, *, source_path: str, inside_list_item: bool) -> tuple[str, str] | None:
    """Return (resource_type, confidence) or None if not an id field."""
    fn = str(field_name or "").strip()
    if not fn:
        return None
    normalized = _snake_case_name(fn)
    # explicit high-confidence patterns
    for prefix in ("order", "vehicle", "car", "post", "video", "report", "user"):
        if normalized in {f"{prefix}id", f"{prefix}_id"}:
            rtype = "vehicle" if prefix == "car" else prefix
            return rtype, "high"
    if normalized.endswith("_id") and len(normalized) > 3:
        # unknown prefix, but still id-like; use path hint as medium
        hinted = _resource_hint_from_path(source_path)
        return hinted, "medium" if hinted != "unknown" else "low"
    if re.fullmatch(r"[a-z][a-z0-9]*id", fn) or re.fullmatch(r"[A-Z][A-Za-z0-9]*ID", fn):
        hinted = _resource_hint_from_path(source_path)
        return hinted, "medium" if hinted != "unknown" else "low"
    if normalized == "id":
        hinted = _resource_hint_from_path(source_path)
        if inside_list_item and hinted != "unknown":
            return hinted, "medium"
        return "unknown", "low"
    return None


def _extract_first_object_id(
    payload: Any,
    *,
    source_path: str,
    max_depth: int = 6,
    parent_was_list: bool = False,
) -> tuple[str, str, str, Any] | tuple[None, None, None, None]:
    """Return (resource_type, confidence, field_name, raw_id) or (None,...)."""
    if max_depth <= 0:
        return None, None, None, None
    if isinstance(payload, dict):
        for key, value in payload.items():
            cls = _classify_id_field(str(key), source_path=source_path, inside_list_item=parent_was_list)
            if cls is not None:
                rtype, conf = cls
                if conf in {"high", "medium"} and _value_looks_like_id(value):
                    return rtype, conf, str(key), value
            if isinstance(value, (dict, list)):
                found = _extract_first_object_id(
                    value,
                    source_path=source_path,
                    max_depth=max_depth - 1,
                    parent_was_list=False,
                )
                if found[0] is not None:
                    return found
    elif isinstance(payload, list):
        for item in payload[:10]:
            found = _extract_first_object_id(
                item,
                source_path=source_path,
                max_depth=max_depth - 1,
                parent_was_list=True,
            )
            if found[0] is not None:
                return found
    return None, None, None, None


def _looks_json_creatable(op: Operation) -> bool:
    if str(op.method or "").upper() not in {"POST", "PUT", "PATCH"}:
        return False
    path = str(op.path_template or "")
    blob = " ".join([str(op.operation_id or ""), path, str(op.summary or ""), " ".join(op.tags or [])]).lower()
    if any(part in blob for part in _FORBIDDEN_PATH_PARTS):
        return False
    if op.path_params:
        return False
    body_fields = [str(x) for x in (op.body_fields or []) if str(x).strip()]
    if not body_fields:
        return False
    lowered_fields = [_snake_case_name(x) for x in body_fields]
    if any(any(p in f for p in _SECRET_FIELD_PARTS) for f in lowered_fields):
        return False
    if any(any(p in f for p in _URLISH_FIELD_PARTS) for f in lowered_fields):
        return False
    return True


def _seed_score(op: Operation) -> float:
    if not _looks_json_creatable(op):
        return -1e9
    score = 0.0
    path = str(op.path_template or "").lower()
    opid = str(op.operation_id or "").lower()
    blob = f"{path} {opid} {' '.join(op.tags or [])} {str(op.summary or '').lower()}"
    if any(h in blob for h in _CREATE_HINTS):
        score += 50.0
    if op.auth_required:
        score += 20.0
    rtype = str(op.resource_type or "").strip().lower() or _resource_hint_from_path(path)
    if rtype in {"order", "vehicle", "post", "report"}:
        score += 25.0
    elif rtype in {"video", "comment"}:
        score += 10.0
    fields = [str(x) for x in (op.body_fields or []) if str(x).strip()]
    score -= float(len(fields)) * 2.0
    if any(_snake_case_name(x) in {"name", "title", "content", "description", "comment"} for x in fields):
        score += 5.0
    if any(_snake_case_name(x) in {"status", "state", "role"} for x in fields):
        score -= 10.0
    return score


def _build_payload(op: Operation) -> tuple[dict[str, Any], list[str]]:
    reason_codes: list[str] = []
    payload: dict[str, Any] = {}
    for raw in op.body_fields or []:
        key = str(raw or "").strip()
        if not key:
            continue
        nk = _snake_case_name(key)
        if any(part in nk for part in _SECRET_FIELD_PARTS):
            _append_unique(reason_codes, "blocked_secret_field_in_body")
            return {}, reason_codes
        if nk in {"id", "user_id", "owner_id", "account_id"} or nk.endswith("_id"):
            # do not attempt to provide unknown object refs
            _append_unique(reason_codes, "blocked_required_object_ref")
            return {}, reason_codes
        if any(part in nk for part in _URLISH_FIELD_PARTS):
            _append_unique(reason_codes, "blocked_url_field_in_body")
            return {}, reason_codes
        if nk in {"count", "total", "quantity", "qty", "amount", "price", "limit", "offset", "page", "size"}:
            payload[key] = 1
        elif nk.startswith(("is_", "has_")) or nk in {"enabled", "active"}:
            payload[key] = False
        elif "email" in nk:
            payload[key] = "seed@example.com"
        elif nk in {"name", "title"}:
            payload[key] = "VKR Seed"
        elif nk in {"description", "content", "comment", "message"}:
            payload[key] = "VKR seed payload"
        elif "phone" in nk or nk == "number":
            payload[key] = "0000000000"
        else:
            payload[key] = f"seed_{nk}"[:64]
    return payload, reason_codes


class ResourceSeedWorkerAdapter:
    def __init__(
        self,
        http_client: SafeHttpClient | None = None,
        graph: ApiGraphService | None = None,
        auth_profiles: AuthProfileStore | None = None,
        instances: ResourceInstanceStore | None = None,
    ) -> None:
        self._http = http_client or SafeHttpClient()
        self._graph = graph or ApiGraphService()
        self._profiles = auth_profiles or AuthProfileStore()
        self._instances = instances or ResourceInstanceStore()
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}

        validation_mode = str(inputs.get("validation_mode") or "resource_seed").strip() or "resource_seed"
        owner_auth_profile_id = str(inputs.get("owner_auth_profile_id") or "").strip()
        try:
            max_seed_attempts = int(inputs.get("max_seed_attempts") or 1)
        except Exception:
            max_seed_attempts = 1
        if max_seed_attempts < 1:
            max_seed_attempts = 1
        if max_seed_attempts > 3:
            max_seed_attempts = 3
        try:
            max_followup_requests = int(inputs.get("max_followup_requests") or 0)
        except Exception:
            max_followup_requests = 0
        if max_followup_requests < 0:
            max_followup_requests = 0
        if max_followup_requests > 1:
            max_followup_requests = 1
        # Fast batch bound: total HTTP calls <= 3 for this worker run.
        max_http_calls = 3

        reason_codes: list[str] = []
        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []

        profile = self._profiles.get_auth_profile(owner_auth_profile_id) if owner_auth_profile_id else None
        if profile is None:
            return self._finished(
                command, tool_run_id, start_ms,
                requests=requests, responses=responses,
                details=self._details(
                    validation_mode=validation_mode,
                    seed_status="blocked",
                    resource_type="unknown",
                    owner_auth_profile_id=owner_auth_profile_id,
                    seed_operation_id="",
                    seed_method="",
                    seed_path="",
                    followup_operation_id="",
                    followup_method="",
                    followup_path="",
                    object_refs=[],
                    http_calls_count=0,
                    attempts_count=0,
                    failed_count=0,
                    reason_codes=["owner_auth_profile_not_found"],
                ),
            )

        headers: dict[str, Any] = {}
        cookies: dict[str, Any] = {}
        if str(profile.auth_type or "") == "bearer":
            token = self._profiles.get_token_by_ref(str(profile.token_ref or ""))
            if token:
                headers["Authorization"] = f"Bearer {token}"
        elif str(profile.auth_type or "") == "cookie":
            token = self._profiles.get_token_by_ref(str(profile.token_ref or ""))
            if isinstance(token, dict) and token:
                cookies = dict(token)
        if not headers and not cookies:
            return self._finished(
                command, tool_run_id, start_ms,
                requests=requests, responses=responses,
                details=self._details(
                    validation_mode=validation_mode,
                    seed_status="blocked",
                    resource_type="unknown",
                    owner_auth_profile_id=owner_auth_profile_id,
                    seed_operation_id="",
                    seed_method="",
                    seed_path="",
                    followup_operation_id="",
                    followup_method="",
                    followup_path="",
                    object_refs=[],
                    http_calls_count=0,
                    attempts_count=0,
                    failed_count=0,
                    reason_codes=["owner_auth_secret_missing"],
                ),
            )

        seed_ops = self._select_seed_operations(campaign.campaign_id, inputs, max_seed_attempts)
        if not seed_ops:
            return self._finished(
                command, tool_run_id, start_ms,
                requests=requests, responses=responses,
                details=self._details(
                    validation_mode=validation_mode,
                    seed_status="no_seedable_operation",
                    resource_type="unknown",
                    owner_auth_profile_id=owner_auth_profile_id,
                    seed_operation_id="",
                    seed_method="",
                    seed_path="",
                    followup_operation_id="",
                    followup_method="",
                    followup_path="",
                    object_refs=[],
                    http_calls_count=0,
                    attempts_count=0,
                    failed_count=0,
                    reason_codes=["no_seedable_operation"],
                ),
            )
        attempts_count = 0
        failed_count = 0
        safe_refs: list[dict[str, Any]] = []
        last_seed_op: Operation | None = None
        last_followup_op: Operation | None = None
        last_seed_status = "no_object_id_found"
        for seed_op in seed_ops:
            if len(requests) >= max_http_calls:
                _append_unique(reason_codes, "seed_http_budget_exhausted")
                break
            attempts_count += 1
            last_seed_op = seed_op
            payload, payload_rc = _build_payload(seed_op)
            reason_codes.extend(payload_rc)
            if not payload and payload_rc:
                failed_count += 1
                last_seed_status = "blocked"
                continue

            seed_url = _operation_url(campaign.target_url, seed_op.path_template)
            req_id = f"req_seed_create_{attempts_count}"
            result = self._http.request(
                campaign,
                method=str(seed_op.method or "POST").upper(),
                url=seed_url,
                headers=headers or None,
                cookies=cookies or None,
                body=payload,
                timeout_sec=min(int(command.budget.timeout_sec or 10), 15),
                max_response_bytes=262144,
                follow_redirects=False,
            )
            requests.append(ToolResultRequest(
                request_id=req_id,
                role="owner",
                method=str(seed_op.method or "POST").upper(),
                url=sanitize_url_for_storage(seed_url),
                path_template=str(seed_op.path_template or ""),
            ))
            sc = int(result.status_code or 0)
            responses.append(ToolResultResponse(request_id=req_id, status_code=sc))

            if result.error is not None:
                failed_count += 1
                last_seed_status = "request_error"
                _append_unique(reason_codes, "request_error")
                continue
            if not (200 <= sc <= 299):
                failed_count += 1
                last_seed_status = "creation_non_2xx"
                _append_unique(reason_codes, "creation_non_2xx")
                continue

            raw_body = result.get_raw_response_body()
            rtype, conf, field_name, raw_id = _extract_first_object_id(raw_body, source_path=str(seed_op.path_template or ""))
            if (
                (rtype is None or conf is None or field_name is None)
                and max_followup_requests > 0
                and len(requests) < max_http_calls
            ):
                followup_op = self._pick_followup_get_operation(campaign.campaign_id, seed_op)
                if followup_op is not None:
                    followup_url = _operation_url(campaign.target_url, followup_op.path_template)
                    req_follow = f"req_seed_followup_{attempts_count}"
                    follow_res = self._http.request(
                        campaign,
                        method="GET",
                        url=followup_url,
                        headers=headers or None,
                        cookies=cookies or None,
                        body=None,
                        timeout_sec=min(int(command.budget.timeout_sec or 10), 15),
                        max_response_bytes=262144,
                        follow_redirects=False,
                    )
                    requests.append(ToolResultRequest(
                        request_id=req_follow,
                        role="owner",
                        method="GET",
                        url=sanitize_url_for_storage(followup_url),
                        path_template=str(followup_op.path_template or ""),
                    ))
                    follow_sc = int(follow_res.status_code or 0)
                    responses.append(ToolResultResponse(request_id=req_follow, status_code=follow_sc))
                    last_followup_op = followup_op
                    if follow_res.error is None and 200 <= follow_sc <= 299:
                        follow_body = follow_res.get_raw_response_body()
                        rtype, conf, field_name, raw_id = _extract_first_object_id(
                            follow_body,
                            source_path=str(followup_op.path_template or ""),
                        )

            if rtype is None or conf is None or field_name is None:
                failed_count += 1
                last_seed_status = "no_object_id_found"
                _append_unique(reason_codes, "no_object_id_found")
                continue

            instance = self._instances.create_resource_instance(
                campaign_id=campaign.campaign_id,
                resource_type=str(rtype or "unknown"),
                object_id_field=str(field_name or ""),
                raw_object_id=raw_id,
                source_operation_id=seed_op.operation_id,
                source_path=str(seed_op.path_template or ""),
                source_auth_profile_id=owner_auth_profile_id,
                source_role_hint="owner",
                confidence=conf,
                created_by="resource_seed_worker",
                metadata={"tool_run_id": tool_run_id, "stage": "seed_create", "attempt": attempts_count},
            )
            safe_refs.append({
                "object_ref_id": instance.object_ref_id,
                "object_id_ref": instance.object_id_ref,
                "object_id_field": instance.object_id_field,
                "resource_type": instance.resource_type,
                "confidence": instance.confidence,
            })
            last_seed_status = "seeded"
            _append_unique(reason_codes, "resource_ids_extracted")

        if safe_refs:
            return self._finished(
                command, tool_run_id, start_ms,
                requests=requests, responses=responses,
                details=self._details(
                    validation_mode=validation_mode,
                    seed_status="seeded",
                    resource_type=str(safe_refs[0].get("resource_type") or "unknown"),
                    owner_auth_profile_id=owner_auth_profile_id,
                    seed_operation_id=str(last_seed_op.operation_id if last_seed_op is not None else ""),
                    seed_method=str(last_seed_op.method if last_seed_op is not None else "").upper(),
                    seed_path=str(last_seed_op.path_template if last_seed_op is not None else ""),
                    followup_operation_id=str(last_followup_op.operation_id if last_followup_op is not None else ""),
                    followup_method="GET" if last_followup_op is not None else "",
                    followup_path=str(last_followup_op.path_template if last_followup_op is not None else ""),
                    object_refs=safe_refs,
                    http_calls_count=len(requests),
                    attempts_count=attempts_count,
                    failed_count=failed_count,
                    reason_codes=reason_codes or ["resource_ids_extracted"],
                ),
            )

        return self._finished(
            command, tool_run_id, start_ms,
            requests=requests, responses=responses,
            details=self._details(
                validation_mode=validation_mode,
                seed_status=last_seed_status,
                resource_type=str(last_seed_op.resource_type if last_seed_op is not None else "unknown").lower() or "unknown",
                owner_auth_profile_id=owner_auth_profile_id,
                seed_operation_id=str(last_seed_op.operation_id if last_seed_op is not None else ""),
                seed_method=str(last_seed_op.method if last_seed_op is not None else "").upper(),
                seed_path=str(last_seed_op.path_template if last_seed_op is not None else ""),
                followup_operation_id=str(last_followup_op.operation_id if last_followup_op is not None else ""),
                followup_method="GET" if last_followup_op is not None else "",
                followup_path=str(last_followup_op.path_template if last_followup_op is not None else ""),
                object_refs=[],
                http_calls_count=len(requests),
                attempts_count=attempts_count,
                failed_count=failed_count,
                reason_codes=reason_codes or ["no_object_id_found"],
            ),
        )

    def _select_seed_operations(self, campaign_id: str, inputs: dict[str, Any], max_seed_attempts: int) -> list[Operation]:
        wanted = str(inputs.get("seed_operation_id") or "").strip()
        operations = self._graph.list_operations(campaign_id)
        if wanted:
            for op in operations:
                if op.operation_id == wanted:
                    return [op]
        scored = sorted(operations, key=_seed_score, reverse=True)
        picked: list[Operation] = []
        seen_ops: set[str] = set()
        seen_resource_types: set[str] = set()
        for op in scored:
            if _seed_score(op) < -1e8:
                continue
            op_id = str(op.operation_id or "").strip()
            if not op_id or op_id in seen_ops:
                continue
            rtype = str(op.resource_type or "").strip().lower() or _resource_hint_from_path(op.path_template)
            # Prefer diversity across resource types where possible.
            if rtype and rtype in seen_resource_types and len(picked) < max_seed_attempts:
                continue
            picked.append(op)
            seen_ops.add(op_id)
            if rtype:
                seen_resource_types.add(rtype)
            if len(picked) >= max_seed_attempts:
                break
        # If diversity-filter skipped too much, fill with remaining top ops.
        if len(picked) < max_seed_attempts:
            for op in scored:
                if _seed_score(op) < -1e8:
                    continue
                op_id = str(op.operation_id or "").strip()
                if not op_id or op_id in seen_ops:
                    continue
                picked.append(op)
                seen_ops.add(op_id)
                if len(picked) >= max_seed_attempts:
                    break
        return picked

    def _pick_followup_get_operation(self, campaign_id: str, seed_op: Operation) -> Operation | None:
        operations = self._graph.list_operations(campaign_id)
        seed_path = str(seed_op.path_template or "").strip()
        for op in operations:
            if str(op.method or "").upper() != "GET":
                continue
            if str(op.path_template or "").strip() != seed_path:
                continue
            if op.path_params:
                continue
            return op
        return None

    @staticmethod
    def _details(
        *,
        validation_mode: str,
        seed_status: str,
        resource_type: str,
        owner_auth_profile_id: str,
        seed_operation_id: str,
        seed_method: str,
        seed_path: str,
        followup_operation_id: str,
        followup_method: str,
        followup_path: str,
        object_refs: list[dict[str, Any]],
        http_calls_count: int,
        attempts_count: int,
        failed_count: int,
        reason_codes: list[str],
    ) -> dict[str, Any]:
        return {
            "validation_mode": validation_mode,
            "seed_status": seed_status,
            "resource_type": resource_type,
            "owner_auth_profile_id": owner_auth_profile_id,
            "seed_operation_id": seed_operation_id,
            "seed_method": seed_method,
            "seed_path": seed_path,
            "followup_operation_id": followup_operation_id,
            "followup_method": followup_method,
            "followup_path": followup_path,
            "object_refs_created_count": len(object_refs),
            "object_refs": object_refs[:5],
            "http_calls_count": int(http_calls_count or 0),
            "resource_seed_attempts_count": int(attempts_count or 0),
            "resource_seed_failed_count": int(failed_count or 0),
            "reason_codes": list(reason_codes or [])[:20],
        }

    def _finished(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        *,
        requests: list[ToolResultRequest],
        responses: list[ToolResultResponse],
        details: dict[str, Any],
    ) -> ToolResult:
        observation = ToolResultObservationLite(
            observation_type="resource_seed_result",
            confidence=0.55 if details.get("seed_status") == "seeded" else 0.25,
            details=details,
        )
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="resource_seed_summary",
            content={
                "validation_mode": str(details.get("validation_mode") or "resource_seed"),
                "seed_status": str(details.get("seed_status") or ""),
                "resource_type": str(details.get("resource_type") or ""),
                "owner_auth_profile_id": str(details.get("owner_auth_profile_id") or ""),
                "seed_operation_id": str(details.get("seed_operation_id") or ""),
                "seed_method": str(details.get("seed_method") or ""),
                "seed_path": str(details.get("seed_path") or ""),
                "followup_operation_id": str(details.get("followup_operation_id") or ""),
                "object_refs_created_count": int(details.get("object_refs_created_count") or 0),
                "http_calls_count": int(details.get("http_calls_count") or 0),
                "resource_seed_attempts_count": int(details.get("resource_seed_attempts_count") or 0),
                "resource_seed_failed_count": int(details.get("resource_seed_failed_count") or 0),
                "reason_codes": list(details.get("reason_codes") or [])[:20],
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
                success_count=sum(1 for r in responses if 200 <= int(r.status_code or 0) <= 399),
                client_error_count=sum(1 for r in responses if 400 <= int(r.status_code or 0) <= 499),
                server_error_count=sum(1 for r in responses if 500 <= int(r.status_code or 0) <= 599),
                duration_ms=duration_ms,
            ),
            requests=requests,
            responses=responses,
            observations=[observation],
            artifacts=[artifact],
        )

    def _failed(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        code: str,
        message: str,
    ) -> ToolResult:
        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            errors=[ToolResultError(error_type=code, message=message, recoverable=False)],
        )
