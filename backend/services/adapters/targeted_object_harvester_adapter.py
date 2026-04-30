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
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from backend.services.resource_instance_store import ResourceInstanceStore
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.api_graph_service import ApiGraphService
    from services.auth_profile_store import AuthProfileStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
    from services.resource_instance_store import ResourceInstanceStore


_RESOURCE_HINTS: dict[str, tuple[str, ...]] = {
    "post": ("post", "posts", "recent", "feed", "community"),
    "vehicle": ("vehicle", "vehicles", "garage"),
    "video": ("video", "videos", "media"),
    "order": ("order", "orders", "shop"),
}


def _semantic_id_kind(field_name: str, json_path: str) -> str:
    field = str(field_name or "").strip().lower()
    p = str(json_path or "").lower()
    if ".author." in p and field == "id":
        return "author_id"
    if ".owner." in p and field == "id":
        return "owner_id"
    if ".user." in p and field == "id":
        return "user_id"
    if field in {"vehicleid", "vehicle_id", "vin"} or ".vehicles[" in p or p.endswith(".author.vehicleid"):
        return "vehicle_id"
    if field in {"videoid", "video_id"} or ".videos[" in p:
        return "video_id"
    if field in {"orderid", "order_id"} or ".orders[" in p:
        return "order_id"
    if field in {"postid", "post_id"} or ".posts[" in p:
        return "post_id"
    if field in {"authorid", "author_id"} or ".author." in p:
        return "author_id"
    if field in {"ownerid", "owner_id"} or ".owner." in p:
        return "owner_id"
    if field in {"userid", "user_id"} or ".user." in p:
        return "user_id"
    return "resource_id" if field.endswith("id") or field.endswith("_id") else "unknown_id"


def _resource_type_for(kind: str, json_path: str) -> str:
    p = str(json_path or "").lower()
    if kind == "post_id" or ".posts[" in p:
        return "post"
    if kind == "vehicle_id" or ".vehicles[" in p:
        return "vehicle"
    if kind == "video_id" or ".videos[" in p:
        return "video"
    if kind == "order_id" or ".orders[" in p:
        return "order"
    return "unknown"


def _iter_ids(node: Any, path: str = "$", out: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    result = out if out is not None else []
    if isinstance(node, dict):
        for key, value in node.items():
            next_path = f"{path}.{key}"
            low = str(key).lower()
            if isinstance(value, (str, int)) and (low == "id" or low.endswith("id") or low.endswith("_id")):
                result.append({"field_name": str(key), "id_json_path": next_path, "raw_object_id": value})
            if isinstance(value, (dict, list)):
                _iter_ids(value, next_path, result)
    elif isinstance(node, list):
        for idx, item in enumerate(node[:200]):
            _iter_ids(item, f"{path}[{idx}]", result)
    return result


class TargetedObjectHarvesterAdapter:
    def __init__(self, http_client: SafeHttpClient | None = None) -> None:
        self._http = http_client or SafeHttpClient()
        self._graph = ApiGraphService()
        self._profiles = AuthProfileStore()
        self._instances = ResourceInstanceStore()

    def execute(self, command: WorkerCommand, campaign: Campaign, tool_run_id: str) -> ToolResult:
        start = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        role_hint = str(inputs.get("role_hint") or "owner").strip() or "owner"
        validation_mode = str(inputs.get("validation_mode") or "targeted_object_harvest").strip() or "targeted_object_harvest"
        max_requests = max(1, min(int(inputs.get("max_requests") or 10), 20))
        candidate_resource_types = [str(x).strip().lower() for x in (inputs.get("candidate_resource_types") or ["post", "vehicle", "video", "order"]) if str(x).strip()]
        op_allow = {str(x).strip() for x in (inputs.get("candidate_operations") or []) if str(x).strip()}

        auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
        if not auth_profile_id:
            profile = self._profiles.find_profile_by_campaign_and_role(campaign.campaign_id, "owner")
            auth_profile_id = str(profile.auth_profile_id if profile is not None else "")
        profile = self._profiles.get_auth_profile(auth_profile_id) if auth_profile_id else None
        if profile is None:
            return self._result(
                command, tool_run_id, start, validation_mode, role_hint, auth_profile_id,
                requests=[], responses=[], refs=[], reason_codes=["owner_auth_profile_missing"], ops_count=0,
            )

        token = self._profiles.get_token_by_ref(str(getattr(profile, "token_ref", "") or ""))
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        if not headers:
            return self._result(
                command, tool_run_id, start, validation_mode, role_hint, auth_profile_id,
                requests=[], responses=[], refs=[], reason_codes=["owner_auth_secret_missing"], ops_count=0,
            )

        ops = self._graph.list_operations(campaign.campaign_id)
        selected: list[Operation] = []
        for op in ops:
            if str(op.method or "").upper() != "GET":
                continue
            if op_allow and str(op.operation_id or "") not in op_allow:
                continue
            path = str(op.path_template or "").lower()
            if "{" in path and "}" in path:
                continue
            if not any(any(h in path for h in _RESOURCE_HINTS.get(rt, ())) for rt in candidate_resource_types):
                continue
            selected.append(op)
        selected = selected[:max_requests]

        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        safe_refs: list[dict[str, Any]] = []
        reasons: list[str] = []
        for idx, op in enumerate(selected, start=1):
            url = urljoin(campaign.target_url.rstrip("/") + "/", str(op.path_template or "").lstrip("/"))
            req_id = f"req_toh_{idx}"
            requests.append(ToolResultRequest(
                request_id=req_id,
                role="owner",
                method="GET",
                url=sanitize_url_for_storage(url),
                path_template=str(op.path_template or ""),
            ))
            res = self._http.request(
                campaign=campaign,
                method="GET",
                url=url,
                headers=headers,
                timeout_sec=min(int(command.budget.timeout_sec or 10), 15),
                max_response_bytes=262144,
                follow_redirects=False,
            )
            sc = int(res.status_code or 0)
            responses.append(ToolResultResponse(request_id=req_id, status_code=sc))
            if res.error is not None or sc < 200 or sc > 299:
                continue
            body = res.get_raw_response_body()
            if not isinstance(body, (dict, list)):
                continue
            ctype = str(res.response_content_type or "")
            ids = _iter_ids(body)
            for item in ids:
                kind = _semantic_id_kind(str(item.get("field_name") or ""), str(item.get("id_json_path") or ""))
                if kind in {"author_id", "owner_id", "user_id", "unknown_id"}:
                    continue
                rtype = _resource_type_for(kind, str(item.get("id_json_path") or ""))
                instance = self._instances.create_resource_instance(
                    campaign_id=campaign.campaign_id,
                    resource_type=rtype,
                    object_id_field=str(item.get("field_name") or ""),
                    raw_object_id=item.get("raw_object_id"),
                    source_operation_id=str(op.operation_id or ""),
                    source_path=str(op.path_template or ""),
                    source_auth_profile_id=auth_profile_id,
                    source_role_hint=role_hint,
                    confidence="high",
                    created_by="targeted_object_harvester",
                    metadata={
                        "id_json_path": str(item.get("id_json_path") or ""),
                        "semantic_id_kind": kind,
                        "source_method": "GET",
                        "source_status_code": sc,
                        "source_content_type": ctype,
                        "owner_evidence": bool(role_hint == "owner" and 200 <= sc <= 299),
                        "reason_codes": ["targeted_harvest_id_match", "safe_get_only", f"semantic_{kind}"],
                    },
                )
                safe_refs.append({
                    "object_ref_id": instance.object_ref_id,
                    "object_id_ref": instance.object_id_ref,
                    "resource_type": instance.resource_type,
                    "semantic_id_kind": kind,
                    "object_id_field": instance.object_id_field,
                    "id_json_path": str(instance.metadata.get("id_json_path") or ""),
                    "source_operation_id": str(op.operation_id or ""),
                    "source_method": "GET",
                    "source_path": str(op.path_template or ""),
                    "source_status_code": sc,
                    "source_content_type": ctype,
                    "owner_evidence": bool(role_hint == "owner"),
                    "confidence": "high",
                    "reason_codes": list(instance.metadata.get("reason_codes") or []),
                })

        if safe_refs:
            reasons.append("typed_object_refs_created")
        elif selected:
            reasons.append("no_typed_object_refs_found")
        else:
            reasons.append("no_safe_get_operations")

        return self._result(
            command, tool_run_id, start, validation_mode, role_hint, auth_profile_id,
            requests=requests, responses=responses, refs=safe_refs[:100], reason_codes=reasons, ops_count=len(selected),
        )

    def _result(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        validation_mode: str,
        role_hint: str,
        auth_profile_id: str,
        *,
        requests: list[ToolResultRequest],
        responses: list[ToolResultResponse],
        refs: list[dict[str, Any]],
        reason_codes: list[str],
        ops_count: int,
    ) -> ToolResult:
        by_kind: dict[str, int] = {"post_id": 0, "vehicle_id": 0, "video_id": 0, "order_id": 0}
        for r in refs:
            k = str(r.get("semantic_id_kind") or "")
            if k in by_kind:
                by_kind[k] += 1
        details = {
            "source": "targeted_object_harvester",
            "validation_mode": validation_mode,
            "auth_profile_id": auth_profile_id,
            "role_hint": role_hint,
            "harvest_policy": "safe_get_only",
            "harvested_operations_count": ops_count,
            "http_calls_count": len(requests),
            "object_refs_created_count": len(refs),
            "targeted_post_id_count": by_kind["post_id"],
            "targeted_vehicle_id_count": by_kind["vehicle_id"],
            "targeted_video_id_count": by_kind["video_id"],
            "targeted_order_id_count": by_kind["order_id"],
            "object_refs": refs[:50],
            "reason_codes": [str(x) for x in reason_codes if str(x).strip()][:20],
        }
        dur = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=len(requests),
                success_count=sum(1 for r in responses if int(r.status_code or 0) >= 200 and int(r.status_code or 0) < 300),
                client_error_count=sum(1 for r in responses if int(r.status_code or 0) >= 400 and int(r.status_code or 0) < 500),
                server_error_count=sum(1 for r in responses if int(r.status_code or 0) >= 500),
                duration_ms=dur,
            ),
            observations=[
                ToolResultObservationLite(
                    observation_type="targeted_object_harvest_result",
                    confidence=0.9 if refs else 0.5,
                    details=details,
                )
            ],
            requests=requests,
            responses=responses,
            errors=[],
            artifacts=[],
        )
