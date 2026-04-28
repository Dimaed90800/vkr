from __future__ import annotations

import re
import time
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.resource_instance_store import ResourceInstanceStore
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.resource_instance_store import ResourceInstanceStore
    from storage.memory_store import memory_store


def _normalize_field_key(name: str) -> str:
    return re.sub(r"[\s_-]+", "", str(name or "").strip().lower())


_AGGREGATE_FIELD_DENYLIST_NORM: frozenset[str] = frozenset(
    {
        _normalize_field_key(x)
        for x in (
            "count",
            "total",
            "total_count",
            "totalCount",
            "amount",
            "quantity",
            "qty",
            "price",
            "page",
            "limit",
            "offset",
            "size",
            "status",
            "created_at",
            "updated_at",
            "timestamp",
            "message",
            "error",
            "ok",
            "success",
        )
    }
)

# URL path segment (lowercase) -> canonical resource_type for API context
_PATH_SEGMENT_TO_RESOURCE: dict[str, str] = {
    "order": "order",
    "orders": "order",
    "user": "user",
    "users": "user",
    "account": "user",
    "accounts": "user",
    "profile": "user",
    "me": "user",
    "vehicle": "vehicle",
    "vehicles": "vehicle",
    "car": "vehicle",
    "cars": "vehicle",
    "post": "post",
    "posts": "post",
    "video": "video",
    "videos": "video",
    "report": "report",
    "reports": "report",
    "product": "product",
    "products": "product",
    "item": "order",
    "items": "order",
    "shop": "order",
    "invoice": "order",
    "payment": "order",
}

_PREFIX_TO_RESOURCE: dict[str, str] = {
    "order": "order",
    "user": "user",
    "vehicle": "vehicle",
    "car": "vehicle",
    "post": "post",
    "video": "video",
    "report": "report",
    "product": "product",
    "account": "user",
    "item": "order",
    "invoice": "order",
    "payment": "order",
    "subscription": "order",
    "tenant": "user",
    "org": "user",
    "organization": "user",
    "session": "user",
}

# Explicit resource id field names -> (resource_type, confidence high)
_FIELD_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^vehicle(?:_?id)?$", re.I), "vehicle"),
    (re.compile(r"^car(?:_?id)?$", re.I), "vehicle"),
    (re.compile(r"^post(?:_?id)?$", re.I), "post"),
    (re.compile(r"^order(?:_?id)?$", re.I), "order"),
    (re.compile(r"^video(?:_?id)?$", re.I), "video"),
    (re.compile(r"^report(?:_?id)?$", re.I), "report"),
    (re.compile(r"^(?:user_?id|userid|userId)$", re.I), "user"),
)


def _path_suggests_resource_type(source_path: str) -> str | None:
    raw = str(source_path or "").strip()
    if not raw:
        return None
    segments = [s.lower() for s in raw.split("/") if s]
    for seg in segments:
        hit = _PATH_SEGMENT_TO_RESOURCE.get(seg)
        if hit:
            return hit
    return None


def _classify_id_field(
    field_name: str,
    source_path: str,
    *,
    inside_list_item: bool,
) -> tuple[str, str] | None:
    """Return (resource_type, confidence) or None if field name is not an id field pattern."""
    fn = str(field_name or "").strip()
    if not fn:
        return None
    for pattern, resource_type in _FIELD_PATTERNS:
        if pattern.match(fn):
            return resource_type, "high"
    m_snake = re.fullmatch(r"([A-Za-z0-9]+)_id", fn)
    if m_snake:
        prefix = m_snake.group(1).lower()
        mapped = _PREFIX_TO_RESOURCE.get(prefix)
        if mapped:
            return mapped, "high"
        path_hit = _path_suggests_resource_type(source_path)
        if path_hit:
            return path_hit, "medium"
        return "unknown", "low"
    m_camel = re.fullmatch(r"([a-z][a-z0-9]*)Id", fn)
    if m_camel:
        prefix = m_camel.group(1).lower()
        mapped = _PREFIX_TO_RESOURCE.get(prefix)
        if mapped:
            return mapped, "high"
        path_hit = _path_suggests_resource_type(source_path)
        if path_hit:
            return path_hit, "medium"
        return "unknown", "low"
    m_upper = re.fullmatch(r"([A-Z][A-Za-z0-9]*)ID", fn)
    if m_upper:
        prefix = m_upper.group(1).lower()
        mapped = _PREFIX_TO_RESOURCE.get(prefix)
        if mapped:
            return mapped, "high"
        path_hit = _path_suggests_resource_type(source_path)
        if path_hit:
            return path_hit, "medium"
        return "unknown", "low"
    if re.fullmatch(r"id", fn, flags=re.I):
        path_hit = _path_suggests_resource_type(source_path)
        if inside_list_item and path_hit:
            return path_hit, "medium"
        return "unknown", "low"
    return None


def _value_looks_like_id(value: Any) -> bool:
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, int):
        return value >= 0
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return False
        if len(stripped) > 128:
            return False
        return bool(re.fullmatch(r"[A-Za-z0-9:_-]{1,128}", stripped))
    return False


def _walk_for_object_ids(
    node: Any,
    *,
    source_path: str,
    seen: set[tuple[str, str]],
    out: list[dict[str, Any]],
    max_instances: int,
    counters: dict[str, int],
    parent_was_list: bool = False,
) -> None:
    if len(out) >= max_instances:
        return
    if isinstance(node, dict):
        for key, value in node.items():
            if len(out) >= max_instances:
                return
            fn = str(key)
            norm = _normalize_field_key(fn)
            if norm in _AGGREGATE_FIELD_DENYLIST_NORM:
                counters["aggregate_fields_filtered_count"] += 1
                counters["filtered_fields_count"] += 1
            else:
                cls = _classify_id_field(fn, source_path, inside_list_item=parent_was_list)
                if cls is not None:
                    resource_type, confidence = cls
                    if not _value_looks_like_id(value):
                        counters["filtered_fields_count"] += 1
                    else:
                        counters["candidate_fields_count"] += 1
                        if confidence == "low":
                            counters["low_confidence_filtered_count"] += 1
                            counters["filtered_fields_count"] += 1
                        else:
                            dedup = (fn, str(value))
                            if dedup not in seen:
                                seen.add(dedup)
                                out.append({
                                    "field_name": fn,
                                    "raw_object_id": value,
                                    "resource_type": resource_type,
                                    "confidence": confidence,
                                })
                                if len(out) >= max_instances:
                                    return
            if isinstance(value, (dict, list)):
                _walk_for_object_ids(
                    value,
                    source_path=source_path,
                    seen=seen,
                    out=out,
                    max_instances=max_instances,
                    counters=counters,
                    parent_was_list=False,
                )
    elif isinstance(node, list):
        limit = min(len(node), max(1, max_instances))
        for item in node[:limit]:
            if len(out) >= max_instances:
                return
            if isinstance(item, (dict, list)):
                _walk_for_object_ids(
                    item,
                    source_path=source_path,
                    seen=seen,
                    out=out,
                    max_instances=max_instances,
                    counters=counters,
                    parent_was_list=True,
                )


class ResourceInstanceExtractorAdapter:
    def __init__(self) -> None:
        self._artifacts = ArtifactStore()
        self._instances = ResourceInstanceStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        source_observation_id = str(inputs.get("source_observation_id") or "").strip()
        validation_mode = str(inputs.get("validation_mode") or "resource_instance_extraction").strip() or "resource_instance_extraction"
        max_instances = max(1, min(int(inputs.get("max_instances") or 20), 50))
        source = memory_store.get_observation(source_observation_id) if source_observation_id else None
        if source is None:
            return self._failed(command, tool_run_id, start_ms, "source_observation_not_found", "source_observation_id was not found.")
        details = source.get("details") if isinstance(source.get("details"), dict) else {}
        source_tool_run_id = str(source.get("tool_run_id") or "").strip()
        source_operation_id = str(details.get("operation_id") or source.get("operation_id") or "").strip()
        source_path = str(details.get("path") or "").strip()
        source_auth_profile_id = str(details.get("auth_profile_id") or "").strip()
        source_role_hint = str(details.get("role_hint") or "unknown").strip() or "unknown"
        raw_json = memory_store.get_runtime_response_json_secret(source_tool_run_id) if source_tool_run_id else None

        resource_rows: list[dict[str, Any]] = []
        reason_codes: list[str] = []
        counters = {
            "candidate_fields_count": 0,
            "filtered_fields_count": 0,
            "aggregate_fields_filtered_count": 0,
            "low_confidence_filtered_count": 0,
        }
        if raw_json is None:
            reason_codes = ["no_raw_values_available"]
        else:
            extracted: list[dict[str, Any]] = []
            _walk_for_object_ids(
                raw_json,
                source_path=source_path,
                seen=set(),
                out=extracted,
                max_instances=max_instances,
                counters=counters,
                parent_was_list=False,
            )
            for item in extracted:
                instance = self._instances.create_resource_instance(
                    campaign_id=campaign.campaign_id,
                    resource_type=str(item.get("resource_type") or "unknown"),
                    object_id_field=str(item.get("field_name") or ""),
                    raw_object_id=item.get("raw_object_id"),
                    source_operation_id=source_operation_id,
                    source_path=source_path,
                    source_auth_profile_id=source_auth_profile_id,
                    source_role_hint=source_role_hint,
                    confidence=str(item.get("confidence") or "low"),
                    created_by="resource_instance_extractor",
                    metadata={"source_observation_id": source_observation_id},
                )
                resource_rows.append({
                    "object_ref_id": instance.object_ref_id,
                    "resource_type": instance.resource_type,
                    "object_id_field": instance.object_id_field,
                    "object_id_ref": instance.object_id_ref,
                    "confidence": instance.confidence,
                })
            if resource_rows:
                reason_codes.append("resource_ids_extracted")
            if counters["aggregate_fields_filtered_count"]:
                reason_codes.append("aggregate_field_filtered")
            if counters["low_confidence_filtered_count"]:
                reason_codes.append("low_confidence_filtered")
            if not resource_rows:
                reason_codes.append("no_resource_ids_found")

        resource_types = sorted({str(row.get("resource_type") or "unknown") for row in resource_rows if str(row.get("resource_type") or "").strip()})
        obs_details: dict[str, Any] = {
            "source": "resource_instance_extractor",
            "validation_mode": validation_mode,
            "source_observation_id": source_observation_id,
            "source_operation_id": source_operation_id,
            "source_path": source_path,
            "source_auth_profile_id": source_auth_profile_id,
            "source_role_hint": source_role_hint,
            "resource_instances_count": len(resource_rows),
            "resource_types": resource_types,
            "object_refs": resource_rows[:20],
            "reason_codes": reason_codes,
            "candidate_fields_count": counters["candidate_fields_count"],
            "filtered_fields_count": counters["filtered_fields_count"],
            "aggregate_fields_filtered_count": counters["aggregate_fields_filtered_count"],
            "low_confidence_filtered_count": counters["low_confidence_filtered_count"],
        }
        observation = ToolResultObservationLite(
            observation_type="resource_instance_inventory",
            confidence=0.5 if resource_rows else 0.1,
            details=obs_details,
        )
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="resource_instance_inventory_summary",
            content={
                "validation_mode": validation_mode,
                "source_observation_id": source_observation_id,
                "source_operation_id": source_operation_id,
                "source_path": source_path,
                "source_auth_profile_id": source_auth_profile_id,
                "source_role_hint": source_role_hint,
                "resource_instances_count": len(resource_rows),
                "resource_types": resource_types,
                "object_refs_count": len(resource_rows),
                "reason_codes": reason_codes,
                "candidate_fields_count": counters["candidate_fields_count"],
                "filtered_fields_count": counters["filtered_fields_count"],
                "aggregate_fields_filtered_count": counters["aggregate_fields_filtered_count"],
                "low_confidence_filtered_count": counters["low_confidence_filtered_count"],
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
                request_count=0,
                success_count=1,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
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
