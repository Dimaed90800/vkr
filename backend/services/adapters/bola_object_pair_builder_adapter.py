from __future__ import annotations

import re
import time
from typing import Any

try:
    from backend.models.api_graph import Operation
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.bola_object_pair_store import BolaObjectPairStore
    from backend.services.resource_instance_store import ResourceInstanceStore
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.api_graph_service import ApiGraphService
    from services.bola_object_pair_store import BolaObjectPairStore
    from services.resource_instance_store import ResourceInstanceStore


_RESOURCE_ALIASES: dict[str, set[str]] = {
    "vehicle": {"vehicle", "vehicles", "car", "cars", "vin"},
    "post": {"post", "posts", "article", "message"},
    "order": {"order", "orders", "purchase"},
    "video": {"video", "videos", "media"},
    "user": {"user", "users", "account", "profile"},
    "report": {"report", "reports"},
}


def _normalize_resource_type(raw: str) -> str:
    value = str(raw or "").strip().lower()
    if value in _RESOURCE_ALIASES:
        return value
    for canonical, aliases in _RESOURCE_ALIASES.items():
        if value in aliases:
            return canonical
    return "unknown"


def _id_like_name(name: str) -> bool:
    n = str(name or "").strip()
    if not n:
        return False
    if n.lower() == "id":
        return True
    if n.endswith("_id") or n.endswith("Id") or n.endswith("ID"):
        return True
    return bool(re.fullmatch(r"[A-Za-z]+(?:id|Id|ID)", n))


def _resource_specific_param_match(resource_type: str, param_name: str) -> bool:
    p = str(param_name or "").strip().lower().replace("_", "")
    aliases = _RESOURCE_ALIASES.get(resource_type, set())
    for alias in aliases:
        a = alias.replace("_", "")
        if p == f"{a}id" or p == a:
            return True
    return False


def _path_tokens(path_template: str) -> set[str]:
    return {seg.lower() for seg in str(path_template or "").split("/") if seg and not seg.startswith("{")}


def _extract_path_params(op: Operation) -> list[str]:
    if op.path_params:
        return [str(x) for x in op.path_params if str(x).strip()]
    return re.findall(r"{([^{}]+)}", str(op.path_template or ""))


class BolaObjectPairBuilderAdapter:
    def __init__(self) -> None:
        self._graph = ApiGraphService()
        self._instances = ResourceInstanceStore()
        self._pairs = BolaObjectPairStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        started = int(time.monotonic() * 1000)
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        validation_mode = str(inputs.get("validation_mode") or "bola_object_pair_building").strip() or "bola_object_pair_building"
        owner = str(inputs.get("owner_auth_profile_id") or "").strip()
        attacker = str(inputs.get("attacker_auth_profile_id") or "").strip()

        reason_codes: list[str] = []
        if not owner:
            reason_codes.append("owner_auth_profile_missing")
        if not attacker:
            reason_codes.append("attacker_auth_profile_missing")
        if reason_codes:
            return self._result(
                command=command,
                tool_run_id=tool_run_id,
                started_ms=started,
                validation_mode=validation_mode,
                object_pairs=[],
                reason_codes=reason_codes,
            )

        instances = self._instances.list_resource_instances(campaign.campaign_id)
        if not instances:
            return self._result(
                command=command,
                tool_run_id=tool_run_id,
                started_ms=started,
                validation_mode=validation_mode,
                object_pairs=[],
                reason_codes=["no_resource_instances_available"],
            )

        operations = self._graph.list_operations(campaign.campaign_id)
        built_pairs: list[dict[str, Any]] = []
        max_pairs = min(10, max(1, int(inputs.get("max_object_pairs") or 10)))
        for row in instances:
            if len(built_pairs) >= max_pairs:
                break
            resource_type = _normalize_resource_type(str(row.get("resource_type") or "unknown"))
            object_ref_id = str(row.get("object_ref_id") or "")
            object_id_ref = str(row.get("object_id_ref") or "")
            if not object_ref_id or not object_id_ref:
                continue
            ranked = self._rank_operations(operations, resource_type)
            if not ranked:
                continue
            for _, op, path_param_name, confidence, op_reasons in ranked:
                if len(built_pairs) >= max_pairs:
                    break
                created = self._pairs.create_bola_object_pair(
                    campaign_id=campaign.campaign_id,
                    resource_type=resource_type,
                    object_ref_id=object_ref_id,
                    object_id_ref=object_id_ref,
                    owner_auth_profile_id=owner,
                    attacker_auth_profile_id=attacker,
                    target_operation_id=op.operation_id,
                    target_path_template=op.path_template,
                    target_method=str(op.method or "GET").upper(),
                    path_param_name=path_param_name,
                    confidence=confidence,
                    created_by="bola_object_pair_builder",
                    reason_codes=["owner_object_ref_available", "attacker_profile_available", *op_reasons],
                )
                built_pairs.append(self._pairs.sanitize_bola_object_pair(created))
                break

        if not built_pairs:
            reason_codes = ["no_matching_path_param_operation"]
        else:
            reason_codes = ["object_pairs_built"]
        return self._result(
            command=command,
            tool_run_id=tool_run_id,
            started_ms=started,
            validation_mode=validation_mode,
            object_pairs=built_pairs,
            reason_codes=reason_codes,
        )

    def _rank_operations(
        self,
        operations: list[Operation],
        resource_type: str,
    ) -> list[tuple[int, Operation, str, str, list[str]]]:
        ranked: list[tuple[int, Operation, str, str, list[str]]] = []
        aliases = _RESOURCE_ALIASES.get(resource_type, set())
        for op in operations:
            params = _extract_path_params(op)
            if not params:
                continue
            method = str(op.method or "GET").upper()
            score = 0
            reasons: list[str] = []
            if method == "GET":
                score += 40
                reasons.append("method_get_preferred")
            elif method in {"PUT", "PATCH"}:
                score += 28
                reasons.append("method_write_supported")
            elif method == "DELETE":
                score += 12
                reasons.append("method_delete_diagnostic")
            else:
                continue
            if bool(op.auth_required):
                score += 20
                reasons.append("auth_required")
            op_resource = _normalize_resource_type(op.resource_type)
            if resource_type != "unknown" and op_resource == resource_type:
                score += 24
                reasons.append("operation_resource_type_match")
            tokens = _path_tokens(op.path_template)
            tags = {str(t).strip().lower() for t in op.tags}
            if aliases and (tokens & aliases or tags & aliases):
                score += 16
                reasons.append("path_or_tag_alias_match")
            for p in params:
                pscore = score
                preasons = list(reasons)
                if _resource_specific_param_match(resource_type, p):
                    pscore += 26
                    preasons.append("path_param_resource_match")
                elif _id_like_name(p):
                    pscore += 12
                    preasons.append("path_param_generic_id_match")
                else:
                    continue
                confidence = "high" if (
                    "operation_resource_type_match" in preasons and "path_param_resource_match" in preasons and "auth_required" in preasons
                ) else "medium"
                if confidence == "high" or pscore >= 60:
                    ranked.append((pscore, op, p, confidence, preasons))
        ranked.sort(key=lambda x: (-x[0], 0 if str(x[1].method or "").upper() == "GET" else 1, x[1].operation_id))
        return ranked

    def _result(
        self,
        *,
        command: WorkerCommand,
        tool_run_id: str,
        started_ms: int,
        validation_mode: str,
        object_pairs: list[dict[str, Any]],
        reason_codes: list[str],
    ) -> ToolResult:
        resource_types = sorted({str(x.get("resource_type") or "unknown") for x in object_pairs if isinstance(x, dict)})
        details = {
            "validation_mode": validation_mode,
            "object_pairs_count": len(object_pairs),
            "resource_types": resource_types,
            "object_pairs": object_pairs[:10],
            "reason_codes": [str(x) for x in reason_codes if str(x).strip()],
        }
        duration_ms = int(time.monotonic() * 1000) - started_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=0,
                success_count=0,
                client_error_count=0,
                server_error_count=0,
                duration_ms=duration_ms,
            ),
            observations=[
                ToolResultObservationLite(
                    observation_type="bola_object_pair_inventory",
                    confidence=0.8 if object_pairs else 0.5,
                    details=details,
                )
            ],
            artifacts=[],
            errors=[],
        )
