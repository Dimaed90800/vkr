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

_SEMANTIC_TO_RESOURCE: dict[str, str] = {
    "post_id": "post",
    "video_id": "video",
    "vehicle_id": "vehicle",
    "order_id": "order",
    "user_id": "user",
    "owner_id": "user",
    "author_id": "user",
}

_COMPAT_PARAMS_BY_SEMANTIC: dict[str, set[str]] = {
    "post_id": {"postid", "post_id", "articleid"},
    "vehicle_id": {"vehicleid", "vehicle_id"},
    "order_id": {"orderid", "order_id"},
    "video_id": {"videoid", "video_id"},
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


def _semantic_id_kind_from_field(field_name: str) -> str:
    lowered = str(field_name or "").strip().lower()
    if lowered in {"authorid", "author_id"}:
        return "author_id"
    if lowered in {"ownerid", "owner_id"}:
        return "owner_id"
    if lowered in {"userid", "user_id"}:
        return "user_id"
    if lowered in {"postid", "post_id"}:
        return "post_id"
    if lowered in {"videoid", "video_id"}:
        return "video_id"
    if lowered in {"vehicleid", "vehicle_id"}:
        return "vehicle_id"
    if lowered == "vin":
        return "vin"
    if lowered.endswith("id") or lowered.endswith("_id"):
        return "resource_id"
    return "unknown_id"


def _semantic_id_kind_from_param(param_name: str) -> str:
    p = str(param_name or "").strip().lower().replace("_", "")
    if p in {"postid", "articleid"}:
        return "post_id"
    if p == "videoid":
        return "video_id"
    if p == "vehicleid":
        return "vehicle_id"
    if p == "orderid":
        return "order_id"
    if p in {"userid", "ownerid", "authorid"}:
        return "user_id"
    if p == "vin":
        return "vin"
    if p.endswith("id"):
        return "resource_id"
    return "unknown_id"


def _ops_look_related(source_operation_id: str, source_path: str, target_operation_id: str, target_path: str, resource_type: str) -> bool:
    src = " ".join([str(source_operation_id or "").lower(), str(source_path or "").lower()])
    tgt = " ".join([str(target_operation_id or "").lower(), str(target_path or "").lower()])
    aliases = _RESOURCE_ALIASES.get(resource_type, set())
    if not src or not tgt:
        return False
    if any(alias and alias in src and alias in tgt for alias in aliases):
        return True
    src_tokens = {t for t in re.split(r"[^a-z0-9]+", src) if t}
    tgt_tokens = {t for t in re.split(r"[^a-z0-9]+", tgt) if t}
    overlap = src_tokens & tgt_tokens
    return len(overlap) >= 2


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
        blocked_pairs: list[dict[str, Any]] = []
        max_pairs = min(10, max(1, int(inputs.get("max_object_pairs") or 10)))
        def _instance_rank_key(item: dict[str, Any]) -> tuple[int, int, int]:
            md = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
            owner_ev = bool(item.get("owner_evidence") or md.get("owner_evidence") or str(item.get("source_role_hint") or md.get("source_role_hint") or "").strip().lower() == "owner")
            status_code = int(item.get("source_status_code") or md.get("source_status_code") or 0)
            conf = str(item.get("confidence") or "").strip().lower()
            conf_weight = 2 if conf == "high" else (1 if conf == "medium" else 0)
            return (1 if owner_ev else 0, 1 if 200 <= status_code <= 299 else 0, conf_weight)

        for row in sorted(instances, key=_instance_rank_key, reverse=True):
            if len(built_pairs) >= max_pairs:
                break
            resource_type = _normalize_resource_type(str(row.get("resource_type") or "unknown"))
            source_operation_id = str(row.get("source_operation_id") or "")
            source_path = str(row.get("source_path") or "")
            metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
            semantic_id_kind = str(metadata.get("semantic_id_kind") or _semantic_id_kind_from_field(str(row.get("object_id_field") or "")))
            source_reason_codes = [
                str(x)
                for x in (
                    metadata.get("source_reason_codes")
                    or row.get("source_reason_codes")
                    or []
                )
                if str(x).strip()
            ]
            owner_evidence = bool(
                row.get("owner_evidence")
                or metadata.get("owner_evidence")
                or (str(row.get("source_role_hint") or metadata.get("source_role_hint") or "").strip().lower() == "owner")
            )
            source_status_code = int(row.get("source_status_code") or metadata.get("source_status_code") or 0)
            object_ref_id = str(row.get("object_ref_id") or "")
            object_id_ref = str(row.get("object_id_ref") or "")
            if not object_ref_id or not object_id_ref:
                continue
            ranked = self._rank_operations(operations, resource_type)
            if not ranked:
                continue
            for score, op, path_param_name, confidence, op_reasons in ranked:
                if len(built_pairs) >= max_pairs:
                    break
                compat_penalty, compat_reasons, block_reasons = self._compatibility_penalty(
                    row=row,
                    operation=op,
                    path_param_name=path_param_name,
                    resource_type=resource_type,
                    semantic_id_kind=semantic_id_kind,
                    source_operation_id=source_operation_id,
                    source_path=source_path,
                    source_reason_codes=source_reason_codes,
                    owner_evidence=owner_evidence,
                    source_status_code=source_status_code,
                )
                score = float(score) + float(compat_penalty)
                edge_conf = "high" if score >= 85 else ("medium" if score >= 60 else "low")
                if score < 50 or block_reasons:
                    blocked_pairs.append({
                        "status": "blocked",
                        "resource_type": resource_type,
                        "object_ref_id": object_ref_id,
                        "target_operation_id": str(op.operation_id or ""),
                        "target_path_template": str(op.path_template or ""),
                        "target_method": str(op.method or "GET").upper(),
                        "path_param_name": path_param_name,
                        "confidence": confidence,
                        "metadata": {
                            "baseline_probability_score": float(score),
                            "baseline_probability_reasons": [*op_reasons, *compat_reasons][:20],
                            "baseline_block_reasons": block_reasons[:20],
                            "semantic_id_kind": semantic_id_kind,
                            "source_reason_codes": source_reason_codes[:20],
                            "source_operation_id": source_operation_id,
                            "source_path": source_path,
                            "source_status_code": int(row.get("source_status_code") or metadata.get("source_status_code") or 0),
                            "owner_evidence": owner_evidence,
                            "object_id_field": str(row.get("object_id_field") or ""),
                            "id_json_path": str(row.get("id_json_path") or metadata.get("id_json_path") or ""),
                            "dependency_producer_operation_id": str(row.get("source_operation_id") or ""),
                            "object_ref_confidence": str(row.get("confidence") or "low"),
                            "dependency_edge_confidence": edge_conf,
                        },
                    })
                    continue
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
                    metadata={
                        "dependency_edge": {
                            "producer_operation_id": str(row.get("source_operation_id") or ""),
                            "consumer_operation_id": str(op.operation_id or ""),
                            "param_name": path_param_name,
                            "param_location": "path",
                            "resource_type": resource_type,
                            "confidence": edge_conf,
                            "reason_codes": [*op_reasons],
                        },
                        "baseline_probability_score": float(score),
                        "baseline_probability_reasons": [*op_reasons, *compat_reasons][:20],
                        "baseline_block_reasons": block_reasons[:20],
                        "semantic_id_kind": semantic_id_kind,
                        "source_operation_id": source_operation_id,
                        "source_path": source_path,
                        "object_id_field": str(row.get("object_id_field") or ""),
                        "path_param_name": path_param_name,
                        "dependency_producer_operation_id": str(row.get("source_operation_id") or ""),
                        "source_reason_codes": source_reason_codes[:20],
                        "source_status_code": int(row.get("source_status_code") or metadata.get("source_status_code") or 0),
                        "id_json_path": str(row.get("id_json_path") or metadata.get("id_json_path") or ""),
                        "owner_evidence": owner_evidence,
                        "object_ref_confidence": str(row.get("confidence") or "low"),
                        "dependency_edge_confidence": edge_conf,
                    },
                )
                built_pairs.append(self._pairs.sanitize_bola_object_pair(created))
                break

        if not built_pairs and blocked_pairs:
            reason_codes = ["all_candidate_pairs_blocked"]
        elif not built_pairs:
            reason_codes = ["no_matching_path_param_operation"]
        else:
            reason_codes = ["object_pairs_built"]
        return self._result(
            command=command,
            tool_run_id=tool_run_id,
            started_ms=started,
            validation_mode=validation_mode,
            object_pairs=[*built_pairs, *blocked_pairs],
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
                if confidence == "high" or pscore >= 55:
                    ranked.append((pscore, op, p, confidence, preasons))
        ranked.sort(key=lambda x: (-x[0], 0 if str(x[1].method or "").upper() == "GET" else 1, x[1].operation_id))
        return ranked

    def _compatibility_penalty(
        self,
        *,
        row: dict[str, Any],
        operation: Operation,
        path_param_name: str,
        resource_type: str,
        semantic_id_kind: str,
        source_operation_id: str,
        source_path: str,
        source_reason_codes: list[str],
        owner_evidence: bool,
        source_status_code: int,
    ) -> tuple[float, list[str], list[str]]:
        score_delta = 0.0
        reasons: list[str] = []
        block_reasons: list[str] = []
        param_kind = _semantic_id_kind_from_param(path_param_name)
        producer_expected = _SEMANTIC_TO_RESOURCE.get(param_kind, "")
        semantic_resource = _SEMANTIC_TO_RESOURCE.get(semantic_id_kind, "")
        param_norm = str(path_param_name or "").strip().lower().replace("_", "")
        compat_params = _COMPAT_PARAMS_BY_SEMANTIC.get(semantic_id_kind, set())
        is_user_identity_sem = semantic_id_kind in {"author_id", "owner_id", "user_id"}
        target_res = _normalize_resource_type(str(operation.resource_type or ""))
        semantic_res = _SEMANTIC_TO_RESOURCE.get(semantic_id_kind, "")

        if compat_params and param_norm in compat_params:
            score_delta += 40.0
            reasons.append("semantic_id_kind_matches_path_param")
        elif is_user_identity_sem and param_kind in {"post_id", "video_id", "vehicle_id", "order_id"}:
            score_delta -= 80.0
            reasons.append("path_param_semantic_mismatch")
            reasons.append("object_id_field_semantic_mismatch")
            block_reasons.append("object_id_field_semantic_mismatch")
            block_reasons.append("path_param_semantic_mismatch")
        elif param_kind not in {"unknown_id", "resource_id"} and semantic_id_kind not in {"unknown_id", "resource_id"} and param_kind != semantic_id_kind:
            score_delta -= 80.0
            reasons.append("path_param_semantic_mismatch")
            block_reasons.append("path_param_semantic_mismatch")

        if semantic_res and target_res and semantic_res == target_res:
            score_delta += 30.0
            reasons.append("resource_type_matches_target")

        if owner_evidence:
            score_delta += 25.0
            reasons.append("owner_evidence_true")
        else:
            score_delta -= 60.0
            reasons.append("weak_object_ref_provenance")

        if 200 <= int(source_status_code or 0) <= 299:
            score_delta += 20.0
            reasons.append("source_status_2xx")
        elif int(source_status_code or 0) > 0:
            score_delta -= 60.0
            reasons.append("source_status_non_2xx")
            block_reasons.append("weak_object_ref_provenance")

        if _ops_look_related(source_operation_id, source_path, str(operation.operation_id or ""), str(operation.path_template or ""), resource_type):
            score_delta += 20.0
            reasons.append("source_target_operation_related")

        if producer_expected and semantic_resource and producer_expected != semantic_resource:
            score_delta -= 60.0
            reasons.append("object_ref_source_operation_mismatch")
            reasons.append("dependency_edge_producer_mismatch")
            block_reasons.append("weak_object_ref_provenance")

        op_id = str(operation.operation_id or "")
        src_tokens = source_operation_id.lower()
        if src_tokens and op_id and not any(tok and tok in src_tokens for tok in op_id.lower().split("/")):
            score_delta -= 30.0
            reasons.append("object_ref_source_operation_mismatch")

        source_path_low = source_path.lower()
        if source_path_low and resource_type and resource_type not in source_path_low and semantic_resource and semantic_resource not in source_path_low:
            score_delta -= 18.0
            reasons.append("object_ref_provenance_weak")

        if "creation_non_2xx" in source_reason_codes:
            score_delta -= 60.0
            reasons.append("seed_creation_non_2xx_penalty")
            block_reasons.append("source_seed_creation_non_2xx")
        if "blocked_required_object_ref" in source_reason_codes:
            score_delta -= 80.0
            reasons.append("blocked_required_object_ref_penalty")
            block_reasons.append("source_seed_blocked_required_object_ref")

        return score_delta, reasons, block_reasons

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
