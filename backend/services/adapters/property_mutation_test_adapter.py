"""Phase 18A-1 — diagnostic-only property_mutation_test adapter.

Safe bounded adapter: no mutation HTTP requests, no observations.
Produces only compact diagnostic artifact metadata.
"""
from __future__ import annotations

import re
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore


_CANON_SENSITIVE_FIELDS: tuple[str, ...] = (
    "role",
    "roles",
    "isadmin",
    "admin",
    "status",
    "ownerid",
    "userid",
    "price",
    "balance",
    "verified",
    "permissions",
    "internal",
    "isinternal",
    "isstaff",
    "credit",
    "limit",
)

_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


def _norm_name(value: str) -> str:
    return re.sub(r"[_\-.]+", "", (value or "").strip().lower())


def _field_is_sensitive(name: str) -> bool:
    n = _norm_name(name)
    if not n:
        return False
    if n in _CANON_SENSITIVE_FIELDS:
        return True
    return any(n in canon or canon in n for canon in _CANON_SENSITIVE_FIELDS)


class PropertyMutationTestAdapter:
    """Diagnostic-only property mutation adapter (no network writes)."""

    def __init__(self) -> None:
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        del campaign  # intentionally unused in diagnostic mode
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        op_id = str(command.operation_id or "").strip()

        raw_fields = inputs.get("sensitive_fields")
        fields_considered: list[str] = []
        fields_selected: list[str] = []
        fields_skipped: list[str] = []

        if isinstance(raw_fields, list):
            for raw in raw_fields:
                s = str(raw or "").strip()
                if not s:
                    continue
                if not _SAFE_NAME_RE.match(s):
                    fields_skipped.append(s[:64])
                    continue
                fields_considered.append(s)
                if _field_is_sensitive(s):
                    fields_selected.append(s)
                else:
                    fields_skipped.append(s)

        seed_request_id = str(
            inputs.get("seed_request_id") or command.seed_request_id or ""
        ).strip()
        seed_present = bool(seed_request_id)

        reason_codes: list[str] = []
        if not fields_selected:
            result = "no_sensitive_fields"
            reason_codes.append("no_writable_sensitive_fields")
        elif not seed_present:
            result = "needs_verification_context"
            reason_codes.append("missing_seed_request")
        else:
            result = "diagnostic_ready"
            reason_codes.append("ready_for_safe_probe_context")

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="mass_assignment_probe_summary",
            content={
                "artifact_type": "mass_assignment_probe_summary",
                "operation_id": op_id,
                "policy": "diagnostic_only",
                "diagnostic_only": True,
                "fields_considered": fields_considered[:20],
                "fields_selected": fields_selected[:20],
                "fields_skipped": fields_skipped[:20],
                "reason_codes": sorted(set(reason_codes)),
                "seed_request_id_present": seed_present,
                "result": result,
            },
        )

        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(request_count=0, success_count=0, duration_ms=0),
            observations=[],
            artifacts=[artifact],
        )
