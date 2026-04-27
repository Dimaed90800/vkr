"""Phase 18A-1 — diagnostic-only property_mutation_test adapter.

Safe bounded adapter: no mutation HTTP requests.
Always emits compact mass_assignment_probe_summary artifact metadata.
Emits mass_assignment_signal only for diagnostic_ready context.
"""
from __future__ import annotations

from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResultObservationLite,
        ToolResult,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.mass_assignment_field_classifier import (
        MassAssignmentFieldSelection,
        select_mass_assignment_fields,
    )
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResultObservationLite,
        ToolResult,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.mass_assignment_field_classifier import (
        MassAssignmentFieldSelection,
        select_mass_assignment_fields,
    )


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
        selection = select_mass_assignment_fields(
            raw_fields if isinstance(raw_fields, list) else [],
        )
        if isinstance(selection, MassAssignmentFieldSelection):
            fields_considered = selection.considered
            fields_selected = selection.selected
            fields_skipped = selection.skipped
        else:  # pragma: no cover
            fields_considered = []
            fields_selected = []
            fields_skipped = []

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

        observations: list[ToolResultObservationLite] = []
        if result == "diagnostic_ready" and fields_selected and seed_present:
            observations.append(
                ToolResultObservationLite(
                    observation_type="mass_assignment_signal",
                    confidence=0.55,
                    details={
                        "tool_name": "property_mutation_test",
                        "operation_id": op_id,
                        "signal_types": [
                            "candidate_sensitive_writable_fields",
                            "seed_context_present",
                            "diagnostic_probe_ready",
                        ],
                        "mutation_policy": "diagnostic_only",
                        "diagnostic_only": True,
                        "runtime_effect_proven": False,
                        "fields_selected": fields_selected[:20],
                        "fields_considered_count": len(fields_considered),
                        "fields_skipped_count": len(fields_skipped),
                        "seed_request_id": seed_request_id,
                        "seed_request_id_present": True,
                        "proof_scope": "diagnostic_signal_only",
                        "recommended_next_action": "validate_mass_assignment_impact",
                        "security_relevance": "medium",
                    },
                )
            )

        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(request_count=0, success_count=0, duration_ms=0),
            observations=observations,
            artifacts=[artifact],
        )
