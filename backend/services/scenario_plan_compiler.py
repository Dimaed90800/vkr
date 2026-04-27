"""Phase 15B — compile validated ScenarioPlan items into planner candidates (hints only).

Does not execute tools, create ToolRuns, evidence, judge inputs, or findings.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.planner import (
        PlannerCandidate,
        PlannerCandidateKind,
        PlannerCandidateStatus,
        PlannerRequest,
    )
    from backend.models.scenario_plan import SCENARIO_TYPES, ScenarioStatus, ValidatedScenarioItem
    from backend.models.worker_command import CommandBudget, WorkerCommand
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.command_validator import CommandValidator
    from backend.services.injection_scenario_parameter_candidates import (
        INJECTION_COMPILER_PAYLOAD_FAMILIES,
        safe_query_parameter_candidates_for_operation,
    )
    from backend.services.tool_registry import ToolRegistry
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.planner import (
        PlannerCandidate,
        PlannerCandidateKind,
        PlannerCandidateStatus,
        PlannerRequest,
    )
    from models.scenario_plan import SCENARIO_TYPES, ScenarioStatus, ValidatedScenarioItem
    from models.worker_command import CommandBudget, WorkerCommand
    from services.api_graph_service import ApiGraphService
    from services.command_validator import CommandValidator
    from services.injection_scenario_parameter_candidates import (
        INJECTION_COMPILER_PAYLOAD_FAMILIES,
        safe_query_parameter_candidates_for_operation,
    )
    from services.tool_registry import ToolRegistry
    from storage.memory_store import memory_store

_JWT_LIKE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)


def _contains_raw_url(text: str) -> bool:
    lower = (text or "").lower()
    return "http://" in lower or "https://" in lower


def _contains_raw_url_any(obj: Any) -> bool:
    if isinstance(obj, str):
        return _contains_raw_url(obj)
    if isinstance(obj, list):
        return any(_contains_raw_url_any(x) for x in obj)
    if isinstance(obj, dict):
        return any(_contains_raw_url_any(k) or _contains_raw_url_any(v) for k, v in obj.items())
    return False


def _contains_secret(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    if "authorization" in lower:
        return True
    if "bearer " in lower or lower.startswith("bearer "):
        return True
    if "cookie:" in lower or "set-cookie" in lower:
        return True
    if "token=" in lower or "api_key=" in lower:
        return True
    if "access_token" in lower or "refresh_token" in lower:
        return True
    if _JWT_LIKE.search(text):
        return True
    return False


def _contains_secret_any(obj: Any) -> bool:
    if isinstance(obj, str):
        return _contains_secret(obj)
    if isinstance(obj, list):
        return any(_contains_secret_any(x) for x in obj)
    if isinstance(obj, dict):
        return any(_contains_secret_any(k) or _contains_secret_any(v) for k, v in obj.items())
    return False


def _has_passive_signal(campaign_id: str) -> bool:
    for obs in memory_store.list_observations_by_campaign(campaign_id):
        t = str(obs.get("type") or "")
        if t in ("zap_alert", "nuclei_match", "discovered_endpoint"):
            return True
    return False


def _candidate_id(kind: str, dedup_key: str) -> str:
    digest = hashlib.sha256(f"{kind}|{dedup_key}".encode()).hexdigest()[:16]
    return f"pcand_{digest}"


def _openapi_ref(campaign: Campaign) -> str:
    return str(campaign.openapi_url or "").strip()


def _role_count(campaign: Campaign) -> int:
    names: set[str] = set()
    for entry in campaign.roles_json or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or entry.get("role") or "").strip()
        if name:
            names.add(name.lower())
    return len(names)


def _injection_task_id(operation_id: str) -> str:
    base = re.sub(r"[^a-zA-Z0-9_]+", "_", operation_id).strip("_")[:80]
    return f"task_injection_probe_{base or 'op'}"


@dataclass
class ScenarioCompilerResult:
    extra_candidates: list[PlannerCandidate]
    priority_add_by_dedup_key: dict[str, float]
    warnings: list[str]


class ScenarioPlanCompiler:
    """Maps accepted ScenarioPlan rows to planner candidates and priority hints."""

    def __init__(
        self,
        *,
        registry: ToolRegistry | None = None,
        validator: CommandValidator | None = None,
    ) -> None:
        self._registry = registry or ToolRegistry()
        self._validator = validator or CommandValidator()

    def compile(
        self,
        *,
        campaign: Campaign,
        request: PlannerRequest,
        valid_operation_ids: frozenset[str],
        graph_operations_total: int,
        base_candidates: list[PlannerCandidate],
    ) -> ScenarioCompilerResult:
        extra: list[PlannerCandidate] = []
        warnings: list[str] = []
        priority_add: dict[str, float] = {}

        sp = request.scenario_plan
        if sp is None or not request.include_scenario_compiler:
            return ScenarioCompilerResult(extra, priority_add, warnings)

        scenarios = list(sp.scenarios or [])
        if not scenarios:
            return ScenarioCompilerResult(extra, priority_add, warnings)

        openapi_ref = _openapi_ref(campaign)
        passive = _has_passive_signal(campaign.campaign_id)
        roles_n = _role_count(campaign)

        schema_ops_ordered: list[str] = []
        schema_ops_seen: set[str] = set()
        schema_scenarios_by_op: dict[str, list[str]] = {}

        injection_ops_ordered: list[str] = []
        injection_ops_seen: set[str] = set()
        injection_scenarios_by_op: dict[str, list[str]] = {}

        for item in scenarios:
            if item.status == ScenarioStatus.rejected:
                continue

            blob = item.model_dump(mode="json")
            if _contains_raw_url_any(blob):
                extra.append(self._safety_audit(
                    campaign.campaign_id, item, "raw_url_not_allowed",
                ))
                continue
            if _contains_secret_any(blob):
                extra.append(self._safety_audit(
                    campaign.campaign_id, item, "secret_pattern_in_scenario_fields",
                ))
                continue

            stype = str(item.scenario_type or "").strip()
            if stype and stype not in SCENARIO_TYPES:
                extra.append(self._audit_candidate(
                    campaign_id=campaign.campaign_id,
                    scenario_id=item.scenario_id,
                    reason="Unknown scenario_type for ScenarioPlan compiler.",
                    missing=["unknown_scenario_type"],
                    summary={
                        "scenario_type": stype,
                        "audit_code": "unknown_scenario_type",
                    },
                ))
                continue

            for w in item.candidate_workers or []:
                wn = str(w).strip()
                if wn and not self._registry.is_known(wn):
                    warnings.append(f"unknown_candidate_worker_hint:{wn}")

            if item.status != ScenarioStatus.accepted:
                continue

            if stype == "schema_negative_testing":
                if graph_operations_total <= 0:
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="Graph empty; schema negative testing cannot run.",
                        missing=["graph_empty"],
                        summary={"scenario_type": stype, "audit_code": "graph_empty"},
                    ))
                    continue
                if not openapi_ref:
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="Campaign has no openapi_url; cannot build schemathesis command.",
                        missing=["openapi_source"],
                        summary={"scenario_type": stype, "audit_code": "openapi_source"},
                    ))
                    continue
                for oid in item.operation_ids or []:
                    op = str(oid).strip()
                    if not op:
                        continue
                    if op not in valid_operation_ids:
                        extra.append(self._audit_candidate(
                            campaign_id=campaign.campaign_id,
                            scenario_id=item.scenario_id,
                            reason=f"operation_id not in graph: {op}",
                            missing=[f"unknown_operation_id:{op}"],
                            summary={"scenario_type": stype, "operation_id": op},
                        ))
                        continue
                    if op in schema_ops_seen:
                        schema_scenarios_by_op.setdefault(op, []).append(item.scenario_id)
                        continue
                    schema_ops_seen.add(op)
                    schema_ops_ordered.append(op)
                    schema_scenarios_by_op[op] = [item.scenario_id]

            elif stype == "access_control_bola":
                pairs = list(request.bola.object_pairs or [])
                if not pairs or roles_n < 2:
                    missing: list[str] = []
                    if not pairs:
                        missing.append("object_pairs")
                    if roles_n < 2:
                        missing.append("two_authenticated_roles")
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="BOLA scenario requires object_pairs and two roles; no command from ScenarioPlan.",
                        missing=missing,
                        summary={
                            "scenario_type": stype,
                            "scenario_confidence": item.confidence,
                            "audit_code": "bola_scenario_blocked",
                        },
                    ))
                else:
                    scenario_ops = {str(x).strip() for x in (item.operation_ids or []) if str(x).strip()}
                    for bc in base_candidates:
                        if bc.kind != PlannerCandidateKind.bola_replay_probe:
                            continue
                        op_hint = str((bc.summary or {}).get("operation_id") or "").strip()
                        if op_hint and op_hint in scenario_ops:
                            bonus = 3.0 + float(item.confidence or 0.0) * 5.0
                            priority_add[bc.dedup_key] = priority_add.get(bc.dedup_key, 0.0) + bonus

            elif stype in ("security_header_validation", "passive_signal_validation"):
                if not passive:
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="No passive signal context (zap_alert/nuclei_match/discovered_endpoint).",
                        missing=["passive_signal_context"],
                        summary={
                            "scenario_type": stype,
                            "scenario_confidence": item.confidence,
                            "audit_code": "passive_signal_context",
                        },
                    ))
                else:
                    bonus = 5.0 + float(item.confidence or 0.0) * 10.0
                    for bc in base_candidates:
                        if (
                            bc.kind == PlannerCandidateKind.security_header_validator
                            and bc.status == PlannerCandidateStatus.ready
                        ):
                            priority_add[bc.dedup_key] = priority_add.get(bc.dedup_key, 0.0) + bonus

            elif stype == "injection_testing":
                if graph_operations_total <= 0:
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="Graph empty; injection_testing cannot run.",
                        missing=["graph_empty"],
                        summary={"scenario_type": stype, "audit_code": "graph_empty"},
                    ))
                    continue
                if not str(campaign.target_url or "").strip():
                    extra.append(self._audit_candidate(
                        campaign_id=campaign.campaign_id,
                        scenario_id=item.scenario_id,
                        reason="Campaign has no target_url; cannot build injection_test command.",
                        missing=["campaign_target_url_missing"],
                        summary={"scenario_type": stype, "audit_code": "campaign_target_url_missing"},
                    ))
                    continue
                for oid in item.operation_ids or []:
                    op = str(oid).strip()
                    if not op:
                        continue
                    if op not in valid_operation_ids:
                        extra.append(self._audit_candidate(
                            campaign_id=campaign.campaign_id,
                            scenario_id=item.scenario_id,
                            reason=f"operation_id not in graph: {op}",
                            missing=[f"unknown_operation_id:{op}"],
                            summary={"scenario_type": stype, "operation_id": op},
                        ))
                        continue
                    if op in injection_ops_seen:
                        injection_scenarios_by_op.setdefault(op, []).append(item.scenario_id)
                        continue
                    injection_ops_seen.add(op)
                    injection_ops_ordered.append(op)
                    injection_scenarios_by_op[op] = [item.scenario_id]

            else:
                extra.append(self._audit_candidate(
                    campaign_id=campaign.campaign_id,
                    scenario_id=item.scenario_id,
                    reason="Scenario type is not executable in Phase 15B compiler.",
                    missing=["unsupported_scenario_type_for_execution"],
                    summary={
                        "scenario_type": stype,
                        "scenario_confidence": item.confidence,
                        "audit_code": "unsupported_scenario_type_for_execution",
                    },
                ))

        for op, scn_ids in schema_scenarios_by_op.items():
            if len(scn_ids) > 1:
                warnings.append(
                    f"scenario_duplicate_schema_op_merged:{op}:"
                    f"{','.join(scn_ids)}",
                )

        for op, scn_ids in injection_scenarios_by_op.items():
            if len(scn_ids) > 1:
                warnings.append(
                    f"scenario_duplicate_injection_op_merged:{op}:"
                    f"{','.join(scn_ids)}",
                )

        graph_api = ApiGraphService()
        operations_by_id = {
            o.operation_id: o for o in graph_api.list_operations(campaign.campaign_id)
        }

        for op in schema_ops_ordered:
            dedup_key = f"{campaign.campaign_id}|schemathesis_negative_test|{op}"
            existing = self._existing_schemathesis_run(campaign.campaign_id, op)
            if existing is not None:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("schemathesis_negative_test", dedup_key),
                        kind=PlannerCandidateKind.schemathesis_negative_test,
                        status=PlannerCandidateStatus.skipped_existing,
                        priority=35.0,
                        reason="Existing schemathesis_negative_test ToolRun for this operation_id.",
                        dedup_key=dedup_key,
                        command=None,
                        summary={
                            "operation_id": op,
                            "existing_tool_run_id": str(existing.get("tool_run_id") or ""),
                            "source_scenario_ids": schema_scenarios_by_op.get(op, []),
                        },
                    ),
                )
                continue

            command = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=f"task_schemathesis_negative_{op.replace('/', '_')[:80]}",
                worker_class="contract_fuzzing",
                strategy="schema_negative_testing",
                tool_name="schemathesis_negative_test",
                operation_id=op,
                seed_request_id="",
                inputs={
                    "openapi_url": openapi_ref,
                    "target_url": campaign.target_url,
                    "operation_id": op,
                    "max_examples": 5,
                },
                budget=CommandBudget(max_requests=3, timeout_sec=120),
                success_criteria=["schema_negative_testing_completed"],
            )
            validation = self._validator.validate(command)
            summary_base: dict[str, Any] = {
                "operation_id": op,
                "source_scenario_ids": schema_scenarios_by_op.get(op, []),
                "openapi_source": "campaign.openapi_url",
            }
            if validation.valid:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("schemathesis_negative_test", dedup_key),
                        kind=PlannerCandidateKind.schemathesis_negative_test,
                        status=PlannerCandidateStatus.ready,
                        priority=35.0,
                        reason="ScenarioPlan schema_negative_testing mapped to schemathesis_negative_test.",
                        dedup_key=dedup_key,
                        command=command,
                        summary={
                            **summary_base,
                            "validation_warnings": list(validation.warnings),
                            "scenario_compiler": "phase_15b",
                        },
                    ),
                )
            else:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("schemathesis_negative_test", dedup_key),
                        kind=PlannerCandidateKind.schemathesis_negative_test,
                        status=PlannerCandidateStatus.blocked,
                        priority=35.0,
                        reason="Schemathesis candidate failed CommandValidator.",
                        missing_inputs=[e.code for e in validation.errors],
                        dedup_key=dedup_key,
                        command=None,
                        summary={
                            **summary_base,
                            "validation_errors": [e.model_dump(mode="json") for e in validation.errors],
                            "validation_warnings": list(validation.warnings),
                        },
                    ),
                )

        payload_families = list(INJECTION_COMPILER_PAYLOAD_FAMILIES)
        for op in injection_ops_ordered:
            dedup_key = f"{campaign.campaign_id}|injection_test|{op}"
            existing_inj = self._existing_injection_run(campaign.campaign_id, op)
            if existing_inj is not None:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("injection_test", dedup_key),
                        kind=PlannerCandidateKind.injection_test,
                        status=PlannerCandidateStatus.skipped_existing,
                        priority=34.0,
                        reason="Existing injection_test ToolRun for this operation_id.",
                        dedup_key=dedup_key,
                        command=None,
                        summary={
                            "operation_id": op,
                            "existing_tool_run_id": str(existing_inj.get("tool_run_id") or ""),
                            "source_scenario_ids": injection_scenarios_by_op.get(op, []),
                        },
                    ),
                )
                continue

            operation = operations_by_id.get(op)
            if operation is None:
                extra.append(self._audit_candidate(
                    campaign_id=campaign.campaign_id,
                    scenario_id=(injection_scenarios_by_op.get(op) or ["scn_injection"])[0],
                    reason=f"operation_id not found in graph store: {op}",
                    missing=[f"missing_operation:{op}"],
                    summary={"scenario_type": "injection_testing", "operation_id": op},
                ))
                continue

            param_candidates = safe_query_parameter_candidates_for_operation(
                operation, max_candidates=2,
            )
            if not param_candidates:
                extra.append(self._audit_candidate(
                    campaign_id=campaign.campaign_id,
                    scenario_id=(injection_scenarios_by_op.get(op) or ["scn_injection"])[0],
                    reason="No safe query parameter candidates for injection_testing.",
                    missing=["no_safe_query_parameter_candidates"],
                    summary={
                        "scenario_type": "injection_testing",
                        "operation_id": op,
                        "audit_code": "no_safe_query_parameter_candidates",
                    },
                ))
                continue

            n_c = len(param_candidates)
            n_f = len(payload_families)
            max_req = min(10, 1 + n_c * n_f)
            command = WorkerCommand(
                campaign_id=campaign.campaign_id,
                task_id=_injection_task_id(op),
                worker_class="contract_fuzzing",
                strategy="injection_probe",
                tool_name="injection_test",
                operation_id=op,
                seed_request_id="",
                inputs={
                    "target_url": campaign.target_url,
                    "operation_id": op,
                    "payload_families": list(payload_families),
                    "max_payloads_per_param": 1,
                    "parameter_candidates": param_candidates,
                },
                budget=CommandBudget(max_requests=max_req, timeout_sec=30),
                success_criteria=["injection_probe_completed"],
            )
            validation = self._validator.validate(command)
            summary_base: dict[str, Any] = {
                "operation_id": op,
                "source_scenario_ids": injection_scenarios_by_op.get(op, []),
                "parameter_candidates": param_candidates,
            }
            if validation.valid:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("injection_test", dedup_key),
                        kind=PlannerCandidateKind.injection_test,
                        status=PlannerCandidateStatus.ready,
                        priority=34.0,
                        reason="ScenarioPlan injection_testing mapped to injection_test.",
                        dedup_key=dedup_key,
                        command=command,
                        summary={
                            **summary_base,
                            "validation_warnings": list(validation.warnings),
                            "scenario_compiler": "phase_17b_3b",
                        },
                    ),
                )
            else:
                extra.append(
                    PlannerCandidate(
                        candidate_id=_candidate_id("injection_test", dedup_key),
                        kind=PlannerCandidateKind.injection_test,
                        status=PlannerCandidateStatus.blocked,
                        priority=34.0,
                        reason="Injection_test candidate failed CommandValidator.",
                        missing_inputs=[e.code for e in validation.errors],
                        dedup_key=dedup_key,
                        command=None,
                        summary={
                            **summary_base,
                            "validation_errors": [e.model_dump(mode="json") for e in validation.errors],
                            "validation_warnings": list(validation.warnings),
                        },
                    ),
                )

        return ScenarioCompilerResult(extra, priority_add, warnings)

    def _existing_injection_run(self, campaign_id: str, operation_id: str) -> dict[str, Any] | None:
        active_or_done = {
            "accepted",
            "queued",
            "running",
            "finished",
            "partial",
            "failed",
            "timeout",
            "cancelled",
            "skipped",
        }
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "injection_test":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            cmd_id = str(run.get("command_id") or "").strip()
            if cmd_id:
                cmd = memory_store.get_command(cmd_id) or {}
                inputs = cmd.get("inputs") if isinstance(cmd, dict) else None
                if isinstance(inputs, dict) and str(inputs.get("operation_id") or "").strip() == operation_id:
                    return run
            run_id = str(run.get("tool_run_id") or "").strip()
            if not run_id:
                continue
            result = memory_store.get_tool_result(run_id) or {}
            observations = result.get("observations") if isinstance(result, dict) else None
            if not isinstance(observations, list):
                continue
            for obs in observations:
                if not isinstance(obs, dict):
                    continue
                details = obs.get("details") if isinstance(obs.get("details"), dict) else {}
                if str(details.get("operation_id") or "").strip() == operation_id:
                    return run
        return None

    def _existing_schemathesis_run(self, campaign_id: str, operation_id: str) -> dict[str, Any] | None:
        active_or_done = {
            "accepted",
            "queued",
            "running",
            "finished",
            "partial",
            "failed",
            "timeout",
            "cancelled",
            "skipped",
        }
        for run in memory_store.list_tool_runs_by_campaign(campaign_id):
            if run.get("tool_name") != "schemathesis_negative_test":
                continue
            if str(run.get("status") or "").lower() not in active_or_done:
                continue
            cmd_id = str(run.get("command_id") or "").strip()
            if cmd_id:
                cmd = memory_store.get_command(cmd_id) or {}
                inputs = cmd.get("inputs") if isinstance(cmd, dict) else None
                if isinstance(inputs, dict) and str(inputs.get("operation_id") or "").strip() == operation_id:
                    return run
            # Dify loop starts ToolRuns directly from planner command_json and may not
            # persist WorkerCommand in memory_store.commands; fall back to ToolResult.
            run_id = str(run.get("tool_run_id") or "").strip()
            if not run_id:
                continue
            result = memory_store.get_tool_result(run_id) or {}
            observations = result.get("observations") if isinstance(result, dict) else None
            if not isinstance(observations, list):
                continue
            for obs in observations:
                if not isinstance(obs, dict):
                    continue
                details = obs.get("details") if isinstance(obs.get("details"), dict) else {}
                if str(details.get("operation_id") or "").strip() == operation_id:
                    return run
        return None

    def _safety_audit(
        self,
        campaign_id: str,
        item: ValidatedScenarioItem,
        code: str,
    ) -> PlannerCandidate:
        return self._audit_candidate(
            campaign_id=campaign_id,
            scenario_id=item.scenario_id,
            reason=f"ScenarioPlan safety re-check failed: {code}",
            missing=[code],
            summary={
                "scenario_type": item.scenario_type,
                "scenario_confidence": item.confidence,
                "audit_code": code,
            },
        )

    def _audit_candidate(
        self,
        *,
        campaign_id: str,
        scenario_id: str,
        reason: str,
        missing: list[str],
        summary: dict[str, Any],
    ) -> PlannerCandidate:
        dedup_key = f"{campaign_id}|scenario_plan_blocked|{scenario_id}|{','.join(missing)}"
        return PlannerCandidate(
            candidate_id=_candidate_id("scenario_plan_blocked", dedup_key),
            kind=PlannerCandidateKind.scenario_plan_blocked,
            status=PlannerCandidateStatus.blocked,
            priority=5.0,
            reason=reason,
            missing_inputs=missing,
            dedup_key=dedup_key,
            command=None,
            summary=summary,
        )
