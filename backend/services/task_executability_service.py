from __future__ import annotations

from typing import Any

try:
    from backend.models.scheduling import ExecutabilityDecision, SchedulerState
    from backend.models.testing import ExecutionContext, TaskModel
    from backend.services.rejection_analyzer import RejectionAnalyzer
except ModuleNotFoundError:  # pragma: no cover
    from models.scheduling import ExecutabilityDecision, SchedulerState
    from models.testing import ExecutionContext, TaskModel
    from services.rejection_analyzer import RejectionAnalyzer


class TaskExecutabilityService:
    SUCCESS_PATH_MIN_FEASIBILITY = 0.45
    MATERIALIZATION_STRATEGIES = {
        "create_object_then_replay",
        "list_then_select_object_then_replay",
        "object_specific_auth_probe",
        "prepare_workflow_state_then_retry",
    }
    AUTH_BOOTSTRAP_STRATEGIES = {
        "provision_then_replay",
        "register_then_login_retry",
        "login_only_bootstrap_retry",
        "discover_auth_bootstrap_then_provision",
        "use_existing_provisioned_identity",
    }

    def __init__(self) -> None:
        self.rejection_analyzer = RejectionAnalyzer()

    def evaluate(
        self,
        task: TaskModel,
        *,
        execution_context: ExecutionContext | None = None,
        scheduler_state: SchedulerState | None = None,
    ) -> ExecutabilityDecision:
        context = execution_context or ExecutionContext(target_url="http://example.test")
        hints = task.context_hints or {}
        prerequisites = task.prerequisites
        capability_state = task.capability_state or {}
        creator_candidates = list(hints.get("spec_creator_candidates") or [])
        list_candidates = list(hints.get("spec_list_candidates") or [])
        resolved_object_id, available_object_ids = self._resolve_object_id(task, context)
        auth_available = self._auth_context_available(task, context)
        baseline_valid = self._baseline_valid(task)
        success_path_feasibility = float(hints.get("spec_success_path_feasibility") or 0.0)
        workflow_state_available = self._workflow_state_available(task, context, resolved_object_id)
        next_strategies = self._next_best_followups(task, creator_candidates, list_candidates)
        is_preparation_task = self._is_preparation_task(task)

        if str(task.status or "").lower() not in {"", "pending"}:
            return ExecutabilityDecision(
                executable=False,
                execution_mode="blocked",
                block_reason="task_not_pending",
                missing_prerequisites=["task_not_pending"],
                available_object_ids_count=len(available_object_ids),
                auth_context_available=auth_available,
                baseline_valid=baseline_valid,
                creator_candidate_count=len(creator_candidates),
                list_candidate_count=len(list_candidates),
                success_path_feasibility=success_path_feasibility,
                next_best_followup_strategies=next_strategies,
            )

        if str(task.readiness or "").lower() == "cannot_proceed":
            return ExecutabilityDecision(
                executable=False,
                execution_mode="blocked",
                block_reason="task_marked_cannot_proceed",
                missing_prerequisites=["task_marked_cannot_proceed"],
                available_object_ids_count=len(available_object_ids),
                auth_context_available=auth_available,
                baseline_valid=baseline_valid,
                creator_candidate_count=len(creator_candidates),
                list_candidate_count=len(list_candidates),
                success_path_feasibility=success_path_feasibility,
                next_best_followup_strategies=next_strategies,
            )

        missing: list[str] = []
        prep_reason = ""
        preferred_tool = None
        preferred_strategy = None

        if prerequisites.requires_auth_context and not auth_available:
            missing.append("missing_auth_context")
            if not self._is_materialization_strategy(task):
                preferred_tool, preferred_strategy = self._auth_preparation_path(task)
            prep_reason = prep_reason or "missing_auth_context"

        if prerequisites.requires_creator_candidate and not creator_candidates:
            missing.append("creator_not_available")
        if prerequisites.requires_list_candidate and not list_candidates:
            missing.append("list_not_available")

        if prerequisites.requires_object_id and not resolved_object_id:
            missing.append("object_id_missing")
            object_tool, object_strategy = self._object_materialization_path(task, creator_candidates, list_candidates)
            if object_tool:
                preferred_tool = preferred_tool or object_tool
                preferred_strategy = preferred_strategy or object_strategy
                prep_reason = prep_reason or "object_materialization_required"
            else:
                prep_reason = prep_reason or "missing_object_materialization_path"

        if prerequisites.requires_valid_baseline and baseline_valid is False:
            missing.append("baseline_invalid_from_spec")
            baseline_tool, baseline_strategy = self._baseline_preparation_path(task)
            if baseline_tool:
                preferred_tool = preferred_tool or baseline_tool
                preferred_strategy = preferred_strategy or baseline_strategy
                prep_reason = prep_reason or "missing_valid_baseline_path"
            else:
                prep_reason = prep_reason or "missing_valid_baseline_path"

        if prerequisites.requires_success_path:
            if not workflow_state_available and success_path_feasibility < self.SUCCESS_PATH_MIN_FEASIBILITY:
                missing.append("success_path_not_reachable")
                success_tool, success_strategy = self._success_path_preparation_path(task, creator_candidates, list_candidates)
                if success_tool:
                    preferred_tool = preferred_tool or success_tool
                    preferred_strategy = preferred_strategy or success_strategy
                    prep_reason = prep_reason or "missing_valid_baseline_path"
                else:
                    prep_reason = prep_reason or "missing_valid_baseline_path"

        if prerequisites.requires_workflow_state and not workflow_state_available:
            missing.append("missing_workflow_state")
            workflow_tool, workflow_strategy = self._workflow_preparation_path(task, creator_candidates, list_candidates)
            if workflow_tool:
                preferred_tool = preferred_tool or workflow_tool
                preferred_strategy = preferred_strategy or workflow_strategy
                prep_reason = prep_reason or "missing_workflow_state"
            else:
                prep_reason = prep_reason or "missing_workflow_state"

        if missing:
            can_prepare = bool(preferred_tool and preferred_tool in self._preparation_tool_candidates(task))
            if is_preparation_task and "object_id_missing" in missing:
                preferred_tool = preferred_tool or self._preparation_tool_fallback(task)
                preferred_strategy = preferred_strategy or self._default_preparation_strategy(task, preferred_tool)
                if preferred_tool:
                    can_prepare = True
            if can_prepare:
                return ExecutabilityDecision(
                    executable=True,
                    execution_mode="preparation",
                    block_reason="preparation_allowed" if is_preparation_task else prep_reason,
                    missing_prerequisites=missing,
                    preferred_tool=preferred_tool,
                    preferred_strategy=preferred_strategy,
                    resolved_object_id=resolved_object_id,
                    available_object_ids_count=len(available_object_ids),
                    auth_context_available=auth_available,
                    baseline_valid=baseline_valid,
                    creator_candidate_count=len(creator_candidates),
                    list_candidate_count=len(list_candidates),
                    success_path_feasibility=success_path_feasibility,
                    next_best_followup_strategies=next_strategies,
                )
            return ExecutabilityDecision(
                executable=False,
                execution_mode="blocked",
                block_reason=prep_reason or missing[0],
                missing_prerequisites=missing,
                preferred_tool=preferred_tool,
                preferred_strategy=preferred_strategy,
                resolved_object_id=resolved_object_id,
                available_object_ids_count=len(available_object_ids),
                auth_context_available=auth_available,
                baseline_valid=baseline_valid,
                creator_candidate_count=len(creator_candidates),
                list_candidate_count=len(list_candidates),
                success_path_feasibility=success_path_feasibility,
                next_best_followup_strategies=next_strategies,
            )

        if str(task.readiness or "").lower() == "needs_preparation":
            preferred_tool = preferred_tool or self._preferred_preparation_tool(task)
            preferred_strategy = preferred_strategy or self._default_preparation_strategy(task, preferred_tool)
            if preferred_tool:
                return ExecutabilityDecision(
                    executable=True,
                    execution_mode="preparation",
                    block_reason="preparation_required",
                    preferred_tool=preferred_tool,
                    preferred_strategy=preferred_strategy,
                    resolved_object_id=resolved_object_id,
                    available_object_ids_count=len(available_object_ids),
                    auth_context_available=auth_available,
                    baseline_valid=baseline_valid,
                    creator_candidate_count=len(creator_candidates),
                    list_candidate_count=len(list_candidates),
                    success_path_feasibility=success_path_feasibility,
                    next_best_followup_strategies=next_strategies,
                )
            return ExecutabilityDecision(
                executable=False,
                execution_mode="blocked",
                block_reason="no_executable_preparation_tasks",
                missing_prerequisites=["no_executable_preparation_tasks"],
                resolved_object_id=resolved_object_id,
                available_object_ids_count=len(available_object_ids),
                auth_context_available=auth_available,
                baseline_valid=baseline_valid,
                creator_candidate_count=len(creator_candidates),
                list_candidate_count=len(list_candidates),
                success_path_feasibility=success_path_feasibility,
                next_best_followup_strategies=next_strategies,
            )

        return ExecutabilityDecision(
            executable=True,
            execution_mode="test",
            block_reason="",
            resolved_object_id=resolved_object_id,
            available_object_ids_count=len(available_object_ids),
            auth_context_available=auth_available,
            baseline_valid=baseline_valid,
            creator_candidate_count=len(creator_candidates),
            list_candidate_count=len(list_candidates),
            success_path_feasibility=success_path_feasibility,
            next_best_followup_strategies=next_strategies,
        )

    def prepare_task_for_execution(self, task: TaskModel, decision: ExecutabilityDecision) -> TaskModel:
        updated = task.model_copy(deep=True)
        if decision.resolved_object_id and updated.params.selected_object_id in (None, "", "{id}"):
            updated.params.selected_object_id = decision.resolved_object_id
            updated.params.requires_object_id_enrichment = False
            if decision.resolved_object_id not in updated.params.object_id_candidates:
                updated.params.object_id_candidates.insert(0, decision.resolved_object_id)
        if decision.execution_mode == "preparation":
            updated.readiness = "needs_preparation"
            if decision.preferred_tool:
                updated.allowed_tools = [decision.preferred_tool]
                updated.recommended_next_step = decision.preferred_tool
            if decision.preferred_strategy:
                updated.test_strategy = decision.preferred_strategy
                updated.strategy_family = decision.preferred_strategy
        elif decision.execution_mode == "test":
            updated.readiness = "ready_to_test"
        return updated

    def _resolve_object_id(self, task: TaskModel, context: ExecutionContext) -> tuple[str | None, list[str]]:
        values: list[str] = []
        for item in [task.params.selected_object_id, *(task.params.object_id_candidates or [])]:
            normalized = self._real_object_id(item)
            if normalized and normalized not in values:
                values.append(normalized)
        family = str(task.resource_family or (task.context_hints or {}).get("resource_family") or "").strip().lower()
        prepared_objects = context.prepared_objects or {}
        if family and isinstance(prepared_objects, dict):
            prepared = prepared_objects.get(family)
            if isinstance(prepared, dict):
                normalized = self._real_object_id(prepared.get("object_id"))
                if normalized and normalized not in values:
                    values.insert(0, normalized)
        workflow_context = context.workflow_context or {}
        if family and isinstance(workflow_context, dict):
            workflow_family = str(workflow_context.get("resource_family") or "").strip().lower()
            if workflow_family == family:
                normalized = self._real_object_id(workflow_context.get("object_id"))
                if normalized and normalized not in values:
                    values.insert(0, normalized)
        for item in (context.harvested_object_ids or [])[:10]:
            normalized = self._real_object_id(item)
            if normalized and normalized not in values:
                values.append(normalized)
        return (values[0] if values else None), values

    def _auth_context_available(self, task: TaskModel, context: ExecutionContext) -> bool:
        roles = context.roles or []
        if any(self._has_auth_material(item) for item in roles if isinstance(item, dict)):
            return True
        capability_state = task.capability_state or {}
        return bool(capability_state.get("has_auth_profiles") or capability_state.get("has_multi_role_auth"))

    def _baseline_valid(self, task: TaskModel) -> bool | None:
        hints = task.context_hints or {}
        if "baseline_valid" in hints:
            return bool(hints.get("baseline_valid"))
        if "spec_baseline_available" in hints:
            return bool(hints.get("spec_baseline_available"))
        if task.class_name == "injection":
            return bool(task.params.query_params or task.params.body_fields or task.params.path_params)
        return None

    def _workflow_state_available(self, task: TaskModel, context: ExecutionContext, resolved_object_id: str | None) -> bool:
        hints = task.context_hints or {}
        capability_state = task.capability_state or {}
        if bool(hints.get("prepared_workflow_state")) or bool(capability_state.get("has_workflow_hints")):
            return True
        if resolved_object_id and str(task.resource_family or "").lower() in {"order", "post", "video", "vehicle", "report"}:
            return True
        workflow_context = context.workflow_context or {}
        family = str(task.resource_family or hints.get("resource_family") or "").strip().lower()
        if isinstance(workflow_context, dict) and family and str(workflow_context.get("resource_family") or "").strip().lower() == family:
            return True
        return False

    def _object_materialization_path(self, task: TaskModel, creator_candidates: list[dict[str, Any]], list_candidates: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        tools = self._preparation_tool_candidates(task)
        if "create_test_object" in tools:
            if creator_candidates:
                return "create_test_object", "create_object_then_replay"
            if list_candidates:
                return "create_test_object", "list_then_select_object_then_replay"
            return "create_test_object", "create_object_then_replay"
        return None, None

    def _auth_preparation_path(self, task: TaskModel) -> tuple[str | None, str | None]:
        tools = self._preparation_tool_candidates(task)
        if "auto_provision" in tools:
            if str(task.subtype or "").lower() == "auth_bootstrap":
                return "auto_provision", "login_only_bootstrap_retry"
            return "auto_provision", "register_then_login_retry"
        if "auth_probe_entrypoints" in tools:
            return "auth_probe_entrypoints", "discover_auth_bootstrap_then_provision"
        if "auth_test_access" in tools:
            return "auth_test_access", "use_existing_provisioned_identity"
        return None, None

    def _baseline_preparation_path(self, task: TaskModel) -> tuple[str | None, str | None]:
        tools = self._preparation_tool_candidates(task)
        if "input_shape_probe" in tools:
            return "input_shape_probe", "baseline_refinement"
        if "workflow_probe" in tools:
            return "workflow_probe", "prepare_workflow_state_then_retry"
        return None, None

    def _workflow_preparation_path(self, task: TaskModel, creator_candidates: list[dict[str, Any]], list_candidates: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        tools = self._preparation_tool_candidates(task)
        family = str(task.resource_family or (task.context_hints or {}).get("resource_family") or "").strip().lower()
        endpoint = str(task.endpoint or "").lower()
        if family == "order" and "workflow_probe" in tools:
            if "return_order" in endpoint and creator_candidates:
                return "workflow_probe", "create_order_then_return_order"
            if "return_order" in endpoint and list_candidates:
                return "workflow_probe", "list_orders_then_pick_order_then_return_order"
            if creator_candidates:
                return "workflow_probe", "create_order_then_update_order"
        if "workflow_probe" in tools:
            return "workflow_probe", "prepare_workflow_state_then_retry"
        if "create_test_object" in tools and (creator_candidates or list_candidates):
            return "create_test_object", "create_object_then_replay"
        return None, None

    def _success_path_preparation_path(self, task: TaskModel, creator_candidates: list[dict[str, Any]], list_candidates: list[dict[str, Any]]) -> tuple[str | None, str | None]:
        if str(task.subtype or "").lower() == "excessive_data_exposure":
            return None, None
        return self._workflow_preparation_path(task, creator_candidates, list_candidates)

    def _preparation_tool_candidates(self, task: TaskModel) -> list[str]:
        values: list[str] = []
        sources: list[str] = []
        if self._is_materialization_strategy(task):
            sources.extend([*(task.allowed_tools or []), *(task.preparation_options or [])])
        else:
            sources.extend([*(task.preparation_options or []), *(task.allowed_tools or [])])
        for item in sources:
            value = str(item or "").strip()
            if value and value not in values:
                values.append(value)
        return values

    def _preferred_preparation_tool(self, task: TaskModel) -> str | None:
        tools = self._preparation_tool_candidates(task)
        if self._is_materialization_strategy(task):
            for tool in ("create_test_object", "workflow_probe"):
                if tool in tools:
                    return tool
        if self._is_auth_bootstrap_strategy(task):
            for tool in ("auto_provision", "auth_probe_entrypoints"):
                if tool in tools:
                    return tool
        return next((tool for tool in tools if tool != "capture_authenticated_traffic"), None)

    def _preparation_tool_fallback(self, task: TaskModel) -> str | None:
        tools = self._preparation_tool_candidates(task)
        for tool in tools:
            if tool in {
                "create_test_object",
                "workflow_probe",
                "input_shape_probe",
                "auto_provision",
                "auth_probe_entrypoints",
            }:
                return tool
        return next((tool for tool in tools if tool != "capture_authenticated_traffic"), None)

    def _is_preparation_task(self, task: TaskModel) -> bool:
        if str(task.readiness or "").lower() == "needs_preparation":
            return True
        strategy = str(task.test_strategy or "").strip().lower()
        strategy_family = str(task.strategy_family or "").strip().lower()
        known = {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "provision_then_replay",
            "prepare_workflow_state_then_retry",
        }
        return strategy in known or strategy_family in known

    def _is_materialization_strategy(self, task: TaskModel) -> bool:
        strategy = str(task.test_strategy or "").strip().lower()
        if strategy in self.MATERIALIZATION_STRATEGIES:
            return True
        if strategy == "object_specific_auth_probe" and not self._real_object_id(task.params.selected_object_id):
            return True
        return (
            bool(task.params.requires_object_id_enrichment)
            and "create_test_object" in self._preparation_tool_candidates(task)
        )

    def _is_auth_bootstrap_strategy(self, task: TaskModel) -> bool:
        strategy = str(task.test_strategy or "").strip().lower()
        if strategy in self.AUTH_BOOTSTRAP_STRATEGIES:
            return True
        return str(task.subtype or "").lower() == "auth_bootstrap"

    def _default_preparation_strategy(self, task: TaskModel, preferred_tool: str | None) -> str | None:
        mapping = {
            "create_test_object": "create_object_then_replay",
            "workflow_probe": "prepare_workflow_state_then_retry",
            "input_shape_probe": "baseline_refinement",
            "auto_provision": "register_then_login_retry",
            "auth_probe_entrypoints": "discover_auth_bootstrap_then_provision",
        }
        return mapping.get(str(preferred_tool or "").strip())

    def _next_best_followups(self, task: TaskModel, creator_candidates: list[dict[str, Any]], list_candidates: list[dict[str, Any]]) -> list[str]:
        values: list[str] = []
        if creator_candidates:
            values.append("create_object_then_replay")
        if list_candidates:
            values.append("list_then_select_object_then_replay")
        if "input_shape_probe" in self._preparation_tool_candidates(task):
            values.append("baseline_refinement")
        if "workflow_probe" in self._preparation_tool_candidates(task):
            values.append("prepare_workflow_state_then_retry")
        if str(task.subtype or "").lower() == "auth_bootstrap":
            values.extend(["login_only_bootstrap_retry", "register_then_login_retry"])
        return values[:5]

    def _real_object_id(self, value: str | int | None) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        if normalized.startswith("{") and normalized.endswith("}"):
            return None
        if self.rejection_analyzer.is_guessed_object_id(normalized):
            return None
        return normalized

    def _has_auth_material(self, role: dict[str, Any]) -> bool:
        return bool(role.get("token") or role.get("auth_headers") or role.get("cookies"))
