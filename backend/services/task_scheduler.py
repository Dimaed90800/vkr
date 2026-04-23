from collections.abc import Mapping
from typing import Any

try:
    from backend.models.scheduling import (
        ExecutabilityDecision,
        FairnessConfig,
        NextTaskResponse,
        QueueUpdateResponse,
        SchedulerSelection,
        SchedulerState,
    )
    from backend.models.testing import ExecutionContext, TaskModel
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
    from backend.services.graph_state_service import DEFAULT_GRAPH_STATE
    from backend.services.followup_task_generation_service import FollowupTaskGenerationService
    from backend.services.task_executability_service import TaskExecutabilityService
    from backend.services.task_fingerprint import TaskFingerprintService
    from backend.services.task_tooling_service import DEFAULT_TASK_TOOLING
except ModuleNotFoundError:  # pragma: no cover
    from models.scheduling import (
        ExecutabilityDecision,
        FairnessConfig,
        NextTaskResponse,
        QueueUpdateResponse,
        SchedulerSelection,
        SchedulerState,
    )
    from models.testing import ExecutionContext, TaskModel
    from services.diagnostic_logging_service import DiagnosticLoggingService
    from services.graph_state_service import DEFAULT_GRAPH_STATE
    from services.followup_task_generation_service import FollowupTaskGenerationService
    from services.task_executability_service import TaskExecutabilityService
    from services.task_fingerprint import TaskFingerprintService
    from services.task_tooling_service import DEFAULT_TASK_TOOLING


class TaskScheduler:
    def __init__(self) -> None:
        self.fingerprints = TaskFingerprintService()
        self.followups = FollowupTaskGenerationService()
        self.diagnostics = DiagnosticLoggingService()
        self.executability = TaskExecutabilityService()
        self.graph_state = DEFAULT_GRAPH_STATE

    def select_next_task(
        self,
        tasks: list[TaskModel],
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
        execution_context: ExecutionContext | None = None,
    ) -> NextTaskResponse:
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        cleaned_tasks = self._semantic_cleanup(tasks, scheduler_state)
        executable_tests, executable_preparation, decisions = self._partition_executable_tasks(
            cleaned_tasks,
            scheduler_state,
            execution_context=execution_context,
        )
        candidate_pool, prioritizing_preparation = self._selection_candidates(
            executable_tests,
            executable_preparation,
            scheduler_state,
            execution_context=execution_context,
        )
        selection = self.schedule(candidate_pool, scheduler_state, fairness_config) if candidate_pool else SchedulerSelection(
            selected_task_id=None,
            selected_class=None,
            reason=self._derive_stop_reason(cleaned_tasks, decisions),
            deferred_classes=[],
            skipped_task_ids=[],
            updated_state=scheduler_state,
        )
        if (
            selection.selected_task_id is not None
            and prioritizing_preparation
            and selection.reason != "selected_materialization_preparation_despite_class_budget"
        ):
            selection = selection.model_copy(update={"reason": "selected_highest_priority_preparation_task"})
        self._log_scheduler_selection(
            original_tasks=tasks,
            cleaned_tasks=cleaned_tasks,
            executable_tests=executable_tests,
            executable_preparation=executable_preparation,
            decisions=decisions,
            state=scheduler_state,
            selection=selection,
        )
        if selection.selected_task_id is None:
            self._log_run_stop(
                original_tasks=tasks,
                cleaned_tasks=cleaned_tasks,
                executable_tests=executable_tests,
                executable_preparation=executable_preparation,
                decisions=decisions,
                state=scheduler_state,
                selection=selection,
            )

        if selection.selected_task_id is None:
            return NextTaskResponse(
                next_task=None,
                remaining_tasks=[],
                scheduler_state=scheduler_state,
                selection_reason=selection.reason,
                deferred_classes=selection.deferred_classes,
                skipped_task_ids=selection.skipped_task_ids,
                should_stop=True,
                executable_test_task_count=len(executable_tests),
                executable_preparation_task_count=len(executable_preparation),
                blocked_by_reason=self._blocked_by_reason(decisions),
                top_non_executable_tasks=self._top_non_executable_tasks(cleaned_tasks, decisions),
            )

        selected_task = next((task for task in candidate_pool if task.id == selection.selected_task_id), None)
        if selected_task is None:
            return NextTaskResponse(
                next_task=None,
                remaining_tasks=[],
                scheduler_state=scheduler_state,
                selection_reason="selected_task_not_found",
                deferred_classes=selection.deferred_classes,
                skipped_task_ids=selection.skipped_task_ids,
                should_stop=True,
                executable_test_task_count=len(executable_tests),
                executable_preparation_task_count=len(executable_preparation),
                blocked_by_reason=self._blocked_by_reason(decisions),
                top_non_executable_tasks=self._top_non_executable_tasks(cleaned_tasks, decisions),
            )
        selected_task = self.executability.prepare_task_for_execution(selected_task, decisions.get(selected_task.id) or ExecutabilityDecision())

        selected_fingerprint = self.fingerprints.task_fingerprint(selected_task)
        remaining_tasks = [
            task
            for task in cleaned_tasks
            if task.id != selected_task.id
            and self.fingerprints.task_fingerprint(task) != selected_fingerprint
        ]
        ordered_remaining = self._order_remaining_lightweight(remaining_tasks)
        return NextTaskResponse(
            next_task=selected_task,
            remaining_tasks=ordered_remaining,
            scheduler_state=selection.updated_state,
            selection_reason=selection.reason,
            deferred_classes=selection.deferred_classes,
            skipped_task_ids=selection.skipped_task_ids,
            should_stop=False,
            executable_test_task_count=len(executable_tests),
            executable_preparation_task_count=len(executable_preparation),
            blocked_by_reason=self._blocked_by_reason(decisions),
            top_non_executable_tasks=self._top_non_executable_tasks(cleaned_tasks, decisions),
        )

    def _order_remaining_lightweight(self, tasks: list[TaskModel]) -> list[TaskModel]:
        return sorted(
            tasks,
            key=lambda item: (
                0 if str(item.readiness or "").lower() == "needs_preparation" else 1,
                -int(item.priority or 0),
                int(item.followup_generation or 0),
                str(item.id or ""),
            ),
        )

    def update_queue_after_verdict(
        self,
        tasks: list[TaskModel],
        active_task: TaskModel | None,
        verdict: str,
        rework_hint: str | None,
        max_retries: int,
        evidence: dict | None = None,
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
        execution_context: ExecutionContext | None = None,
    ) -> QueueUpdateResponse:
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        pending = self._semantic_cleanup(tasks, scheduler_state)
        normalized_verdict = str(verdict or "rejected").lower()
        runtime_context = execution_context.model_copy(deep=True) if execution_context is not None else None

        if active_task is None:
            return self._finalize_queue_update(
                pending=pending,
                scheduler_state=scheduler_state,
                fairness_config=fairness_config,
                execution_context=runtime_context,
                queue_update_reason="no_active_task_to_update",
                requeued_task_id=None,
                generated_followup_task_ids=[],
            )
        if active_task.id == "__no_task__":
            return self._finalize_queue_update(
                pending=pending,
                scheduler_state=scheduler_state,
                fairness_config=fairness_config,
                execution_context=runtime_context,
                queue_update_reason="noop_active_task",
                requeued_task_id=None,
                generated_followup_task_ids=[],
            )

        self._log_judge_input_handoff(
            active_task=active_task,
            scheduler_state=scheduler_state,
            evidence=evidence or {},
        )

        task_fingerprint = self.fingerprints.task_fingerprint(active_task)
        finding_fingerprint = self.fingerprints.finding_fingerprint(active_task, normalized_verdict)
        followup_tasks = self.followups.generate_followups(
            active_task=active_task,
            verdict=normalized_verdict,
            rework_hint=rework_hint,
            evidence=evidence or {},
            pending_tasks=pending,
            state=scheduler_state,
            max_retries=max_retries,
        )
        scheduler_state = self.followups.record_task_outcome(
            scheduler_state,
            active_task,
            followup_count=len(followup_tasks),
        )
        self._log_judge_verdict(
            active_task=active_task,
            scheduler_state=scheduler_state,
            verdict=normalized_verdict,
            evidence=evidence or {},
            rework_hint=rework_hint,
        )

        if normalized_verdict == "confirmed":
            scheduler_state = self._record_completed_fingerprint(scheduler_state, task_fingerprint)
            scheduler_state = self._record_confirmed_fingerprint(scheduler_state, finding_fingerprint)
            pending = self._drop_equivalent_tasks(pending, task_fingerprint, finding_fingerprint)
            self._log_queue_update(
                active_task=active_task,
                scheduler_state=scheduler_state,
                verdict=normalized_verdict,
                evidence=evidence or {},
                queue_update_reason="verdict_confirmed",
                pending_before=len(tasks),
                pending_after=len(pending),
                followup_tasks=[],
                removed_task=True,
            )
            return self._finalize_queue_update(
                pending=pending,
                scheduler_state=scheduler_state,
                fairness_config=fairness_config,
                execution_context=runtime_context,
                queue_update_reason="verdict_confirmed",
                requeued_task_id=None,
                generated_followup_task_ids=[],
                active_task=active_task,
                evidence=evidence or {},
            )

        if normalized_verdict == "rework":
            if followup_tasks:
                pending.extend(followup_tasks)
                pending = self._semantic_cleanup(pending, scheduler_state)
                self._log_queue_update(
                    active_task=active_task,
                    scheduler_state=scheduler_state,
                    verdict=normalized_verdict,
                    evidence=evidence or {},
                    queue_update_reason="generated_rework_followups",
                    pending_before=len(tasks),
                    pending_after=len(pending),
                    followup_tasks=followup_tasks,
                    removed_task=False,
                )
                return self._finalize_queue_update(
                    pending=pending,
                    scheduler_state=scheduler_state,
                    fairness_config=fairness_config,
                    execution_context=runtime_context,
                    queue_update_reason="generated_rework_followups",
                    requeued_task_id=followup_tasks[0].id,
                    generated_followup_task_ids=[task.id for task in followup_tasks],
                    active_task=active_task,
                    evidence=evidence or {},
                )
            updated_task = active_task.model_copy(deep=True)
            updated_task.retry_count = int(updated_task.retry_count or 0) + 1
            updated_task.rework_hint = rework_hint
            if updated_task.retry_count <= int(max_retries or 0):
                updated_task.status = "pending"
                pending.append(updated_task)
                pending = self._semantic_cleanup(pending, scheduler_state)
                self._log_queue_update(
                    active_task=active_task,
                    scheduler_state=scheduler_state,
                    verdict=normalized_verdict,
                    evidence=evidence or {},
                    queue_update_reason="requeued_rework_task",
                    pending_before=len(tasks),
                    pending_after=len(pending),
                    followup_tasks=[updated_task],
                    removed_task=False,
                )
                return self._finalize_queue_update(
                    pending=pending,
                    scheduler_state=scheduler_state,
                    fairness_config=fairness_config,
                    execution_context=runtime_context,
                    queue_update_reason="requeued_rework_task",
                    requeued_task_id=updated_task.id,
                    generated_followup_task_ids=[],
                    active_task=active_task,
                    evidence=evidence or {},
                )
            self._log_queue_update(
                active_task=active_task,
                scheduler_state=scheduler_state,
                verdict=normalized_verdict,
                evidence=evidence or {},
                queue_update_reason="rework_retry_limit_exceeded",
                pending_before=len(tasks),
                pending_after=len(pending),
                followup_tasks=[],
                removed_task=False,
            )
            return self._finalize_queue_update(
                pending=pending,
                scheduler_state=scheduler_state,
                fairness_config=fairness_config,
                execution_context=runtime_context,
                queue_update_reason="rework_retry_limit_exceeded",
                requeued_task_id=None,
                generated_followup_task_ids=[],
                active_task=active_task,
                evidence=evidence or {},
            )

        if followup_tasks:
            scheduler_state = self._record_completed_fingerprint(scheduler_state, task_fingerprint)
            pending = self._drop_equivalent_tasks(pending, task_fingerprint, None)
            pending.extend(followup_tasks)
            pending = self._semantic_cleanup(pending, scheduler_state)
            self._log_queue_update(
                active_task=active_task,
                scheduler_state=scheduler_state,
                verdict=normalized_verdict,
                evidence=evidence or {},
                queue_update_reason=f"verdict_{normalized_verdict}_generated_followups",
                pending_before=len(tasks),
                pending_after=len(pending),
                followup_tasks=followup_tasks,
                removed_task=True,
            )
            return self._finalize_queue_update(
                pending=pending,
                scheduler_state=scheduler_state,
                fairness_config=fairness_config,
                execution_context=runtime_context,
                queue_update_reason=f"verdict_{normalized_verdict}_generated_followups",
                requeued_task_id=followup_tasks[0].id,
                generated_followup_task_ids=[task.id for task in followup_tasks],
                active_task=active_task,
                evidence=evidence or {},
            )

        scheduler_state = self._record_completed_fingerprint(scheduler_state, task_fingerprint)
        pending = self._drop_equivalent_tasks(pending, task_fingerprint, None)
        self._log_queue_update(
            active_task=active_task,
            scheduler_state=scheduler_state,
            verdict=normalized_verdict,
            evidence=evidence or {},
            queue_update_reason=f"verdict_{normalized_verdict}",
            pending_before=len(tasks),
            pending_after=len(pending),
            followup_tasks=[],
            removed_task=True,
        )
        return self._finalize_queue_update(
            pending=pending,
            scheduler_state=scheduler_state,
            fairness_config=fairness_config,
            execution_context=runtime_context,
            queue_update_reason=f"verdict_{normalized_verdict}",
            requeued_task_id=None,
            generated_followup_task_ids=[],
            active_task=active_task,
            evidence=evidence or {},
        )

    def _finalize_queue_update(
        self,
        *,
        pending: list[TaskModel],
        scheduler_state: SchedulerState,
        fairness_config: FairnessConfig,
        execution_context: ExecutionContext | None,
        queue_update_reason: str,
        requeued_task_id: str | None,
        generated_followup_task_ids: list[str],
        active_task: TaskModel | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> QueueUpdateResponse:
        enriched_pending, updated_context, enrichment = self._apply_evidence_runtime_enrichment(
            pending,
            active_task=active_task,
            evidence=evidence or {},
            execution_context=execution_context,
            scheduler_state=scheduler_state,
        )
        ordered_pending = self._order_remaining_lightweight(self._semantic_cleanup(enriched_pending, scheduler_state))
        return QueueUpdateResponse(
            pending_tasks=ordered_pending,
            scheduler_state=scheduler_state,
            queue_update_reason=queue_update_reason,
            requeued_task_id=requeued_task_id,
            generated_followup_task_ids=generated_followup_task_ids,
            should_stop=len(ordered_pending) == 0,
            updated_execution_context=updated_context,
            queue_enrichment=enrichment,
        )

    def _apply_evidence_runtime_enrichment(
        self,
        pending: list[TaskModel],
        *,
        active_task: TaskModel | None,
        evidence: dict[str, Any],
        execution_context: ExecutionContext | None,
        scheduler_state: SchedulerState,
    ) -> tuple[list[TaskModel], ExecutionContext | None, dict[str, Any]]:
        if execution_context is None:
            return pending, execution_context, {}
        context = execution_context.model_copy(deep=True)
        self.graph_state.ensure_graph(context)
        artifacts = self._artifact_map(evidence)
        enriched_task_ids: list[str] = []
        queue_enrichment: dict[str, Any] = {}

        prepared_roles = artifacts.get("provisioned_identities") if isinstance(artifacts.get("provisioned_identities"), list) else []
        if prepared_roles:
            context.roles = self._merge_roles(context.roles, prepared_roles)
            self.graph_state.upsert_auth_identities(context, prepared_roles)
            context.capabilities["has_auth_profiles"] = any(self._has_auth_material(item) for item in context.roles)
            context.capabilities["has_multi_role_auth"] = sum(1 for item in context.roles if self._has_auth_material(item)) >= 2
            context.capabilities["has_provisioned_identities"] = context.capabilities["has_multi_role_auth"]

        discovered_auth_endpoints = artifacts.get("discovered_auth_endpoints") if isinstance(artifacts.get("discovered_auth_endpoints"), list) else []
        if discovered_auth_endpoints:
            context.discovered_auth_endpoints = self._merge_endpoint_dicts(context.discovered_auth_endpoints, discovered_auth_endpoints, ("type", "path", "method"))
            context.capabilities["has_login_endpoint"] = any(str(item.get("type") or "").lower() == "login" for item in context.discovered_auth_endpoints if isinstance(item, dict))
            context.capabilities["has_register_endpoint"] = any(str(item.get("type") or "").lower() == "register" for item in context.discovered_auth_endpoints if isinstance(item, dict))

        prepared_object = artifacts.get("prepared_object") if isinstance(artifacts.get("prepared_object"), dict) else None
        harvested_object_ids = [str(item).strip() for item in (artifacts.get("harvested_object_ids") or []) if str(item).strip()]
        harvested_links = [str(item).strip() for item in (artifacts.get("harvested_links") or []) if str(item).strip()]
        workflow_context = artifacts.get("workflow_context") if isinstance(artifacts.get("workflow_context"), dict) else None
        replay_endpoint = ""
        replay_path_params: dict[str, Any] = {}
        propagated_object_id = None
        propagation_family = ""
        propagation_source = ""

        if isinstance(prepared_object, dict):
            propagated_object_id = self._normalize_object_id(prepared_object.get("object_id"))
            propagation_family = str(prepared_object.get("resource_family") or prepared_object.get("object_type") or "").strip().lower()
            propagation_source = str(prepared_object.get("source") or "prepared_object").strip() or "prepared_object"
            replay_endpoint = str(prepared_object.get("replay_endpoint_template") or prepared_object.get("replay_ready_endpoint") or "").strip()
            replay_path_params = dict(prepared_object.get("replay_path_params") or {}) if isinstance(prepared_object.get("replay_path_params"), dict) else {}
            if propagated_object_id:
                prepared_copy = dict(prepared_object)
                prepared_copy["object_id"] = propagated_object_id
                if propagation_family:
                    context.prepared_objects[propagation_family] = prepared_copy
                self.graph_state.upsert_prepared_object(context, prepared_copy)

        if not propagated_object_id and isinstance(workflow_context, dict):
            propagated_object_id = self._normalize_object_id(workflow_context.get("object_id"))
            propagation_family = str(workflow_context.get("resource_family") or "").strip().lower()
            propagation_source = str(workflow_context.get("source") or "workflow_context").strip() or "workflow_context"
            replay_endpoint = replay_endpoint or str(workflow_context.get("replay_endpoint_template") or workflow_context.get("replay_ready_endpoint") or "").strip()
            replay_path_params = dict(workflow_context.get("replay_path_params") or {}) if isinstance(workflow_context.get("replay_path_params"), dict) else replay_path_params
            if propagated_object_id:
                context.workflow_context = dict(workflow_context)

        if not propagated_object_id and harvested_object_ids:
            propagated_object_id = self._normalize_object_id(harvested_object_ids[0])
            propagation_source = "harvested_from_list"
            if not propagation_family and active_task is not None:
                propagation_family = self._task_resource_family(active_task)

        if harvested_object_ids:
            context.harvested_object_ids = self._merge_strings(context.harvested_object_ids, harvested_object_ids)
            self.graph_state.upsert_harvested_ids(context, harvested_object_ids, resource_family=propagation_family or self._task_resource_family(active_task) if active_task is not None else "")
        if harvested_links:
            context.harvested_links = self._merge_strings(context.harvested_links, harvested_links)
        if propagated_object_id:
            context.capabilities["has_object_candidates"] = True
            if propagation_family and propagation_family not in context.prepared_objects:
                context.prepared_objects[propagation_family] = {
                    "object_id": propagated_object_id,
                    "resource_family": propagation_family,
                    "source": propagation_source or "propagated_from_execution_context",
                }

        if isinstance(workflow_context, dict) and workflow_context:
            context.workflow_context = dict(workflow_context)
            self.graph_state.upsert_workflow_context(context, workflow_context)
            if self._normalize_object_id(workflow_context.get("object_id")):
                context.capabilities["has_workflow_hints"] = True

        if propagated_object_id:
            pending, enriched_task_ids = self._enrich_tasks_with_object(
                pending,
                object_id=propagated_object_id,
                resource_family=propagation_family,
                replay_endpoint=replay_endpoint,
                replay_path_params=replay_path_params,
            )
            if not enriched_task_ids and active_task is not None:
                replay = self._build_post_preparation_replay_task(active_task, propagated_object_id, propagation_family, replay_endpoint=replay_endpoint, replay_path_params=replay_path_params)
                if replay is not None:
                    pending = [replay, *pending]
                    enriched_task_ids.append(replay.id)
            queue_enrichment = {
                "resource_family": propagation_family,
                "propagated_object_id": propagated_object_id,
                "source": propagation_source or "propagated_from_execution_context",
                "enriched_task_ids": enriched_task_ids,
            }
            self.diagnostics.emit(
                event_type="queue_enrichment_applied",
                component="queue_update",
                status="success",
                summary=f"Propagated object context for family={propagation_family or 'generic_resource'}.",
                run_id=scheduler_state.run_id,
                trace_context=self.diagnostics.trace_context(
                    run_id=scheduler_state.run_id,
                    root_trace_id=scheduler_state.root_trace_id,
                    task=active_task,
                ),
                artifacts=queue_enrichment,
                counters={"enriched_task_count": len(enriched_task_ids)},
            )
        return pending, context, queue_enrichment

    def schedule(
        self,
        tasks: list[TaskModel],
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
    ) -> SchedulerSelection:
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()

        if not tasks:
            return SchedulerSelection(
                selected_task_id=None,
                selected_class=None,
                reason="no_tasks_available",
                deferred_classes=[],
                skipped_task_ids=[],
                updated_state=scheduler_state,
            )

        ordered_tasks = sorted(tasks, key=lambda item: int(item.priority or 0), reverse=True)
        deferred_classes: list[str] = []
        skipped_task_ids: list[str] = []
        budget_blocked_classes: set[str] = set()

        for task in ordered_tasks:
            task_class = str(task.class_name or "").lower()
            if not self._is_class_budget_available(task_class, scheduler_state, fairness_config):
                deferred_classes.append(task_class)
                skipped_task_ids.append(task.id)
                budget_blocked_classes.add(task_class)
                continue
            if not self._is_consecutive_slot_available(task_class, scheduler_state, fairness_config, ordered_tasks):
                deferred_classes.append(task_class)
                skipped_task_ids.append(task.id)
                continue

            updated_state = self._advance_state(task, scheduler_state)
            return SchedulerSelection(
                selected_task_id=task.id,
                selected_class=task_class,
                reason="selected_highest_priority_eligible_task",
                deferred_classes=sorted(set(deferred_classes)),
                skipped_task_ids=skipped_task_ids,
                updated_state=updated_state,
            )

        materialization_task = self._materialization_preparation_fallback(ordered_tasks)
        if materialization_task is not None:
            updated_state = self._advance_state(materialization_task, scheduler_state, count_class_budget=False)
            return SchedulerSelection(
                selected_task_id=materialization_task.id,
                selected_class=str(materialization_task.class_name or "").lower(),
                reason="selected_materialization_preparation_despite_class_budget",
                deferred_classes=sorted(set(deferred_classes)),
                skipped_task_ids=[task_id for task_id in skipped_task_ids if task_id != materialization_task.id],
                updated_state=updated_state,
            )

        fallback_task = self._safe_fallback_candidate(ordered_tasks, scheduler_state)
        if fallback_task is not None:
            updated_state = self._advance_state(fallback_task, scheduler_state)
            return SchedulerSelection(
                selected_task_id=fallback_task.id,
                selected_class=str(fallback_task.class_name or "").lower(),
                reason="fallback_single_class_queue",
                deferred_classes=sorted(set(deferred_classes)),
                skipped_task_ids=skipped_task_ids,
                updated_state=updated_state,
            )

        present_classes = {
            str(task.class_name or "").lower()
            for task in ordered_tasks
            if str(task.class_name or "").strip()
        }
        if present_classes and present_classes.issubset(budget_blocked_classes):
            reason = "all_class_budgets_exhausted"
        else:
            reason = "no_eligible_task_after_fairness"
        return SchedulerSelection(
            selected_task_id=None,
            selected_class=None,
            reason=reason,
            deferred_classes=sorted(set(deferred_classes)),
            skipped_task_ids=skipped_task_ids,
            updated_state=scheduler_state,
        )

    def order_queue(
        self,
        tasks: list[TaskModel],
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
        execution_context: ExecutionContext | None = None,
    ) -> tuple[list[TaskModel], SchedulerState]:
        remaining = self._semantic_cleanup(tasks, state or SchedulerState())
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        ordered: list[TaskModel] = []

        while remaining:
            executable_tests, executable_preparation, decisions = self._partition_executable_tasks(
                remaining,
                scheduler_state,
                execution_context=execution_context,
            )
            candidate_pool, _ = self._selection_candidates(
                executable_tests,
                executable_preparation,
                scheduler_state,
                execution_context=execution_context,
            )
            if not candidate_pool:
                break
            selection = self.schedule(candidate_pool, scheduler_state, fairness_config)
            if selection.selected_task_id is None:
                break
            selected = next((task for task in candidate_pool if task.id == selection.selected_task_id), None)
            if selected is None:
                break
            selected = self.executability.prepare_task_for_execution(selected, decisions.get(selected.id) or ExecutabilityDecision())
            ordered.append(selected)
            remaining = [task for task in remaining if task.id != selected.id]
            scheduler_state = selection.updated_state

        ordered.extend(self._sort_blocked_tasks(remaining, scheduler_state, execution_context=execution_context))
        return ordered, scheduler_state

    def _semantic_cleanup(
        self,
        tasks: list[TaskModel],
        state: SchedulerState,
    ) -> list[TaskModel]:
        completed = set(state.completed_task_fingerprints or [])
        confirmed = set(state.confirmed_finding_fingerprints or [])
        deduped: dict[str, TaskModel] = {}

        for task in sorted(
            [item for item in tasks if isinstance(item, TaskModel)],
            key=lambda item: (-int(item.priority or 0), int(item.retry_count or 0), item.id),
        ):
            task_fingerprint = self.fingerprints.task_fingerprint(task)
            finding_fingerprint = self.fingerprints.finding_fingerprint(task, "confirmed")
            if task_fingerprint in completed or finding_fingerprint in confirmed:
                continue
            if task_fingerprint not in deduped:
                deduped[task_fingerprint] = task

        return list(deduped.values())

    def _partition_executable_tasks(
        self,
        tasks: list[TaskModel],
        state: SchedulerState,
        *,
        execution_context: ExecutionContext | None = None,
    ) -> tuple[list[TaskModel], list[TaskModel], dict[str, ExecutabilityDecision]]:
        executable_tests: list[TaskModel] = []
        executable_preparation: list[TaskModel] = []
        decisions: dict[str, ExecutabilityDecision] = {}
        for task in tasks:
            decision = self.executability.evaluate(task, execution_context=execution_context, scheduler_state=state)
            decisions[task.id] = decision
            prepared_task = self.executability.prepare_task_for_execution(task, decision)
            self._log_task_executability(task=prepared_task, state=state, decision=decision)
            if not decision.executable:
                continue
            if decision.execution_mode == "test":
                executable_tests.append(prepared_task)
            elif decision.execution_mode == "preparation":
                executable_preparation.append(prepared_task)
        executable_tests.sort(key=lambda item: int(item.priority or 0), reverse=True)
        executable_preparation.sort(key=lambda item: int(item.priority or 0), reverse=True)
        return executable_tests, executable_preparation, decisions

    def _derive_stop_reason(self, tasks: list[TaskModel], decisions: dict[str, ExecutabilityDecision]) -> str:
        if not tasks:
            return "no_tasks_available"
        blocked_by_reason = self._blocked_by_reason(decisions)
        if blocked_by_reason.get("missing_object_materialization_path"):
            return "missing_object_materialization_path"
        if blocked_by_reason.get("missing_valid_baseline_path"):
            return "missing_valid_baseline_path"
        if blocked_by_reason.get("no_executable_preparation_tasks"):
            return "no_executable_preparation_tasks"
        if any(decision.execution_mode == "preparation" for decision in decisions.values()):
            return "no_executable_test_tasks"
        return "no_executable_tasks"

    def _blocked_by_reason(self, decisions: dict[str, ExecutabilityDecision]) -> dict[str, int]:
        counters: dict[str, int] = {}
        for decision in decisions.values():
            if decision.executable:
                continue
            reason = str(decision.block_reason or "unknown").strip() or "unknown"
            counters[reason] = int(counters.get(reason, 0) or 0) + 1
        return counters

    def _top_non_executable_tasks(self, tasks: list[TaskModel], decisions: dict[str, ExecutabilityDecision]) -> list[dict]:
        blocked: list[dict] = []
        for task in sorted(tasks, key=lambda item: int(item.priority or 0), reverse=True):
            decision = decisions.get(task.id)
            if decision is None or decision.executable:
                continue
            blocked.append(
                {
                    "id": task.id,
                    "endpoint": task.endpoint,
                    "class": task.class_name,
                    "subtype": task.subtype,
                    "reason": decision.block_reason,
                    "missing_prerequisites": list(decision.missing_prerequisites or [])[:4],
                }
            )
            if len(blocked) >= 5:
                break
        return blocked

    def _sort_blocked_tasks(
        self,
        tasks: list[TaskModel],
        state: SchedulerState,
        *,
        execution_context: ExecutionContext | None = None,
    ) -> list[TaskModel]:
        scored: list[tuple[int, int, TaskModel]] = []
        for task in tasks:
            decision = self.executability.evaluate(task, execution_context=execution_context, scheduler_state=state)
            mode_rank = 0 if decision.execution_mode == "preparation" and decision.executable else 1
            scored.append((mode_rank, -int(task.priority or 0), task))
        return [item[2] for item in sorted(scored, key=lambda value: (value[0], value[1], value[2].id))]

    def _artifact_map(self, evidence: dict[str, Any]) -> dict[str, Any]:
        artifacts: dict[str, Any] = {}
        for item in evidence.get("artifacts") or []:
            if not isinstance(item, dict):
                continue
            artifact_type = str(item.get("type") or "").strip()
            if artifact_type:
                artifacts[artifact_type] = item.get("value")
        return artifacts

    def _normalize_object_id(self, value: Any) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        if normalized.lower() in {"id", "{id}", "video_id", "{video_id}", "order_id", "{order_id}", "postid", "{postid}", "post_id", "{post_id}", "vehicleid", "{vehicleid}", "vehicle_id", "{vehicle_id}", "report_id", "{report_id}"}:
            return None
        return normalized

    def _has_auth_material(self, role: dict[str, Any] | None) -> bool:
        if not isinstance(role, dict):
            return False
        return bool(role.get("token") or role.get("auth_headers") or role.get("cookies"))

    def _merge_roles(self, existing_roles: list[dict[str, Any]], prepared_roles: list[dict[str, Any]]) -> list[dict[str, Any]]:
        merged: dict[str, dict[str, Any]] = {}
        for role in [*(existing_roles or []), *(prepared_roles or [])]:
            if not isinstance(role, dict):
                continue
            name = str(role.get("name") or role.get("role") or "").strip()
            if not name:
                continue
            current = dict(merged.get(name) or {})
            current.update(role)
            merged[name] = current
        return [merged[key] for key in sorted(merged.keys())]

    def _merge_endpoint_dicts(
        self,
        existing_items: list[dict[str, Any]],
        new_items: list[dict[str, Any]],
        keys: tuple[str, ...],
    ) -> list[dict[str, Any]]:
        merged: list[dict[str, Any]] = []
        seen: set[tuple[str, ...]] = set()
        for item in [*(existing_items or []), *(new_items or [])]:
            if not isinstance(item, dict):
                continue
            fingerprint = tuple(str(item.get(key) or "").strip() for key in keys)
            if not any(fingerprint):
                continue
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            merged.append(dict(item))
        return merged

    def _merge_strings(self, existing: list[str], new_items: list[str]) -> list[str]:
        merged: list[str] = []
        seen: set[str] = set()
        for item in [*(existing or []), *(new_items or [])]:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            merged.append(value)
        return merged

    def _task_resource_family(self, task: TaskModel) -> str:
        if str(task.resource_family or "").strip():
            return str(task.resource_family or "").strip().lower()
        hints = task.context_hints or {}
        value = str(hints.get("resource_family") or "").strip().lower() if isinstance(hints, dict) else ""
        return value or "generic_resource"

    def _task_accepts_family(self, task: TaskModel, family: str) -> bool:
        if not family:
            return False
        task_family = self._task_resource_family(task)
        if task_family == family:
            return True
        aliases = {
            "mechanic": {"report", "service_request"},
            "report": {"mechanic", "service_request"},
            "service_request": {"report", "mechanic"},
        }
        return family in aliases.get(task_family, set()) or task_family in aliases.get(family, set())

    def _is_object_dependent_task(self, task: TaskModel) -> bool:
        if bool(task.params.requires_object_id_enrichment) or bool(task.prerequisites.requires_object_id):
            return True
        endpoint = str(task.endpoint or "")
        if "{" in endpoint and "}" in endpoint:
            return True
        strategy = str(task.test_strategy or "").strip().lower()
        subtype = str(task.subtype or "").strip().lower()
        hypothesis_family = str(task.hypothesis_family or "").strip().lower()
        return strategy in {"object_specific_auth_probe", "create_object_then_replay", "list_then_select_object_then_replay"} or subtype == "bola" or hypothesis_family == "object_authorization"

    def _should_apply_object_replay_endpoint(self, task: TaskModel, replay_endpoint: str) -> bool:
        endpoint_value = str(replay_endpoint or "").strip()
        if not endpoint_value:
            return False
        if self._is_object_dependent_task(task):
            return True
        strategy = str(task.test_strategy or "").strip().lower()
        origin_reason = str(task.origin_reason or "").strip().lower()
        return strategy.endswith("_replay") or origin_reason == "preparation_replay"

    def _direct_test_tool(self, task: TaskModel) -> str:
        preferred = str(task.preferred_tool or (task.tool_preference.preferred_tool if task.tool_preference else "") or "").strip()
        normalized_allowed = list(getattr(task, "allowed_tools", None) or [])
        prep_tools = {"auto_provision", "auth_probe_entrypoints", "create_test_object", "workflow_probe", "input_shape_probe", "import_har_capture"}
        if preferred and preferred in normalized_allowed and preferred not in prep_tools:
            return preferred
        if task.class_name == "authorization":
            return "property_mutation_test" if task.subtype in {"property_level_authorization", "mass_assignment"} else "auth_test_access"
        if task.class_name == "injection":
            return "injection_test"
        mapping = {
            "excessive_data_exposure": "data_exposure_test",
            "resource_abuse_rate_limit": "resource_abuse_test",
            "security_misconfiguration": "misconfiguration_test",
            "improper_assets_management": "version_diff_test",
            "documentation_inventory_leak": "version_diff_test",
        }
        return mapping.get(str(task.hypothesis_family or ""), "logic_test")

    def _test_strategy_for_replay(self, task: TaskModel) -> str:
        if task.class_name == "authorization" and self._is_object_dependent_task(task):
            return "object_specific_auth_probe"
        if task.class_name == "business_logic":
            return "workflow_sequence_probe"
        if task.class_name == "injection":
            return "direct_input_probe"
        return str(task.test_strategy or "cross_role_replay")

    def _enrich_tasks_with_object(
        self,
        tasks: list[TaskModel],
        *,
        object_id: str,
        resource_family: str,
        replay_endpoint: str = "",
        replay_path_params: Mapping[str, Any] | None = None,
    ) -> tuple[list[TaskModel], list[str]]:
        enriched: list[TaskModel] = []
        enriched_ids: list[str] = []
        for task in tasks:
            updated = DEFAULT_TASK_TOOLING.mutable_task_copy(task)
            if not self._task_accepts_family(updated, resource_family):
                enriched.append(updated)
                continue
            existing_candidates = [str(item).strip() for item in (updated.params.object_id_candidates or []) if str(item).strip()]
            if object_id not in existing_candidates:
                existing_candidates.insert(0, object_id)
            updated.params.object_id_candidates = existing_candidates[:10]
            updated.params.selected_object_id = object_id
            updated.params.requires_object_id_enrichment = False
            updated.capability_state["has_object_candidates"] = True
            updated.context_source = updated.context_source or "propagated"
            if self._should_apply_object_replay_endpoint(updated, replay_endpoint):
                updated.endpoint = replay_endpoint
                placeholders = self._extract_placeholders(replay_endpoint)
                if placeholders:
                    updated.params.object_param_name = str(placeholders[0])
                elif isinstance(replay_path_params, Mapping) and replay_path_params:
                    first_key = next(iter(replay_path_params.keys()))
                    updated.params.object_param_name = str(first_key)
            if updated.readiness == "needs_preparation" and self._is_object_dependent_task(updated):
                updated.readiness = "ready_to_test"
                updated.allowed_tools = [self._direct_test_tool(updated)]
                updated.preparation_options = []
                updated.test_strategy = self._test_strategy_for_replay(updated)
                updated = DEFAULT_TASK_TOOLING.normalize_task(updated, explicit_allowed_tools=updated.allowed_tools)
            enriched.append(updated)
            enriched_ids.append(updated.id)
        return enriched, enriched_ids

    def _build_post_preparation_replay_task(
        self,
        active_task: TaskModel,
        object_id: str,
        resource_family: str,
        *,
        replay_endpoint: str = "",
        replay_path_params: Mapping[str, Any] | None = None,
    ) -> TaskModel | None:
        if active_task is None or active_task.class_name not in {"authorization", "business_logic"}:
            return None
        replay = DEFAULT_TASK_TOOLING.mutable_task_copy(active_task)
        replay.id = f"{active_task.id}__prepared_replay"
        replay.parent_task_id = str(active_task.parent_task_id or active_task.id)
        replay.followup_generation = int(active_task.followup_generation or 0) + 1
        replay.origin_reason = "preparation_replay"
        replay.params.selected_object_id = object_id
        replay.params.requires_object_id_enrichment = False
        candidates = [str(item).strip() for item in (replay.params.object_id_candidates or []) if str(item).strip()]
        if object_id not in candidates:
            candidates.insert(0, object_id)
        replay.params.object_id_candidates = candidates[:10]
        replay.resource_family = replay.resource_family or resource_family
        if self._should_apply_object_replay_endpoint(replay, replay_endpoint):
            replay.endpoint = replay_endpoint
            placeholders = self._extract_placeholders(replay_endpoint)
            if placeholders:
                replay.params.object_param_name = str(placeholders[0])
            elif isinstance(replay_path_params, Mapping) and replay_path_params:
                replay.params.object_param_name = str(next(iter(replay_path_params.keys())))
        replay.readiness = "ready_to_test"
        replay.allowed_tools = [self._direct_test_tool(replay)]
        replay.preparation_options = []
        replay.test_strategy = self._test_strategy_for_replay(replay)
        replay = DEFAULT_TASK_TOOLING.normalize_task(replay, explicit_allowed_tools=replay.allowed_tools)
        replay.priority = min(100, int(replay.priority or 0) + 8)
        return replay

    def _drop_equivalent_tasks(
        self,
        tasks: list[TaskModel],
        task_fingerprint: str | None,
        finding_fingerprint: str | None,
    ) -> list[TaskModel]:
        filtered: list[TaskModel] = []
        for task in tasks:
            candidate_task_fingerprint = self.fingerprints.task_fingerprint(task)
            candidate_finding_fingerprint = self.fingerprints.finding_fingerprint(task, "confirmed")
            if task_fingerprint and candidate_task_fingerprint == task_fingerprint:
                continue
            if finding_fingerprint and candidate_finding_fingerprint == finding_fingerprint:
                continue
            filtered.append(task)
        return filtered

    def _record_completed_fingerprint(self, state: SchedulerState, fingerprint: str) -> SchedulerState:
        completed = list(state.completed_task_fingerprints or [])
        if fingerprint and fingerprint not in completed:
            completed.append(fingerprint)
        return state.model_copy(update={"completed_task_fingerprints": completed})

    def _record_confirmed_fingerprint(self, state: SchedulerState, fingerprint: str) -> SchedulerState:
        confirmed = list(state.confirmed_finding_fingerprints or [])
        if fingerprint and fingerprint not in confirmed:
            confirmed.append(fingerprint)
        return state.model_copy(update={"confirmed_finding_fingerprints": confirmed})

    def _is_class_budget_available(
        self,
        task_class: str,
        state: SchedulerState,
        fairness: FairnessConfig,
    ) -> bool:
        limit = fairness.max_tasks_per_class_per_run.get(task_class)
        if limit is None:
            return True
        current = int(state.class_budget_used.get(task_class, 0) or 0)
        return current < limit

    def _is_consecutive_slot_available(
        self,
        task_class: str,
        state: SchedulerState,
        fairness: FairnessConfig,
        tasks: list[TaskModel],
    ) -> bool:
        if state.last_executed_class != task_class:
            return True
        if state.consecutive_class_count < fairness.max_consecutive_tasks_per_class:
            return True

        return not any(
            str(task.class_name or "").lower() != task_class
            and self._is_class_budget_available(str(task.class_name or "").lower(), state, fairness)
            for task in tasks
        )

    def _advance_state(self, task: TaskModel, state: SchedulerState, *, count_class_budget: bool = True) -> SchedulerState:
        task_class = str(task.class_name or "").lower()
        budget_used = dict(state.class_budget_used)
        tasks_completed = dict(state.class_tasks_completed)
        retries_used = dict(state.class_retries_used)

        if count_class_budget:
            budget_used[task_class] = int(budget_used.get(task_class, 0) or 0) + 1
        tasks_completed[task_class] = int(tasks_completed.get(task_class, 0) or 0) + 1
        if int(task.retry_count or 0) > 0:
            retries_used[task_class] = int(retries_used.get(task_class, 0) or 0) + 1

        consecutive_count = 1
        if state.last_executed_class == task_class:
            consecutive_count = int(state.consecutive_class_count or 0) + 1

        return state.model_copy(
            update={
                "class_budget_used": budget_used,
                "class_tasks_completed": tasks_completed,
                "class_retries_used": retries_used,
                "consecutive_class_count": consecutive_count,
                "last_executed_class": task_class,
                "preparation_budget_used": int(state.preparation_budget_used or 0) + (1 if self._is_preparation_task(task) else 0),
                "exploration_budget_used": int(state.exploration_budget_used or 0) + (0 if self._is_preparation_task(task) else 1),
                "deepening_budget_used": int(state.deepening_budget_used or 0) + (1 if int(task.followup_generation or 0) > 0 else 0),
            }
        )

    def _materialization_preparation_fallback(self, ordered_tasks: list[TaskModel]) -> TaskModel | None:
        for task in ordered_tasks:
            if self._is_materialization_preparation_task(task):
                return task
        return None

    def _is_materialization_preparation_task(self, task: TaskModel) -> bool:
        if str(task.readiness or "").lower() != "needs_preparation":
            return False
        strategy = str(task.test_strategy or "").strip().lower()
        strategy_family = str(task.strategy_family or "").strip().lower()
        if strategy not in {"create_object_then_replay", "list_then_select_object_then_replay"} and strategy_family != "object_materialization":
            return False
        tools = {
            str(item or "").strip()
            for item in [
                *(task.allowed_tools or []),
                *(task.preparation_options or []),
                task.preferred_tool,
                task.recommended_next_step,
            ]
            if str(item or "").strip()
        }
        return "create_test_object" in tools and not self._normalize_object_id(task.params.selected_object_id)

    def _extract_placeholders(self, endpoint: str) -> list[str]:
        placeholders: list[str] = []
        current = ""
        in_placeholder = False
        for char in str(endpoint or ""):
            if char == "{":
                current = ""
                in_placeholder = True
            elif char == "}":
                if current:
                    placeholders.append(current)
                in_placeholder = False
            elif in_placeholder:
                current += char
        return placeholders

    def _materialization_preparation_tasks(self, tasks: list[TaskModel]) -> list[TaskModel]:
        prioritized = [task for task in tasks if self._is_materialization_preparation_task(task)]
        prioritized.sort(key=lambda item: int(item.priority or 0), reverse=True)
        return prioritized


    def _selection_candidates(
        self,
        executable_tests: list[TaskModel],
        executable_preparation: list[TaskModel],
        state: SchedulerState,
        *,
        execution_context: ExecutionContext | None = None,
    ) -> tuple[list[TaskModel], bool]:
        materialization_preparation = self._materialization_preparation_tasks(executable_preparation)
        if materialization_preparation:
            prioritized = materialization_preparation + [task for task in executable_preparation if task.id not in {item.id for item in materialization_preparation}]
            return prioritized, True
        if executable_preparation and self._should_prioritize_preparation(
            executable_tests,
            executable_preparation,
            state,
            execution_context=execution_context,
        ):
            return executable_preparation, True
        if executable_tests:
            return executable_tests, False
        if executable_preparation:
            return executable_preparation, True
        return [], False

    def _should_prioritize_preparation(
        self,
        executable_tests: list[TaskModel],
        executable_preparation: list[TaskModel],
        state: SchedulerState,
        *,
        execution_context: ExecutionContext | None = None,
    ) -> bool:
        if not executable_preparation:
            return False
        if not executable_tests:
            return True
        capabilities = (execution_context.capabilities or {}) if execution_context is not None else {}
        missing_auth_profiles = not bool(capabilities.get("has_auth_profiles"))
        missing_object_candidates = not bool(capabilities.get("has_object_candidates"))
        preparation_budget_used = int(state.preparation_budget_used or 0)
        exploration_budget_used = int(state.exploration_budget_used or 0)
        if missing_auth_profiles or missing_object_candidates:
            return preparation_budget_used <= exploration_budget_used
        top_preparation_priority = max(int(task.priority or 0) for task in executable_preparation)
        top_test_priority = max(int(task.priority or 0) for task in executable_tests)
        if top_preparation_priority >= top_test_priority:
            return preparation_budget_used <= exploration_budget_used
        return False

    def _is_preparation_task(self, task: TaskModel) -> bool:
        if str(task.readiness or "").lower() == "needs_preparation":
            return True
        strategy = str(task.test_strategy or "").strip().lower()
        return strategy in {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "provision_then_replay",
            "prepare_workflow_state_then_retry",
            "login_only_bootstrap_retry",
            "register_then_login_retry",
            "baseline_refinement",
        }

    def _safe_fallback_candidate(
        self,
        ordered_tasks: list[TaskModel],
        state: SchedulerState,
    ) -> TaskModel | None:
        if not ordered_tasks:
            return None
        if self._single_semantic_class_queue(ordered_tasks):
            return ordered_tasks[0]
        if not self._has_other_class(ordered_tasks, state.last_executed_class):
            return ordered_tasks[0]
        return None

    def _single_semantic_class_queue(self, tasks: list[TaskModel]) -> bool:
        classes = {
            str(task.class_name or "").lower()
            for task in tasks
            if str(task.class_name or "").strip()
        }
        return len(classes) <= 1

    def _has_other_class(
        self,
        tasks: list[TaskModel],
        task_class: str | None,
    ) -> bool:
        current = str(task_class or "").lower().strip()
        if not current:
            return False
        return any(str(task.class_name or "").lower() != current for task in tasks)

    def _log_scheduler_selection(
        self,
        *,
        original_tasks: list[TaskModel],
        cleaned_tasks: list[TaskModel],
        executable_tests: list[TaskModel],
        executable_preparation: list[TaskModel],
        decisions: dict[str, ExecutabilityDecision],
        state: SchedulerState,
        selection: SchedulerSelection,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=state.run_id,
            root_trace_id=state.root_trace_id,
            extra={"trace_id": state.root_trace_id or state.run_id},
        )
        blocked_count = sum(1 for decision in decisions.values() if not decision.executable)
        waiting_for_preparation_count = len(executable_preparation)
        deduped_count = max(len(original_tasks) - len(cleaned_tasks), 0)
        blocked_by_reason = self._blocked_by_reason(decisions)
        event_type = "scheduler_no_task" if selection.selected_task_id is None else "scheduler_selection"
        self.diagnostics.emit(
            event_type=event_type,
            component="scheduler",
            status="stop" if selection.selected_task_id is None else "selected",
            summary=f"Scheduler reason={selection.reason} pending={len(original_tasks)} executable_tests={len(executable_tests)} executable_preparation={len(executable_preparation)}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason={
                "selection_reason": selection.reason,
                "deferred_classes": list(selection.deferred_classes or []),
                "skipped_task_ids": list(selection.skipped_task_ids or [])[:12],
                "stop_reason": selection.reason if selection.selected_task_id is None else None,
                "blocked_by_reason": blocked_by_reason,
            },
            counters={
                "pending_count": len(original_tasks),
                "runnable_count": len(executable_tests) + len(executable_preparation),
                "executable_test_task_count": len(executable_tests),
                "executable_preparation_task_count": len(executable_preparation),
                "skipped_count": len(selection.skipped_task_ids or []),
                "blocked_count": blocked_count,
                "waiting_for_preparation_count": waiting_for_preparation_count,
                "deduped_count": deduped_count,
                "exploration_budget_used": int(state.exploration_budget_used or 0),
                "deepening_budget_used": int(state.deepening_budget_used or 0),
                "preparation_budget_used": int(state.preparation_budget_used or 0),
            },
            extra={
                "selected_task_id": selection.selected_task_id,
                "selected_class": selection.selected_class,
                "last_executed_class": state.last_executed_class,
                "consecutive_class_count": int(state.consecutive_class_count or 0),
                "endpoint_family_attempts": dict(state.endpoint_family_attempts or {}),
                "strategy_retry_counts": dict(state.strategy_retry_counts or {}),
                "root_followup_counts": dict(state.root_followup_counts or {}),
                "top_non_executable_tasks": self._top_non_executable_tasks(cleaned_tasks, decisions),
            },
        )

    def _log_queue_update(
        self,
        *,
        active_task: TaskModel,
        scheduler_state: SchedulerState,
        verdict: str,
        evidence: dict,
        queue_update_reason: str,
        pending_before: int,
        pending_after: int,
        followup_tasks: list[TaskModel],
        removed_task: bool,
    ) -> None:
        summary = evidence.get("response_summary") or {}
        finding_type = str(summary.get("finding_type_hint") or summary.get("auth_finding_type") or evidence.get("classification_hint") or "").strip()
        trace_context = self.diagnostics.trace_context(
            run_id=scheduler_state.run_id,
            root_trace_id=scheduler_state.root_trace_id,
            task=active_task,
        )
        self.diagnostics.emit(
            event_type="queue_update_processed",
            component="queue_update",
            status="ok",
            summary=f"Queue update reason={queue_update_reason} verdict={verdict} followups={len(followup_tasks)}.",
            run_id=scheduler_state.run_id,
            trace_context=trace_context,
            reason={
                "verdict": verdict,
                "queue_update_reason": queue_update_reason,
                "finding_type_hint": finding_type,
                "evidence_strength": str(summary.get("evidence_strength") or ""),
                "failure_reason": str(summary.get("failure_reason") or ""),
            },
            counters={
                "pending_before": pending_before,
                "pending_after": pending_after,
                "followup_count": len(followup_tasks),
            },
            artifacts={
                "followup_task_ids": [task.id for task in followup_tasks],
                "generated_followup_task_ids": [task.id for task in followup_tasks],
            },
            extra={
                "removed_task": removed_task,
                "removed_siblings": removed_task and pending_after < pending_before,
            },
        )

    def _log_judge_input_handoff(
        self,
        *,
        active_task: TaskModel,
        scheduler_state: SchedulerState,
        evidence: dict,
    ) -> None:
        summary = evidence.get("response_summary") if isinstance(evidence.get("response_summary"), dict) else {}
        signals = evidence.get("signals") if isinstance(evidence.get("signals"), list) else []
        if not signals:
            signals = summary.get("signals") if isinstance(summary.get("signals"), list) else []
        strong = evidence.get("strong_indicators") if isinstance(evidence.get("strong_indicators"), list) else []
        if not strong:
            strong = summary.get("strong_indicators") if isinstance(summary.get("strong_indicators"), list) else []
        indicators = evidence.get("indicators") if isinstance(evidence.get("indicators"), list) else []
        if not indicators:
            indicators = summary.get("indicators") if isinstance(summary.get("indicators"), list) else []
        tool_summary = evidence.get("tool_summary") if isinstance(evidence.get("tool_summary"), dict) else {}
        if not tool_summary:
            tool_summary = summary.get("tool_summary") if isinstance(summary.get("tool_summary"), dict) else {}
        tool_name = str(evidence.get("tool_name") or summary.get("tool_name") or "").strip()
        evidence_strength = str(summary.get("evidence_strength") or evidence.get("evidence_strength") or "").strip()
        wrapper_evidence_present = bool(
            str(evidence.get("schema_version") or "").startswith("judge-ready-evidence/")
            or tool_name.startswith(("schemathesis_", "restler_", "akto_", "cats_", "astf_"))
            or evidence_strength in {"sufficient_indicators", "generic_wrapper_output"}
        )
        missing_fields = []
        if wrapper_evidence_present:
            for field_name, value in {
                "signals": signals,
                "strong_indicators": strong,
                "tool_summary": tool_summary,
                "classification_hint": evidence.get("classification_hint") or summary.get("classification_hint") or summary.get("finding_type_hint"),
            }.items():
                if not value:
                    missing_fields.append(field_name)
        trace_context = self.diagnostics.trace_context(
            run_id=scheduler_state.run_id,
            root_trace_id=scheduler_state.root_trace_id,
            task=active_task,
        )
        self.diagnostics.emit(
            event_type="judge_input_source_selected",
            component="judge_handoff",
            status="ok",
            summary="Selected evidence source for judge handoff.",
            run_id=scheduler_state.run_id,
            trace_context=trace_context,
            reason={
                "source": "wrapper" if wrapper_evidence_present else "legacy",
                "legacy_overwrite_detected": False,
            },
            artifacts={
                "tool_name": tool_name,
                "wrapper_evidence_present": wrapper_evidence_present,
            },
        )
        self.diagnostics.emit(
            event_type="judge_input_built",
            component="judge_handoff",
            status="ok",
            summary="Built judge input for queue update.",
            run_id=scheduler_state.run_id,
            trace_context=trace_context,
            counters={
                "signals_count": len(signals),
                "strong_indicators_count": len(strong),
                "indicators_count": len(indicators),
            },
            artifacts={
                "tool_name": tool_name,
                "classification_hint": evidence.get("classification_hint") or summary.get("classification_hint") or summary.get("finding_type_hint"),
                "tool_summary_present": bool(tool_summary),
                "evidence_strength": summary.get("evidence_strength"),
            },
        )
        wrapper_event_type = "judge_input_wrapper_fields_not_applicable"
        wrapper_status = "ok"
        if wrapper_evidence_present:
            wrapper_event_type = "judge_input_wrapper_fields_present" if not missing_fields else "judge_input_wrapper_fields_missing"
            wrapper_status = "ok" if not missing_fields else "partial"
        self.diagnostics.emit(
            event_type=wrapper_event_type,
            component="judge_handoff",
            status=wrapper_status,
            summary="Checked wrapper fields in judge input.",
            run_id=scheduler_state.run_id,
            trace_context=trace_context,
            reason={"missing_fields": missing_fields},
            artifacts={
                "tool_name": tool_name,
                "signals_count": len(signals),
                "strong_indicators_count": len(strong),
                "tool_summary_present": bool(tool_summary),
                "legacy_overwrite_detected": False,
                "wrapper_evidence_present": wrapper_evidence_present,
            },
        )

    def _log_judge_verdict(
        self,
        *,
        active_task: TaskModel,
        scheduler_state: SchedulerState,
        verdict: str,
        evidence: dict,
        rework_hint: str | None,
    ) -> None:
        summary = evidence.get("response_summary") or {}
        trace_context = self.diagnostics.trace_context(
            run_id=scheduler_state.run_id,
            root_trace_id=scheduler_state.root_trace_id,
            task=active_task,
        )
        self.diagnostics.emit(
            event_type="judge_verdict_finalized",
            component="judge",
            status="success",
            summary=f"Final verdict={verdict} for task {active_task.id}.",
            run_id=scheduler_state.run_id,
            trace_context=trace_context,
            reason={
                "final_verdict": verdict,
                "classification": str(
                    summary.get("finding_type_hint")
                    or summary.get("auth_finding_type")
                    or evidence.get("classification_hint")
                    or ""
                ),
                "signal_strength": str(summary.get("evidence_strength") or ""),
                "judge_reason": str(evidence.get("reason") or ""),
            },
            artifacts={
                "rework_hint": rework_hint,
                "indicators": list((evidence.get("indicators") or [])[:8]),
            },
        )

    def _log_run_stop(
        self,
        *,
        original_tasks: list[TaskModel],
        cleaned_tasks: list[TaskModel],
        executable_tests: list[TaskModel],
        executable_preparation: list[TaskModel],
        decisions: dict[str, ExecutabilityDecision],
        state: SchedulerState,
        selection: SchedulerSelection,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=state.run_id,
            root_trace_id=state.root_trace_id,
            extra={"trace_id": state.root_trace_id or state.run_id},
        )
        strongest_candidates = []
        for task in sorted((executable_tests or executable_preparation), key=lambda item: float(item.evidence_feasibility or 0), reverse=True)[:5]:
            strongest_candidates.append(
                {
                    "id": task.id,
                    "endpoint": task.endpoint,
                    "class": task.class_name,
                    "subtype": task.subtype,
                    "readiness": task.readiness,
                    "test_strategy": task.test_strategy,
                }
            )
        blocked_count = sum(1 for decision in decisions.values() if not decision.executable)
        waiting_for_preparation_count = len(executable_preparation)
        blocked_by_reason = self._blocked_by_reason(decisions)
        self.diagnostics.emit(
            event_type="scheduler_stop_diagnostics",
            component="scheduler",
            status="stop",
            summary=f"Run stopped because scheduler returned {selection.reason}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason={"stop_reason": selection.reason, "blocked_by_reason": blocked_by_reason},
            counters={
                "pending_count": len(original_tasks),
                "runnable_count": len(executable_tests) + len(executable_preparation),
                "executable_test_task_count": len(executable_tests),
                "executable_preparation_task_count": len(executable_preparation),
                "blocked_count": blocked_count,
                "waiting_for_preparation_count": waiting_for_preparation_count,
                "exploration_budget_used": int(state.exploration_budget_used or 0),
                "deepening_budget_used": int(state.deepening_budget_used or 0),
                "preparation_budget_used": int(state.preparation_budget_used or 0),
                "total_followups_generated": sum(int(value or 0) for value in (state.root_followup_counts or {}).values()),
            },
            artifacts={
                "strongest_unconfirmed_candidates": strongest_candidates,
                "top_non_executable_tasks": self._top_non_executable_tasks(cleaned_tasks, decisions),
            },
        )
        self.diagnostics.emit(
            event_type="run_stop",
            component="scheduler",
            status="stop",
            summary=f"Run stopped because scheduler returned {selection.reason}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason={"stop_reason": selection.reason, "blocked_by_reason": blocked_by_reason},
            counters={
                "pending_count": len(original_tasks),
                "runnable_count": len(executable_tests) + len(executable_preparation),
                "blocked_count": blocked_count,
                "waiting_for_preparation_count": waiting_for_preparation_count,
                "executable_test_task_count": len(executable_tests),
                "executable_preparation_task_count": len(executable_preparation),
                "exploration_budget_used": int(state.exploration_budget_used or 0),
                "deepening_budget_used": int(state.deepening_budget_used or 0),
                "preparation_budget_used": int(state.preparation_budget_used or 0),
                "total_followups_generated": sum(int(value or 0) for value in (state.root_followup_counts or {}).values()),
            },
            artifacts={"strongest_unconfirmed_candidates": strongest_candidates, "top_non_executable_tasks": self._top_non_executable_tasks(cleaned_tasks, decisions)},
        )

    def _log_task_executability(
        self,
        *,
        task: TaskModel,
        state: SchedulerState,
        decision: ExecutabilityDecision,
    ) -> None:
        trace_context = self.diagnostics.trace_context(
            run_id=state.run_id,
            root_trace_id=state.root_trace_id,
            task=task,
        )
        payload_reason = {
            "execution_mode": decision.execution_mode,
            "block_reason": decision.block_reason,
            "missing_prerequisites": list(decision.missing_prerequisites or []),
            "blocking_reason": decision.block_reason,
        }
        payload_counters = {
            "available_object_ids_count": int(decision.available_object_ids_count or 0),
            "creator_candidate_count": int(decision.creator_candidate_count or 0),
            "list_candidate_count": int(decision.list_candidate_count or 0),
            "baseline_valid": decision.baseline_valid,
            "success_path_feasibility": float(decision.success_path_feasibility or 0.0),
            "missing_object_id": "object_id_missing" in (decision.missing_prerequisites or []),
        }
        payload_artifacts = {
            "preferred_tool": decision.preferred_tool,
            "preferred_strategy": decision.preferred_strategy,
            "next_best_followup_strategies": list(decision.next_best_followup_strategies or []),
            "auth_context_available": decision.auth_context_available,
            "resolved_object_id": decision.resolved_object_id,
        }
        is_preparation_task = str(task.readiness or "").lower() == "needs_preparation" or str(task.test_strategy or "").lower() in {
            "create_object_then_replay",
            "list_then_select_object_then_replay",
            "provision_then_replay",
            "prepare_workflow_state_then_retry",
        }
        self.diagnostics.emit(
            event_type="task_executability_evaluated",
            component="scheduler",
            status="ok" if decision.executable else "blocked",
            summary=f"Executability evaluated for task {task.id}: mode={decision.execution_mode}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason=payload_reason,
            counters=payload_counters,
            artifacts=payload_artifacts,
            extra={
                "readiness": task.readiness,
                "is_preparation_task": is_preparation_task,
                "allowed_without_object_id": is_preparation_task and "object_id_missing" in (decision.missing_prerequisites or []),
            },
        )
        self.diagnostics.emit(
            event_type="executability_resolved",
            component="scheduler",
            status="ok" if decision.executable else "blocked",
            summary=f"Resolved executability for task {task.id}.",
            run_id=state.run_id,
            trace_context=trace_context,
            reason=payload_reason,
            counters=payload_counters,
            artifacts=payload_artifacts,
            extra={
                "readiness": task.readiness,
                "selected_strategy": task.test_strategy,
                "selected_object_id": decision.resolved_object_id,
                "selected_role": task.auth_context.owner_role,
                "is_preparation_task": is_preparation_task,
                "allowed_without_object_id": is_preparation_task and "object_id_missing" in (decision.missing_prerequisites or []),
            },
        )
        if not decision.executable:
            self.diagnostics.emit(
                event_type="task_blocked_by_prerequisite",
                component="scheduler",
                status="blocked",
                summary=f"Task {task.id} blocked by prerequisite {decision.block_reason}.",
                run_id=state.run_id,
                trace_context=trace_context,
                reason=payload_reason,
                counters=payload_counters,
                artifacts=payload_artifacts,
                extra={"readiness": task.readiness},
            )
