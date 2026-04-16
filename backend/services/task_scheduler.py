try:
    from backend.models.scheduling import (
        FairnessConfig,
        NextTaskResponse,
        QueueUpdateResponse,
        SchedulerSelection,
        SchedulerState,
    )
    from backend.models.testing import TaskModel
    from backend.services.task_fingerprint import TaskFingerprintService
except ModuleNotFoundError:  # pragma: no cover
    from models.scheduling import (
        FairnessConfig,
        NextTaskResponse,
        QueueUpdateResponse,
        SchedulerSelection,
        SchedulerState,
    )
    from models.testing import TaskModel
    from services.task_fingerprint import TaskFingerprintService


class TaskScheduler:
    def __init__(self) -> None:
        self.fingerprints = TaskFingerprintService()

    def select_next_task(
        self,
        tasks: list[TaskModel],
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
    ) -> NextTaskResponse:
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        runnable_tasks = self._semantic_cleanup(tasks, scheduler_state)
        selection = self.schedule(runnable_tasks, scheduler_state, fairness_config)

        if selection.selected_task_id is None:
            return NextTaskResponse(
                next_task=None,
                remaining_tasks=[],
                scheduler_state=scheduler_state,
                selection_reason=selection.reason,
                deferred_classes=selection.deferred_classes,
                skipped_task_ids=selection.skipped_task_ids,
                should_stop=True,
            )

        selected_task = next((task for task in runnable_tasks if task.id == selection.selected_task_id), None)
        if selected_task is None:
            return NextTaskResponse(
                next_task=None,
                remaining_tasks=[],
                scheduler_state=scheduler_state,
                selection_reason="selected_task_not_found",
                deferred_classes=selection.deferred_classes,
                skipped_task_ids=selection.skipped_task_ids,
                should_stop=True,
            )

        selected_fingerprint = self.fingerprints.task_fingerprint(selected_task)
        selected_finding_fingerprint = self.fingerprints.finding_fingerprint(selected_task, "confirmed")
        remaining_tasks = [
            task
            for task in runnable_tasks
            if task.id != selected_task.id
            and self.fingerprints.task_fingerprint(task) != selected_fingerprint
            and self.fingerprints.finding_fingerprint(task, "confirmed") != selected_finding_fingerprint
        ]
        ordered_remaining, _ = self.order_queue(
            remaining_tasks,
            state=selection.updated_state,
            fairness=fairness_config,
        )
        return NextTaskResponse(
            next_task=selected_task,
            remaining_tasks=ordered_remaining,
            scheduler_state=selection.updated_state,
            selection_reason=selection.reason,
            deferred_classes=selection.deferred_classes,
            skipped_task_ids=selection.skipped_task_ids,
            should_stop=False,
        )

    def update_queue_after_verdict(
        self,
        tasks: list[TaskModel],
        active_task: TaskModel | None,
        verdict: str,
        rework_hint: str | None,
        max_retries: int,
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
    ) -> QueueUpdateResponse:
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        pending = self._semantic_cleanup(tasks, scheduler_state)
        normalized_verdict = str(verdict or "rejected").lower()

        if active_task is None:
            ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
            return QueueUpdateResponse(
                pending_tasks=ordered_pending,
                scheduler_state=scheduler_state,
                queue_update_reason="no_active_task_to_update",
                requeued_task_id=None,
                should_stop=len(ordered_pending) == 0,
            )
        if active_task.id == "__no_task__":
            ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
            return QueueUpdateResponse(
                pending_tasks=ordered_pending,
                scheduler_state=scheduler_state,
                queue_update_reason="noop_active_task",
                requeued_task_id=None,
                should_stop=len(ordered_pending) == 0,
            )

        task_fingerprint = self.fingerprints.task_fingerprint(active_task)
        finding_fingerprint = self.fingerprints.finding_fingerprint(active_task, normalized_verdict)

        if normalized_verdict == "confirmed":
            scheduler_state = self._record_completed_fingerprint(scheduler_state, task_fingerprint)
            scheduler_state = self._record_confirmed_fingerprint(scheduler_state, finding_fingerprint)
            pending = self._drop_equivalent_tasks(pending, task_fingerprint, finding_fingerprint)
            ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
            return QueueUpdateResponse(
                pending_tasks=ordered_pending,
                scheduler_state=scheduler_state,
                queue_update_reason="verdict_confirmed",
                requeued_task_id=None,
                should_stop=len(ordered_pending) == 0,
            )

        if normalized_verdict == "rework":
            updated_task = active_task.model_copy(deep=True)
            updated_task.retry_count = int(updated_task.retry_count or 0) + 1
            updated_task.rework_hint = rework_hint
            if updated_task.retry_count <= int(max_retries or 0):
                updated_task.status = "pending"
                pending.append(updated_task)
                pending = self._semantic_cleanup(pending, scheduler_state)
                ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
                return QueueUpdateResponse(
                    pending_tasks=ordered_pending,
                    scheduler_state=scheduler_state,
                    queue_update_reason="requeued_rework_task",
                    requeued_task_id=updated_task.id,
                    should_stop=len(ordered_pending) == 0,
                )
            ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
            return QueueUpdateResponse(
                pending_tasks=ordered_pending,
                scheduler_state=scheduler_state,
                queue_update_reason="rework_retry_limit_exceeded",
                requeued_task_id=None,
                should_stop=len(ordered_pending) == 0,
            )

        scheduler_state = self._record_completed_fingerprint(scheduler_state, task_fingerprint)
        pending = self._drop_equivalent_tasks(pending, task_fingerprint, None)
        ordered_pending, _ = self.order_queue(pending, scheduler_state, fairness_config)
        return QueueUpdateResponse(
            pending_tasks=ordered_pending,
            scheduler_state=scheduler_state,
            queue_update_reason=f"verdict_{normalized_verdict}",
            requeued_task_id=None,
            should_stop=len(ordered_pending) == 0,
        )

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

        for task in ordered_tasks:
            task_class = str(task.class_name or "").lower()
            if not self._is_class_budget_available(task_class, scheduler_state, fairness_config):
                deferred_classes.append(task_class)
                skipped_task_ids.append(task.id)
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

        fallback_task = ordered_tasks[0]
        updated_state = self._advance_state(fallback_task, scheduler_state)
        return SchedulerSelection(
            selected_task_id=fallback_task.id,
            selected_class=str(fallback_task.class_name or "").lower(),
            reason="fallback_single_class_or_all_classes_exhausted",
            deferred_classes=sorted(set(deferred_classes)),
            skipped_task_ids=skipped_task_ids,
            updated_state=updated_state,
        )

    def order_queue(
        self,
        tasks: list[TaskModel],
        state: SchedulerState | None = None,
        fairness: FairnessConfig | None = None,
    ) -> tuple[list[TaskModel], SchedulerState]:
        remaining = self._semantic_cleanup(tasks, state or SchedulerState())
        scheduler_state = state or SchedulerState()
        fairness_config = fairness or FairnessConfig()
        ordered: list[TaskModel] = []

        while remaining:
            selection = self.schedule(remaining, scheduler_state, fairness_config)
            if selection.selected_task_id is None:
                break
            selected = next((task for task in remaining if task.id == selection.selected_task_id), None)
            if selected is None:
                break
            ordered.append(selected)
            remaining = [task for task in remaining if task.id != selected.id]
            scheduler_state = selection.updated_state

        ordered.extend(sorted(remaining, key=lambda item: int(item.priority or 0), reverse=True))
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
        return SchedulerState(
            class_budget_used=dict(state.class_budget_used),
            class_tasks_completed=dict(state.class_tasks_completed),
            class_retries_used=dict(state.class_retries_used),
            consecutive_class_count=state.consecutive_class_count,
            last_executed_class=state.last_executed_class,
            completed_task_fingerprints=completed,
            confirmed_finding_fingerprints=list(state.confirmed_finding_fingerprints or []),
        )

    def _record_confirmed_fingerprint(self, state: SchedulerState, fingerprint: str) -> SchedulerState:
        confirmed = list(state.confirmed_finding_fingerprints or [])
        if fingerprint and fingerprint not in confirmed:
            confirmed.append(fingerprint)
        return SchedulerState(
            class_budget_used=dict(state.class_budget_used),
            class_tasks_completed=dict(state.class_tasks_completed),
            class_retries_used=dict(state.class_retries_used),
            consecutive_class_count=state.consecutive_class_count,
            last_executed_class=state.last_executed_class,
            completed_task_fingerprints=list(state.completed_task_fingerprints or []),
            confirmed_finding_fingerprints=confirmed,
        )

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

    def _advance_state(self, task: TaskModel, state: SchedulerState) -> SchedulerState:
        task_class = str(task.class_name or "").lower()
        budget_used = dict(state.class_budget_used)
        tasks_completed = dict(state.class_tasks_completed)
        retries_used = dict(state.class_retries_used)

        budget_used[task_class] = int(budget_used.get(task_class, 0) or 0) + 1
        tasks_completed[task_class] = int(tasks_completed.get(task_class, 0) or 0) + 1
        if int(task.retry_count or 0) > 0:
            retries_used[task_class] = int(retries_used.get(task_class, 0) or 0) + 1

        consecutive_count = 1
        if state.last_executed_class == task_class:
            consecutive_count = int(state.consecutive_class_count or 0) + 1

        return SchedulerState(
            class_budget_used=budget_used,
            class_tasks_completed=tasks_completed,
            class_retries_used=retries_used,
            consecutive_class_count=consecutive_count,
            last_executed_class=task_class,
        )
