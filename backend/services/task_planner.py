try:
    from backend.models.planning import (
        PlannerMetadata,
        PlannerStats,
        TaskPlanningRequest,
        TaskPlanningResponse,
    )
    from backend.services.task_scheduler import TaskScheduler
    from backend.services.task_generator import TaskGenerator
    from backend.models.testing import TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.planning import (
        PlannerMetadata,
        PlannerStats,
        TaskPlanningRequest,
        TaskPlanningResponse,
    )
    from services.task_scheduler import TaskScheduler
    from services.task_generator import TaskGenerator
    from models.testing import TaskModel


class TaskPlanner:
    def __init__(self) -> None:
        self.scheduler = TaskScheduler()
        self.task_generator = TaskGenerator()

    def plan(self, request: TaskPlanningRequest) -> TaskPlanningResponse:
        generated_tasks = self._materialize_tasks(request)
        raw_generated_total = len(generated_tasks)
        normalized_tasks, filtered_duplicates, filtered_inactive, filtered_requires_enrichment = self._prepare_tasks(generated_tasks)
        ordered_tasks, updated_scheduler_state = self.scheduler.order_queue(
            normalized_tasks,
            state=request.scheduler_state,
            fairness=request.fairness_config,
        )
        first_selection = self.scheduler.schedule(
            normalized_tasks,
            state=request.scheduler_state,
            fairness=request.fairness_config,
        )
        target_url = str(request.execution_context.target_url) if request.execution_context else None
        metadata = PlannerMetadata(
            used_backend_generation=request.routing_mode in {"backend_only", "hybrid"},
            llm_router_required=request.routing_mode == "llm_only",
            filtered_duplicates=filtered_duplicates,
            filtered_inactive=filtered_inactive,
            filtered_requires_enrichment=filtered_requires_enrichment,
            target_url=target_url,
            notes=[],
            scheduling_reason=first_selection.reason,
            deferred_classes=first_selection.deferred_classes,
        )

        if request.routing_mode == "llm_only":
            metadata.notes.append("Backend planner skipped final queue generation; LLM Router should build tasks.")
            return TaskPlanningResponse(
                routing_mode=request.routing_mode,
                planner_summary="Routing mode is llm_only. Backend skipped final task queue generation.",
                final_task_queue=[],
                router_candidate_queue=[],
                stats=PlannerStats(
                    generated_total=raw_generated_total,
                    returned_total=0,
                    router_candidate_total=0,
                ),
                metadata=metadata,
                normalized_surface=request.normalized_surface,
                generated_tasks=normalized_tasks,
                scheduler_state=updated_scheduler_state,
                raw_metadata={"routing_mode": request.routing_mode},
            )

        final_queue = self._apply_budget_limit(ordered_tasks, request)
        router_queue = list(final_queue) if request.routing_mode == "hybrid" else []

        if request.routing_mode == "backend_only":
            metadata.notes.append("Final task queue comes directly from backend-generated tasks.")
            planner_summary = (
                f"Generated {raw_generated_total} candidate tasks from normalized API surface. "
                f"Returned {len(final_queue)} tasks using backend_only mode."
            )
        else:
            metadata.notes.append("Backend produced the base queue; LLM Router may reprioritize or annotate it.")
            planner_summary = (
                f"Generated {raw_generated_total} candidate tasks from normalized API surface. "
                f"Prepared {len(router_queue)} router candidates in hybrid mode."
            )

        return TaskPlanningResponse(
            routing_mode=request.routing_mode,
            planner_summary=planner_summary,
            final_task_queue=final_queue,
            router_candidate_queue=router_queue,
            stats=PlannerStats(
                generated_total=raw_generated_total,
                returned_total=len(final_queue),
                router_candidate_total=len(router_queue),
            ),
            metadata=metadata,
            normalized_surface=request.normalized_surface,
            generated_tasks=normalized_tasks,
            scheduler_state=updated_scheduler_state,
            raw_metadata={"routing_mode": request.routing_mode},
        )

    def _materialize_tasks(self, request: TaskPlanningRequest) -> list[TaskModel]:
        tasks = list(request.generated_tasks or [])
        if request.normalized_surface and request.normalized_surface.endpoints:
            generated = self.task_generator.generate(
                request.normalized_surface,
                roles=(request.execution_context.roles if request.execution_context else []),
            )
            tasks.extend(TaskModel.model_validate(item) for item in generated)
        return tasks

    def _prepare_tasks(self, tasks: list[TaskModel]) -> tuple[list[TaskModel], int, int, int]:
        unique: list[TaskModel] = []
        seen: set[tuple[str, str, str, str]] = set()
        filtered_duplicates = 0
        filtered_inactive = 0
        filtered_requires_enrichment = 0

        for task in tasks:
            if str(task.status or "pending").lower() not in {"pending", "queued", "ready"}:
                filtered_inactive += 1
                continue
            if (
                task.class_name == "authorization"
                and task.params.requires_object_id_enrichment
                and task.params.selected_object_id in (None, "")
            ):
                filtered_requires_enrichment += 1
                continue

            key = (
                task.class_name,
                task.endpoint,
                task.method.upper(),
                task.subtype,
            )
            if key in seen:
                filtered_duplicates += 1
                continue
            seen.add(key)
            unique.append(task)

        unique.sort(key=lambda item: int(item.priority or 0), reverse=True)
        return unique, filtered_duplicates, filtered_inactive, filtered_requires_enrichment

    def _apply_budget_limit(self, tasks: list[TaskModel], request: TaskPlanningRequest) -> list[TaskModel]:
        if request.execution_context is None:
            return tasks
        limit = int(request.execution_context.max_requests or 0)
        if limit <= 0:
            return tasks
        return tasks[:limit]
