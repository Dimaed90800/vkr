import logging

try:
    from backend.models.planning import (
        PlannerMetadata,
        PlannerStats,
        TaskPlanningRequest,
        TaskPlanningResponse,
        fresh_runtime_scheduler_state,
    )
    from backend.models.synthesized_context import SynthesizedSecurityContext
    from backend.services.capability_inference_service import CapabilityInferenceService
    from backend.services.diagnostic_logging_service import DiagnosticLoggingService
    from backend.services.task_scheduler import TaskScheduler
    from backend.services.task_generator import TaskGenerator
    from backend.models.testing import TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.planning import (
        PlannerMetadata,
        PlannerStats,
        TaskPlanningRequest,
        TaskPlanningResponse,
        fresh_runtime_scheduler_state,
    )
    from models.synthesized_context import SynthesizedSecurityContext
    from services.capability_inference_service import CapabilityInferenceService
    from services.diagnostic_logging_service import DiagnosticLoggingService
    from services.task_scheduler import TaskScheduler
    from services.task_generator import TaskGenerator
    from models.testing import TaskModel

logger = logging.getLogger(__name__)


class TaskPlanner:
    def __init__(self) -> None:
        self.scheduler = TaskScheduler()
        self.task_generator = TaskGenerator()
        self.capability_inference = CapabilityInferenceService()
        self.diagnostics = DiagnosticLoggingService()

    def plan(self, request: TaskPlanningRequest) -> TaskPlanningResponse:
        capabilities = self.capability_inference.infer(
            execution_context=request.execution_context,
            normalized_surface=request.normalized_surface,
        )
        if request.execution_context is not None:
            request.execution_context = request.execution_context.model_copy(
                update={"capabilities": capabilities},
            )
        generated_tasks = self._materialize_tasks(request)
        raw_generated_total = len(generated_tasks)
        normalized_tasks, filtered_duplicates, filtered_inactive, filtered_requires_enrichment = self._prepare_tasks(generated_tasks)
        ordered_tasks, planner_order_state = self.scheduler.order_queue(
            normalized_tasks,
            state=request.scheduler_state,
            fairness=request.fairness_config,
        )
        runtime_scheduler_state = fresh_runtime_scheduler_state()
        first_selection = self.scheduler.schedule(
            normalized_tasks,
            state=request.scheduler_state,
            fairness=request.fairness_config,
        )
        run_id = getattr(request.execution_context, "run_id", None) if request.execution_context else None
        root_trace_id = getattr(request.execution_context, "root_trace_id", None) if request.execution_context else None
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
            capabilities=capabilities,
            synthesized_context_present=request.synthesized_security_context is not None,
        )

        if request.routing_mode == "llm_only":
            metadata.notes.append("Backend planner skipped final queue generation; LLM Router should build tasks.")
            self._emit_plan_event(
                run_id=run_id,
                root_trace_id=root_trace_id,
                request=request,
                generated_total=raw_generated_total,
                normalized_tasks=normalized_tasks,
                final_queue=[],
                filtered_duplicates=filtered_duplicates,
                filtered_inactive=filtered_inactive,
                filtered_requires_enrichment=filtered_requires_enrichment,
                capabilities=capabilities,
                scheduling_reason=first_selection.reason,
                notes=list(metadata.notes),
            )
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
                synthesized_security_context=request.synthesized_security_context,
                generated_tasks=normalized_tasks,
                scheduler_state=runtime_scheduler_state,
                raw_metadata=self._raw_metadata(request, planner_order_state),
            )

        final_queue = self._apply_budget_limit(ordered_tasks, request)
        router_queue = list(final_queue) if request.routing_mode == "hybrid" else []

        if request.routing_mode == "backend_only":
            metadata.notes.append("Final task queue comes directly from backend-generated tasks.")
            if request.synthesized_security_context is not None:
                metadata.notes.append("Planner used synthesized security context as advisory hints.")
            planner_summary = (
                f"Generated {raw_generated_total} candidate tasks from normalized API surface. "
                f"Returned {len(final_queue)} tasks using backend_only mode."
            )
        else:
            metadata.notes.append("Backend produced the base queue; LLM Router may reprioritize or annotate it.")
            if request.synthesized_security_context is not None:
                metadata.notes.append("Synthesized security context was applied as planner hints before routing.")
            planner_summary = (
                f"Generated {raw_generated_total} candidate tasks from normalized API surface. "
                f"Prepared {len(router_queue)} router candidates in hybrid mode."
            )

        self._emit_plan_event(
            run_id=run_id,
            root_trace_id=root_trace_id,
            request=request,
            generated_total=raw_generated_total,
            normalized_tasks=normalized_tasks,
            final_queue=final_queue,
            filtered_duplicates=filtered_duplicates,
            filtered_inactive=filtered_inactive,
            filtered_requires_enrichment=filtered_requires_enrichment,
            capabilities=capabilities,
            scheduling_reason=first_selection.reason,
            notes=list(metadata.notes),
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
            synthesized_security_context=request.synthesized_security_context,
            generated_tasks=normalized_tasks,
            scheduler_state=runtime_scheduler_state,
            raw_metadata=self._raw_metadata(request, planner_order_state),
        )

    def _materialize_tasks(self, request: TaskPlanningRequest) -> list[TaskModel]:
        tasks = list(request.generated_tasks or [])
        if request.normalized_surface and request.normalized_surface.endpoints:
            generated = self.task_generator.generate(
                request.normalized_surface,
                roles=(request.execution_context.roles if request.execution_context else []),
                capabilities=(request.execution_context.capabilities if request.execution_context else {}),
                synthesized_context=request.synthesized_security_context,
                openapi_spec_text=(request.execution_context.openapi_spec_text if request.execution_context else None),
            )
            tasks.extend(TaskModel.model_validate(item) for item in generated)
        return tasks

    def _raw_metadata(self, request: TaskPlanningRequest, planner_order_state=None) -> dict:
        metadata = {"routing_mode": request.routing_mode}
        if request.synthesized_security_context is not None:
            metadata["synthesized_security_context"] = request.synthesized_security_context.model_dump(mode="json")
        if planner_order_state is not None:
            metadata["planner_order_state"] = planner_order_state.model_dump(mode="json")
        return metadata

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

    def _emit_plan_event(
        self,
        *,
        run_id: str | None,
        root_trace_id: str | None,
        request: TaskPlanningRequest,
        generated_total: int,
        normalized_tasks: list[TaskModel],
        final_queue: list[TaskModel],
        filtered_duplicates: int,
        filtered_inactive: int,
        filtered_requires_enrichment: int,
        capabilities: dict[str, bool],
        scheduling_reason: str,
        notes: list[str],
    ) -> None:
        surface = request.normalized_surface
        endpoints = list(surface.endpoints or []) if surface is not None else []
        class_counts: dict[str, int] = {}
        readiness_counts: dict[str, int] = {}
        for task in normalized_tasks:
            class_counts[task.class_name] = int(class_counts.get(task.class_name, 0) or 0) + 1
            readiness_counts[str(task.readiness or "")] = int(readiness_counts.get(str(task.readiness or ""), 0) or 0) + 1
        top_tasks = [
            {
                "id": task.id,
                "class": task.class_name,
                "subtype": task.subtype,
                "endpoint": task.endpoint,
                "priority": int(task.priority or 0),
                "hypothesis_family": task.hypothesis_family,
                "evidence_feasibility": float(task.evidence_feasibility or 0.0),
                "noise_risk": float(task.noise_risk or 0.0),
                "readiness": task.readiness,
                "worker_role": task.worker_role,
                "preferred_tool": task.preferred_tool,
                "fallback_tools": list(task.fallback_tools or [])[:3],
            }
            for task in normalized_tasks[:8]
        ]
        self.diagnostics.emit(
            event_type="planner_plan_completed",
            component="planner",
            status="ok",
            summary=f"Planner produced {len(final_queue)} runnable tasks from {generated_total} generated candidates.",
            run_id=run_id,
            trace_context={
                "run_id": run_id,
                "root_trace_id": root_trace_id or run_id,
                "trace_id": root_trace_id or run_id,
            },
            counters={
                "total_tasks_generated": generated_total,
                "returned_total": len(final_queue),
                "surface_endpoint_total": len(endpoints),
                "filtered_duplicates": filtered_duplicates,
                "filtered_inactive": filtered_inactive,
                "filtered_requires_enrichment": filtered_requires_enrichment,
            },
            artifacts={
                "top_candidate_tasks": top_tasks,
            },
            extra={
                "capabilities": capabilities,
                "task_counts_by_class": class_counts,
                "task_counts_by_readiness": readiness_counts,
                "planner_notes": notes[:8],
                "scheduling_reason": scheduling_reason,
            },
        )
