from __future__ import annotations

from typing import Any

try:
    from backend.models.tool_wrappers import JudgeReadyEvidence, ToolWrapperResult
    from backend.models.testing import TaskModel
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from models.tool_wrappers import JudgeReadyEvidence, ToolWrapperResult
    from models.testing import TaskModel
    from services.wrapper_observability import append_run_event


class EvidenceBuilderService:
    def from_wrapper_result(
        self,
        *,
        task: TaskModel | None,
        worker_role: str,
        tool_result: ToolWrapperResult,
        run_id: str | None = None,
        notes: list[str] | None = None,
    ) -> JudgeReadyEvidence:
        task_id = task.id if task else tool_result.source_task_id
        append_run_event(
            event_name="evidence_build_start",
            run_id=run_id,
            task_id=task_id,
            worker_role=worker_role,
            tool_name=tool_result.tool_name,
            status="started",
            summary="Building judge-ready evidence from wrapper result.",
            extra={
                "has_wrapper_result": True,
                "wrapper_status": tool_result.status,
            },
        )
        candidate = self._dedupe_candidate_findings(tool_result.candidate_findings)[0] if tool_result.candidate_findings else {}
        evidence = JudgeReadyEvidence(
            task_id=task.id if task else "",
            source_task_id=tool_result.source_task_id or (task.id if task else ""),
            worker_role=worker_role,
            tool_name=tool_result.tool_name,
            auth_context_name=tool_result.auth_context_name,
            hypothesis=task.hypothesis if task else "",
            signals=list(dict.fromkeys(tool_result.signals or [])),
            candidate_finding=candidate,
            reproduction=tool_result.reproduction.model_dump(mode="json"),
            artifacts=tool_result.artifacts.model_dump(mode="json"),
            budget=tool_result.budget.model_dump(mode="json"),
            termination_reason=tool_result.termination_reason,
            notes=list(notes or []),
        )
        append_run_event(
            event_name="evidence_build_finish",
            run_id=run_id,
            task_id=evidence.task_id or evidence.source_task_id,
            worker_role=worker_role,
            tool_name=tool_result.tool_name,
            status="ok",
            summary="Judge-ready wrapper evidence built.",
            counters={
                "signals_count": len(evidence.signals or []),
                "candidate_findings_count": len(tool_result.candidate_findings or []),
            },
            extra={
                "judge_ready": True,
                "used_legacy_path": False,
                "noop_path": tool_result.tool_name == "noop_outcome",
                "signals_count": len(evidence.signals or []),
                "candidate_findings_count": len(tool_result.candidate_findings or []),
            },
        )
        return evidence

    def _dedupe_candidate_findings(self, findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        seen = set()
        result = []
        for item in findings or []:
            key = (
                str(item.get("endpoint") or ""),
                str(item.get("method") or "").upper(),
                str(item.get("vuln_type") or ""),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(item)
        return result
