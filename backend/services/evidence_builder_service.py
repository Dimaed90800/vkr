from __future__ import annotations

import re
from pathlib import Path
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
        raw_signals = list(dict.fromkeys(tool_result.signals or []))
        schemathesis_enrichment = self._schemathesis_enrichment(task=task, tool_result=tool_result)
        generic_enrichment = self._generic_wrapper_enrichment(task=task, tool_result=tool_result, candidate=candidate)
        if schemathesis_enrichment["is_rate_abuse"]:
            append_run_event(
                event_name="rate_abuse_signal_derivation",
                run_id=run_id,
                task_id=task_id,
                worker_role=worker_role,
                tool_name=tool_result.tool_name,
                status="ok",
                summary="Derived rate-abuse signals from Schemathesis wrapper output.",
                counters={
                    "bounded_burst_count": schemathesis_enrichment["tool_summary"].get("bounded_burst_count", 0),
                    "success_count": schemathesis_enrichment["tool_summary"].get("success_count", 0),
                    "client_error_count": schemathesis_enrichment["tool_summary"].get("client_error_count", 0),
                    "server_error_count": schemathesis_enrichment["tool_summary"].get("server_error_count", 0),
                },
                extra={
                    "derived_signals": schemathesis_enrichment["derived_signals"],
                    "tool_summary": schemathesis_enrichment["tool_summary"],
                },
            )
        signals = list(dict.fromkeys([*raw_signals, *schemathesis_enrichment["derived_signals"], *generic_enrichment["derived_signals"]]))
        notes_out = list(notes or [])
        notes_out.extend(schemathesis_enrichment["notes"])
        notes_out.extend(generic_enrichment["notes"])
        merged_tool_summary = dict(generic_enrichment["tool_summary"] or {})
        if schemathesis_enrichment["tool_summary"]:
            merged_tool_summary.update(schemathesis_enrichment["tool_summary"])
        if candidate and merged_tool_summary:
            candidate = dict(candidate)
            candidate.setdefault("tool_summary", merged_tool_summary)
        strong_indicators = self._strong_security_indicators(signals)
        evidence_strength = self._evidence_strength(
            wrapper_status=tool_result.status,
            derived_signals=schemathesis_enrichment["derived_signals"],
            strong_indicators=strong_indicators,
        )
        classification_hint = self._classification_hint(task=task, signals=signals, strong_indicators=strong_indicators)
        response_summary = {
            "finding_type_hint": classification_hint,
            "evidence_strength": evidence_strength,
            "wrapper_status": tool_result.status,
            "termination_reason": tool_result.termination_reason,
            "tool_name": tool_result.tool_name,
            "signals": signals,
            "derived_signals": list(dict.fromkeys([*schemathesis_enrichment["derived_signals"], *generic_enrichment["derived_signals"]])),
            "strong_indicators": strong_indicators,
            "tool_summary": merged_tool_summary,
        }
        indicators = list(dict.fromkeys([*strong_indicators, *signals]))
        evidence = JudgeReadyEvidence(
            run_id=run_id or "",
            task_id=task.id if task else "",
            source_task_id=tool_result.source_task_id or (task.id if task else ""),
            worker_role=worker_role,
            tool_name=tool_result.tool_name,
            auth_context_name=tool_result.auth_context_name,
            hypothesis=task.hypothesis if task else "",
            signals=signals,
            derived_signals=list(dict.fromkeys([*schemathesis_enrichment["derived_signals"], *generic_enrichment["derived_signals"]])),
            strong_indicators=strong_indicators,
            indicators=indicators,
            classification_hint=classification_hint,
            response_summary=response_summary,
            candidate_finding=candidate,
            tool_summary=merged_tool_summary,
            reproduction=tool_result.reproduction.model_dump(mode="json"),
            artifacts=tool_result.artifacts.model_dump(mode="json"),
            budget=tool_result.budget.model_dump(mode="json"),
            termination_reason=tool_result.termination_reason,
            notes=notes_out,
        )
        append_run_event(
            event_name="evidence_strength_assessed",
            run_id=run_id,
            task_id=evidence.task_id or evidence.source_task_id,
            worker_role=worker_role,
            tool_name=tool_result.tool_name,
            status="ok",
            summary="Assessed judge-ready evidence strength.",
            extra={
                "evidence_strength": evidence_strength,
                "strong_indicators": strong_indicators,
                "signals_count": len(evidence.signals or []),
                "is_rate_abuse": schemathesis_enrichment["is_rate_abuse"],
            },
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
                "derived_signals": list(dict.fromkeys([*schemathesis_enrichment["derived_signals"], *generic_enrichment["derived_signals"]])),
                "evidence_strength": evidence_strength,
                "strong_indicators": strong_indicators,
                "classification_hint": classification_hint,
                "tool_summary": evidence.tool_summary,
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

    def _schemathesis_enrichment(
        self,
        *,
        task: TaskModel | None,
        tool_result: ToolWrapperResult,
    ) -> dict[str, Any]:
        if not str(tool_result.tool_name or "").startswith("schemathesis_"):
            return {"derived_signals": [], "tool_summary": {}, "notes": [], "is_rate_abuse": False}

        text = self._read_tool_text(tool_result)
        status_counts = self._status_counts(text)
        budget_used = int(getattr(tool_result.budget, "used_requests", 0) or 0)
        reproduction = tool_result.reproduction
        operation = {
            "method": (task.method if task else reproduction.method or "").upper(),
            "endpoint": task.endpoint if task else "",
            "url": reproduction.url,
        }
        tool_summary = {
            "tool_name": tool_result.tool_name,
            "operation_count": 1 if (operation["endpoint"] or operation["url"]) else 0,
            "success_count": status_counts["success_count"],
            "client_error_count": status_counts["client_error_count"],
            "server_error_count": status_counts["server_error_count"],
            "saw_429": status_counts["saw_429"],
            "saw_5xx": status_counts["saw_5xx"],
            "rate_limit_response_count": status_counts["rate_limit_response_count"],
            "bounded_burst_count": budget_used,
            "request_count": budget_used,
            "error_count": status_counts["client_error_count"] + status_counts["server_error_count"],
            "operations": [operation] if (operation["endpoint"] or operation["url"]) else [],
        }
        derived: list[str] = []
        raw_signals = set(tool_result.signals or [])
        text_l = text.lower()

        if "schema_violation" in raw_signals or "schema violation" in text_l or "response violates schema" in text_l:
            derived.append("schema_violation")
        if "5xx" in raw_signals or status_counts["saw_5xx"] or "server error" in text_l:
            derived.append("server_error_signal")
        if status_counts["saw_429"] or "too many requests" in text_l:
            derived.append("rate_limit_detected")
        if status_counts["rate_limit_response_count"] >= 2:
            derived.append("repeated_429_detected")

        is_rate_abuse = self._is_rate_abuse_task(task)
        if is_rate_abuse:
            repeated_success = status_counts["success_count"] >= 2
            bounded_burst = budget_used >= 2
            if repeated_success and bounded_burst and not status_counts["saw_429"]:
                derived.extend(["repeated_success_without_throttle", "no_rate_limit_detected"])

        workflow_indicators = {
            "workflow_state_bypass": ["workflow state bypass", "state bypass", "step bypass"],
            "invalid_transition_accepted": ["invalid transition accepted", "invalid state transition accepted"],
            "cross_role_workflow_access": ["cross role workflow access", "cross-role workflow access"],
            "repeated_sensitive_action_allowed": ["repeated sensitive action allowed"],
            "invariant_violation": ["invariant violation"],
        }
        for signal, needles in workflow_indicators.items():
            if any(needle in text_l for needle in needles):
                derived.append(signal)

        derived = list(dict.fromkeys(derived))
        notes = ["schemathesis_evidence_enriched"]
        if not self._strong_security_indicators(derived):
            notes.append("schemathesis_evidence_weak")
        return {"derived_signals": derived, "tool_summary": tool_summary, "notes": notes, "is_rate_abuse": is_rate_abuse}

    def _generic_wrapper_enrichment(
        self,
        *,
        task: TaskModel | None,
        tool_result: ToolWrapperResult,
        candidate: dict[str, Any] | None,
    ) -> dict[str, Any]:
        tool_summary: dict[str, Any] = {}
        derived: list[str] = []
        notes: list[str] = []
        candidate = candidate or {}
        vuln_type = str(candidate.get("vuln_type") or "").strip().lower()
        endpoint = str(candidate.get("endpoint") or (task.endpoint if task else "")).strip()
        method = str(candidate.get("method") or (task.method if task else tool_result.reproduction.method or "")).upper()
        if endpoint or method or vuln_type:
            tool_summary = {
                "tool_name": tool_result.tool_name,
                "candidate_endpoint": endpoint,
                "candidate_method": method,
                "candidate_vuln_type": vuln_type,
                "signals": list(tool_result.signals or []),
            }
        signal_set = {str(item or "").strip() for item in tool_result.signals or [] if str(item or "").strip()}
        class_like = str(task.subtype if task else "").strip().lower()
        if vuln_type in {"generic_access_control", "horizontal_privilege_escalation", "object_authorization", "bola", "vertical_privilege"} or class_like in {"generic_access_control", "bola", "vertical_privilege", "function_level_authorization"}:
            if endpoint and '/all' in endpoint or (task and str(task.endpoint or '').endswith('/vehicles')):
                derived.append("cross_user_collection_access")
            if "authz_runtime_plan_ready" in signal_set:
                derived.append("generic_access_control_exposure")
            if "runtime_inventory_built" in signal_set:
                notes.append("runtime_inventory_context_present")
            if vuln_type in {"horizontal_privilege_escalation", "object_authorization", "bola"}:
                derived.append("cross_user_object_access")
        derived = list(dict.fromkeys(derived))
        return {"derived_signals": derived, "tool_summary": tool_summary, "notes": notes}

    def _read_tool_text(self, tool_result: ToolWrapperResult) -> str:
        chunks: list[str] = []
        for raw_path in (tool_result.artifacts.stdout_path, tool_result.artifacts.stderr_path):
            if not raw_path:
                continue
            path = Path(raw_path)
            try:
                if path.exists() and path.is_file():
                    chunks.append(path.read_text(encoding="utf-8", errors="replace")[:12000])
            except OSError:
                continue
        return "\n".join(chunks)

    def _status_counts(self, text: str) -> dict[str, Any]:
        statuses = [int(match.group(1)) for match in re.finditer(r"(?<!\d)([1-5]\d\d)(?!\d)", text or "")]
        return {
            "success_count": sum(1 for status in statuses if 200 <= status <= 299),
            "client_error_count": sum(1 for status in statuses if 400 <= status <= 499 and status != 429),
            "server_error_count": sum(1 for status in statuses if 500 <= status <= 599),
            "saw_429": any(status == 429 for status in statuses),
            "saw_5xx": any(500 <= status <= 599 for status in statuses),
            "rate_limit_response_count": sum(1 for status in statuses if status == 429),
        }

    def _is_rate_abuse_task(self, task: TaskModel | None) -> bool:
        if task is None:
            return False
        fields = [
            task.class_name,
            task.subtype,
            task.hypothesis,
            task.test_strategy,
            task.strategy_family,
            task.resource_family,
            task.hypothesis_family,
        ]
        text = " ".join(str(item or "").lower() for item in fields)
        return any(needle in text for needle in ("rate", "resource_abuse", "resource abuse", "throttle", "burst"))

    def _strong_security_indicators(self, signals: list[str]) -> list[str]:
        strong = {
            "no_rate_limit_detected",
            "rate_limit_detected",
            "repeated_success_without_throttle",
            "repeated_429_detected",
            "schema_violation",
            "server_error_signal",
            "workflow_state_bypass",
            "invalid_transition_accepted",
            "cross_role_workflow_access",
            "repeated_sensitive_action_allowed",
            "invariant_violation",
            "cross_user_collection_access",
            "cross_user_object_access",
            "high_response_similarity",
            "low_privileged_role_gets_2xx",
            "privileged_function_reached",
            "property_level_authz_gap",
            "generic_access_control_exposure",
        }
        return [signal for signal in signals or [] if signal in strong]

    def _classification_hint(
        self,
        *,
        task: TaskModel | None,
        signals: list[str],
        strong_indicators: list[str],
    ) -> str:
        if task is not None and self._is_rate_abuse_task(task):
            return "unrestricted_resource_consumption"
        signal_set = {str(item or "").strip() for item in [*signals, *strong_indicators] if str(item or "").strip()}
        if signal_set.intersection({"workflow_state_bypass", "invalid_transition_accepted", "cross_role_workflow_access", "repeated_sensitive_action_allowed", "invariant_violation"}):
            return "workflow_abuse"
        if task is not None:
            return str(task.subtype or task.class_name or "").strip()
        return ""

    def _evidence_strength(
        self,
        *,
        wrapper_status: str,
        derived_signals: list[str],
        strong_indicators: list[str],
    ) -> str:
        if wrapper_status == "partial" and not strong_indicators:
            return "partial_weak"
        if strong_indicators:
            return "sufficient_indicators"
        if derived_signals:
            return "derived_weak"
        return "generic_wrapper_output"
