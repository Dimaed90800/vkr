from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class DiagnosticLoggingService:
    SECRET_KEYS = {
        "authorization",
        "token",
        "access_token",
        "refresh_token",
        "password",
        "passwd",
        "secret",
        "cookie",
        "cookies",
        "set-cookie",
        "auth_headers",
    }
    PREVIEW_LIMIT = 180
    COLLECTION_LIMIT = 12

    def __init__(self, base_dir: str | Path | None = None) -> None:
        root = (
            base_dir
            or os.getenv("DAST_LOG_DIR")
            or os.getenv("DAST_DIAGNOSTIC_LOG_DIR")
            or "logs/dast_runs"
        )
        self.base_dir = Path(root)

    def emit(
        self,
        *,
        event_type: str,
        component: str,
        status: str,
        summary: str,
        run_id: str | None,
        trace_context: dict[str, Any] | None = None,
        reason: dict[str, Any] | None = None,
        counters: dict[str, Any] | None = None,
        artifacts: dict[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        normalized_run_id = self._normalize_run_id(run_id)
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": str(event_type or "").strip(),
            "component": str(component or "").strip(),
            "status": str(status or "").strip(),
            "summary": self._clip(summary),
            "run_id": normalized_run_id,
            "trace_id": self._clip((trace_context or {}).get("trace_id"), 96),
            "task_id": self._clip((trace_context or {}).get("task_id"), 96),
            "trace_context": self._redact(trace_context or {}),
            "reason": self._redact(reason or {}),
            "counters": self._redact(counters or {}),
            "artifacts": self._redact(artifacts or {}),
            "extra": self._redact(extra or {}),
        }
        try:
            self._append_event(normalized_run_id, event)
            self._update_summary(normalized_run_id, event)
        except Exception as exc:  # pragma: no cover
            self._warn_logging_failure(exc, "emit", self.base_dir / normalized_run_id)
        logger.info("diagnostic_event=%s", json.dumps(event, ensure_ascii=False, sort_keys=True))
        return event

    def trace_context(
        self,
        *,
        run_id: str | None = None,
        root_trace_id: str | None = None,
        parent_trace_id: str | None = None,
        task=None,
        execution_context: Mapping[str, Any] | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        execution_context = execution_context or {}
        inferred_run_id = run_id or self._mapping_get(execution_context, "run_id")
        inferred_root_trace = root_trace_id or self._mapping_get(execution_context, "root_trace_id") or inferred_run_id
        endpoint = ""
        method = ""
        class_name = ""
        subtype = ""
        family = ""
        resource_family = ""
        task_id = ""
        strategy = ""
        retry_count = 0
        followup_generation = 0
        if task is not None:
            endpoint = str(getattr(task, "endpoint", "") or "")
            method = str(getattr(task, "method", "") or "")
            class_name = str(getattr(task, "class_name", "") or "")
            subtype = str(getattr(task, "subtype", "") or "")
            family = str(getattr(task, "hypothesis_family", "") or "")
            resource_family = str(getattr(task, "resource_family", "") or "") or str(
                ((getattr(task, "context_hints", {}) or {}).get("resource_family") if isinstance(getattr(task, "context_hints", {}) or {}, dict) else "") or ""
            )
            task_id = str(getattr(task, "id", "") or "")
            strategy = str(getattr(task, "test_strategy", "") or "")
            retry_count = int(getattr(task, "retry_count", 0) or 0)
            followup_generation = int(getattr(task, "followup_generation", 0) or 0)
        payload = {
            "run_id": inferred_run_id,
            "root_trace_id": inferred_root_trace,
            "parent_trace_id": parent_trace_id,
            "task_id": task_id or None,
            "endpoint": endpoint or None,
            "method": method or None,
            "class": class_name or None,
            "subtype": subtype or None,
            "hypothesis_family": family or None,
            "resource_family": resource_family or None,
            "test_strategy": strategy or None,
            "retry_count": retry_count,
            "followup_generation": followup_generation,
        }
        payload["trace_id"] = self._derive_trace_id(payload)
        if extra:
            payload.update(self._redact(extra))
        return payload

    def summarize_http_result(self, result) -> dict[str, Any]:
        if result is None:
            return {}
        body_text = str(getattr(result, "body_text", "") or "")
        headers = getattr(result, "headers", {}) or {}
        return {
            "status_code": getattr(result, "status_code", None),
            "elapsed_ms": getattr(result, "elapsed_ms", None),
            "error": self._clip(getattr(result, "error", None)),
            "body_length": len(body_text),
            "body_preview": self._clip(body_text),
            "header_names": sorted(str(key).lower() for key in headers.keys())[: self.COLLECTION_LIMIT],
        }

    def event_paths(self, run_id: str) -> dict[str, Path]:
        run_dir = self.base_dir / self._normalize_run_id(run_id)
        return {
            "run_dir": run_dir,
            "events": run_dir / "events.jsonl",
            "summary": run_dir / "run_summary.json",
        }

    def _append_event(self, run_id: str, event: dict[str, Any]) -> None:
        paths = self.event_paths(run_id)
        self._ensure_run_dir(paths["run_dir"])
        component_path = paths["run_dir"] / f"{event['component']}_events.jsonl"
        for path in (paths["events"], component_path):
            self._safe_append_jsonl(path, event)

    def _update_summary(self, run_id: str, event: dict[str, Any]) -> None:
        paths = self.event_paths(run_id)
        summary_path = paths["summary"]
        if summary_path.exists():
            try:
                summary = json.loads(summary_path.read_text(encoding="utf-8"))
            except Exception:
                summary = {}
        else:
            summary = {}
        summary.setdefault("run_id", run_id)
        summary.setdefault("event_counts", {})
        summary.setdefault("component_counts", {})
        summary.setdefault("status_counts", {})
        summary.setdefault("top_dead_end_reasons", {})
        summary.setdefault("top_failing_preparation_reasons", {})
        summary.setdefault("tasks_by_class", {})
        summary.setdefault("tasks_by_readiness", {})
        summary.setdefault("blocked_by_reason", {})
        summary.setdefault("executable_test_task_count", 0)
        summary.setdefault("executable_preparation_task_count", 0)
        summary.setdefault("top_non_executable_tasks", [])
        summary.setdefault("_materialization_attempts", 0)
        summary.setdefault("_materialization_successes", 0)
        summary.setdefault("_baseline_validation_total", 0)
        summary.setdefault("_baseline_validation_failures", 0)
        summary["last_event_type"] = event.get("event_type")
        summary["last_status"] = event.get("status")
        summary["last_updated_at"] = event.get("timestamp")

        event_type = str(event.get("event_type") or "")
        component = str(event.get("component") or "")
        status = str(event.get("status") or "")
        summary["event_counts"][event_type] = int(summary["event_counts"].get(event_type, 0) or 0) + 1
        summary["component_counts"][component] = int(summary["component_counts"].get(component, 0) or 0) + 1
        summary["status_counts"][status] = int(summary["status_counts"].get(status, 0) or 0) + 1

        trace_context = event.get("trace_context") or {}
        if trace_context.get("class"):
            key = str(trace_context.get("class"))
            summary["tasks_by_class"][key] = int(summary["tasks_by_class"].get(key, 0) or 0) + 1
        readiness = ((event.get("extra") or {}).get("readiness"))
        if readiness:
            summary["tasks_by_readiness"][str(readiness)] = int(summary["tasks_by_readiness"].get(str(readiness), 0) or 0) + 1

        reason = event.get("reason") or {}
        stop_reason = str(reason.get("stop_reason") or "")
        if stop_reason:
            summary["stop_reason"] = stop_reason
            summary["top_dead_end_reasons"][stop_reason] = int(summary["top_dead_end_reasons"].get(stop_reason, 0) or 0) + 1
        blocked_reasons = reason.get("blocked_by_reason") or {}
        if isinstance(blocked_reasons, Mapping):
            for key, value in blocked_reasons.items():
                normalized = str(key or "").strip()
                if not normalized:
                    continue
                summary["blocked_by_reason"][normalized] = int(summary["blocked_by_reason"].get(normalized, 0) or 0) + int(value or 0)
        failure_reason = str(reason.get("failure_reason") or "")
        if failure_reason:
            summary["top_failing_preparation_reasons"][failure_reason] = int(summary["top_failing_preparation_reasons"].get(failure_reason, 0) or 0) + 1

        counters = event.get("counters") or {}
        for key in (
            "pending_count",
            "runnable_count",
            "blocked_count",
            "total_followups_generated",
            "total_preparation_tasks_generated",
            "total_enriched_tasks",
            "total_harvested_ids",
            "total_materialized_objects",
            "total_tasks_generated",
            "total_tasks_executed",
            "executable_test_task_count",
            "executable_preparation_task_count",
        ):
            if key in counters:
                summary[key] = counters.get(key)
        if "top_non_executable_tasks" in (event.get("artifacts") or {}):
            summary["top_non_executable_tasks"] = (event.get("artifacts") or {}).get("top_non_executable_tasks") or []
        if event_type in {"prep_object_materialization_result", "object_materialization_attempted"}:
            summary["_materialization_attempts"] = int(summary.get("_materialization_attempts", 0) or 0) + 1
        if event_type in {"prep_object_materialization_result", "object_materialization_succeeded"}:
            harvested = int((counters or {}).get("total_materialized_objects") or 0)
            if event_type == "object_materialization_succeeded" or harvested > 0:
                summary["_materialization_successes"] = int(summary.get("_materialization_successes", 0) or 0) + 1
        if event_type == "baseline_validation_result":
            summary["_baseline_validation_total"] = int(summary.get("_baseline_validation_total", 0) or 0) + 1
            if not bool((counters or {}).get("baseline_valid")):
                summary["_baseline_validation_failures"] = int(summary.get("_baseline_validation_failures", 0) or 0) + 1
        attempts = int(summary.get("_materialization_attempts", 0) or 0)
        successes = int(summary.get("_materialization_successes", 0) or 0)
        baseline_total = int(summary.get("_baseline_validation_total", 0) or 0)
        baseline_failures = int(summary.get("_baseline_validation_failures", 0) or 0)
        summary["object_materialization_success_rate"] = round(successes / attempts, 4) if attempts else 0.0
        summary["baseline_validation_failure_rate"] = round(baseline_failures / baseline_total, 4) if baseline_total else 0.0
        self._safe_write_json(summary_path, summary)

    def _ensure_run_dir(self, run_dir: str | Path) -> Path:
        path = Path(run_dir)
        try:
            path.mkdir(parents=True, exist_ok=True)
        except Exception as exc:  # pragma: no cover
            self._warn_logging_failure(exc, "ensure_run_dir", path)
        return path

    def _safe_append_jsonl(self, file_path: str | Path, record: dict[str, Any]) -> None:
        path = Path(file_path)
        try:
            self._ensure_run_dir(path.parent)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        except Exception as exc:  # pragma: no cover
            self._warn_logging_failure(exc, "append_jsonl", path)

    def _safe_write_json(self, file_path: str | Path, record: dict[str, Any]) -> None:
        path = Path(file_path)
        try:
            self._ensure_run_dir(path.parent)
            path.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
        except Exception as exc:  # pragma: no cover
            self._warn_logging_failure(exc, "write_json", path)

    def _warn_logging_failure(self, exc: Exception, operation: str, path: Path) -> None:
        try:
            print(
                f"[diagnostic-logging-warning] operation={operation} path={path} error={exc}",
                file=sys.stderr,
            )
        except Exception:
            pass

    def _derive_trace_id(self, payload: dict[str, Any]) -> str:
        basis = "|".join(
            [
                str(payload.get("run_id") or ""),
                str(payload.get("task_id") or ""),
                str(payload.get("endpoint") or ""),
                str(payload.get("method") or ""),
                str(payload.get("test_strategy") or ""),
                str(payload.get("retry_count") or 0),
                str(payload.get("followup_generation") or 0),
            ]
        )
        return hashlib.sha1(basis.encode("utf-8")).hexdigest()[:16]

    def _normalize_run_id(self, run_id: str | None) -> str:
        value = str(run_id or "").strip()
        if value:
            return value
        return f"run-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    def _mapping_get(self, value: Mapping[str, Any], key: str) -> str | None:
        raw = value.get(key)
        return str(raw).strip() if raw not in (None, "") else None

    def _redact(self, value: Any):
        if isinstance(value, Mapping):
            redacted = {}
            for key, item in value.items():
                lower = str(key).lower()
                if lower in self.SECRET_KEYS:
                    redacted[str(key)] = self._redacted_secret(item)
                else:
                    redacted[str(key)] = self._redact(item)
            return redacted
        if isinstance(value, list):
            return [self._redact(item) for item in value[: self.COLLECTION_LIMIT]]
        if isinstance(value, tuple):
            return [self._redact(item) for item in value[: self.COLLECTION_LIMIT]]
        if isinstance(value, str):
            return self._clip(value)
        return value

    def _redacted_secret(self, value: Any) -> str:
        raw = str(value or "")
        lowered = raw.lower()
        if "bearer " in lowered:
            token = raw.split(" ", 1)[1] if " " in raw else raw
            return f"Bearer {self._truncate_secret(token)}"
        return self._truncate_secret(raw)

    def _truncate_secret(self, value: str) -> str:
        raw = str(value or "")
        if len(raw) <= 10:
            return "***REDACTED***"
        return f"{raw[:6]}...{raw[-4:]}"

    def _clip(self, value: Any, limit: int | None = None) -> str | None:
        if value in (None, ""):
            return None
        text = str(value)
        max_len = int(limit or self.PREVIEW_LIMIT)
        return text if len(text) <= max_len else text[: max_len - 3] + "..."
