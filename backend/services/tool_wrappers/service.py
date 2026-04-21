from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
import traceback
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from backend.models.tool_wrappers import ToolArtifacts, ToolBudget, ToolReproduction, ToolWrapperRequest, ToolWrapperResult
    from backend.services.wrapper_observability import append_run_event
except ModuleNotFoundError:  # pragma: no cover
    from models.tool_wrappers import ToolArtifacts, ToolBudget, ToolReproduction, ToolWrapperRequest, ToolWrapperResult
    from services.wrapper_observability import append_run_event


TOOL_COMMAND_TO_ENGINE = {
    "restler_compile": "restler",
    "restler_fuzz": "restler",
    "restler_replay": "restler",
    "schemathesis_negative_test": "schemathesis",
    "schemathesis_stateful_test": "schemathesis",
    "cats_fuzz_test": "cats",
    "akto_inventory_discovery": "akto",
    "akto_authz_scan": "akto",
    "astf_top10_suite": "astf",
}

SENSITIVE_HEADER_RE = re.compile(r"(authorization|cookie|token|api[-_]?key|secret)", re.IGNORECASE)
SCHEMATHESIS_TO_SIGNAL = {
    "server error": "5xx",
    "internal server error": "5xx",
    "undocumented http status code": "schema_violation",
    "response violates schema": "schema_violation",
    "schema violation": "schema_violation",
    "negative data rejection": "negative_test_completed",
}
logger = logging.getLogger(__name__)


class ToolWrapperService:
    def __init__(self, base_output_dir: str | None = None) -> None:
        self.base_output_dir = Path(
            base_output_dir
            or os.getenv("DAST_TOOL_OUTPUT_DIR")
            or os.getenv("DAST_LOG_DIR")
            or "backend/exports/tool_runs"
        )

    def execute(self, request: ToolWrapperRequest) -> ToolWrapperResult:
        command = str(request.tool_name or "").strip()
        if command not in TOOL_COMMAND_TO_ENGINE:
            result = self._error_result(request, f"Unsupported wrapper command: {command}")
            self._emit_error_event(request, result.error or result.summary)
            return result
        scope_error = self._scope_error(request)
        if scope_error:
            result = self._error_result(request, scope_error)
            self._emit_error_event(request, result.error or result.summary)
            return result

        run_dir = self._prepare_run_dir(request)
        start = time.monotonic()
        replay_pack_path = run_dir / "replay_pack.json"
        stdout_path = run_dir / "stdout.log"
        stderr_path = run_dir / "stderr.log"

        budget = self._budget_for(request)
        reproduction = self._reproduction_for(request)
        command_preview = self._command_preview(request)
        append_run_event(
            event_name="tool_execution_start",
            run_id=self._run_id(request),
            task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            tool_name=command,
            status="started",
            summary="Tool wrapper execution started.",
            target_url=str(request.target_url or request.execution_context.target_url),
            counters={"max_requests": budget.max_requests},
            artifacts={"artifact_dir": str(run_dir)},
            extra={
                "artifact_dir": str(run_dir),
                "timeout_sec": self._timeout_seconds(request),
                "max_requests": budget.max_requests,
                "target_url": str(request.target_url or request.execution_context.target_url),
                "has_openapi_ref": bool(self._openapi_ref(request)),
            },
        )
        replay_pack = {
            "schema_version": "replay-pack/v1",
            "tool_name": command,
            "engine": TOOL_COMMAND_TO_ENGINE[command],
            "run_id": request.run_id or request.execution_context.run_id,
            "source_task_id": self._source_task_id(request),
            "worker_role": self._worker_role(request),
            "auth_context_name": self._auth_context_name(request),
            "target_url": request.target_url or str(request.execution_context.target_url),
            "openapi_ref": self._openapi_ref(request),
            "allowed_hosts": list(request.execution_context.allowed_hosts or []),
            "task": (request.task.model_dump(by_alias=True, mode="json") if request.task else {}),
            "reproduction": reproduction.model_dump(mode="json"),
            "budget": budget.model_dump(mode="json"),
            "wrapper_command": command_preview,
            "replay": {
                "strategy": "deterministic_tool_replay",
                "cli_command": command_preview,
                "request_template": reproduction.model_dump(mode="json"),
                "notes": [
                    "Schemathesis runs with deterministic generation; rerun cli_command against the same API state to reproduce generated cases.",
                    "Tool stdout/stderr may include the exact minimized failing case when Schemathesis reports one.",
                ],
            },
            "artifact_paths": {
                "run_dir": str(run_dir),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "replay_pack_path": str(replay_pack_path),
            },
        }
        replay_pack_path.write_text(json.dumps(replay_pack, ensure_ascii=False, indent=2), encoding="utf-8")

        try:
            result = self._execute_engine(request, stdout_path=stdout_path, stderr_path=stderr_path)
        except Exception as exc:  # pragma: no cover
            append_run_event(
                event_name="tool_execution_error",
                run_id=self._run_id(request),
                task_id=self._source_task_id(request),
                worker_role=self._worker_role(request),
                tool_name=command,
                status="error",
                summary="Tool wrapper execution raised an exception.",
                reason={"exception_type": type(exc).__name__, "exception_message": str(exc)},
                extra={"traceback_preview": self._preview(traceback.format_exc(), 500)},
            )
            raise
        result.artifacts = ToolArtifacts(
            stdout_path=str(stdout_path),
            stderr_path=str(stderr_path),
            raw_report_paths=result.artifacts.raw_report_paths,
            replay_pack_path=str(replay_pack_path),
        )
        result.source_task_id = self._source_task_id(request)
        result.worker_role = self._worker_role(request)
        result.auth_context_name = self._auth_context_name(request)
        result.reproduction = reproduction
        result.budget = budget.model_copy(
            update={
                "used_requests": int(result.budget.used_requests or budget.used_requests or 0),
                "duration_sec": round(time.monotonic() - start, 3),
                "termination_reason": result.budget.termination_reason or budget.termination_reason,
            }
        )
        result.termination_reason = result.termination_reason or result.budget.termination_reason
        if result.status == "partial" or result.fallback_reason:
            append_run_event(
                event_name="tool_execution_partial",
                run_id=self._run_id(request),
                task_id=self._source_task_id(request),
                worker_role=self._worker_role(request),
                tool_name=command,
                status=result.status,
                summary="Tool wrapper produced a partial result.",
                reason={
                    "termination_reason": result.termination_reason,
                    "fallback_reason": result.fallback_reason,
                },
                extra={
                    "wrapper_status": result.status,
                    "termination_reason": result.termination_reason,
                    "signals": result.signals,
                    "fallback_reason": result.fallback_reason,
                },
            )
        append_run_event(
            event_name="tool_execution_finish",
            run_id=self._run_id(request),
            task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            tool_name=command,
            status=result.status,
            summary="Tool wrapper execution finished.",
            reason={"termination_reason": result.termination_reason, "fallback_reason": result.fallback_reason},
            counters={"used_requests": result.budget.used_requests},
            artifacts={
                "stdout_path": result.artifacts.stdout_path,
                "stderr_path": result.artifacts.stderr_path,
                "raw_report_paths": result.artifacts.raw_report_paths,
                "replay_pack_path": result.artifacts.replay_pack_path,
            },
            extra={
                "wrapper_status": result.status,
                "termination_reason": result.termination_reason,
                "signals": result.signals,
                "used_requests": result.budget.used_requests,
            },
        )
        return result

    def _execute_engine(self, request: ToolWrapperRequest, *, stdout_path: Path, stderr_path: Path) -> ToolWrapperResult:
        engine = TOOL_COMMAND_TO_ENGINE[request.tool_name]
        if engine == "schemathesis":
            return self._run_schemathesis(request, stdout_path=stdout_path, stderr_path=stderr_path)
        return self._stub_result(request, engine=engine, stdout_path=stdout_path, stderr_path=stderr_path)

    def _run_schemathesis(self, request: ToolWrapperRequest, *, stdout_path: Path, stderr_path: Path) -> ToolWrapperResult:
        spec_ref = request.openapi_spec_path or request.openapi_url or request.execution_context.openapi_url
        if not spec_ref:
            return self._stub_result(
                request,
                engine="schemathesis",
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                fallback_reason="schemathesis requires openapi_url or openapi_spec_path",
                termination_reason="missing_openapi",
                extra_signals=["openapi_missing"],
            )

        binary = shutil.which("st") or shutil.which("schemathesis")
        if not binary:
            return self._stub_result(
                request,
                engine="schemathesis",
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                fallback_reason="schemathesis CLI is not installed in this environment",
                termination_reason="tool_unavailable",
                extra_signals=["tool_unavailable"],
            )

        max_examples = self._max_examples(request)
        timeout = self._timeout_seconds(request)
        command = self._schemathesis_command(request, spec_ref=spec_ref, max_examples=max_examples)
        auth_header = self._auth_header(request)
        if auth_header:
            command.extend(["--header", auth_header])
        logger.info(
            "Executing Schemathesis wrapper tool=%s task_id=%s max_examples=%s timeout=%s",
            request.tool_name,
            self._source_task_id(request),
            max_examples,
            timeout,
        )
        command_started = time.monotonic()
        append_run_event(
            event_name="tool_subprocess_start",
            run_id=self._run_id(request),
            task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            tool_name=request.tool_name,
            status="started",
            summary="Starting Schemathesis subprocess.",
            extra={"command": self._redact_command(command), "cwd": None},
        )
        try:
            completed = subprocess.run(
                command,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stdout_path.write_text(self._redact(exc.stdout or ""), encoding="utf-8")
            stderr_path.write_text(self._redact(exc.stderr or "schemathesis timeout"), encoding="utf-8")
            append_run_event(
                event_name="tool_subprocess_completed",
                run_id=self._run_id(request),
                task_id=self._source_task_id(request),
                worker_role=self._worker_role(request),
                tool_name=request.tool_name,
                status="partial",
                summary="Schemathesis subprocess timed out.",
                reason={"termination_reason": "timeout"},
                extra={
                    "returncode": None,
                    "duration_sec": round(time.monotonic() - command_started, 3),
                    "stdout_preview": self._preview(exc.stdout or ""),
                    "stderr_preview": self._preview(exc.stderr or "schemathesis timeout"),
                },
            )
            return ToolWrapperResult(
                tool_name=request.tool_name,
                status="partial",
                summary=f"Schemathesis terminated after {timeout} seconds.",
                signals=["timeout", "budget_exhausted"],
                artifacts=ToolArtifacts(),
                budget=self._budget_for(request).model_copy(update={"termination_reason": "timeout"}),
                termination_reason="timeout",
                error="schemathesis_timeout",
            )

        stdout_path.write_text(self._redact(completed.stdout), encoding="utf-8")
        stderr_path.write_text(self._redact(completed.stderr), encoding="utf-8")
        append_run_event(
            event_name="tool_subprocess_completed",
            run_id=self._run_id(request),
            task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            tool_name=request.tool_name,
            status="ok" if completed.returncode == 0 else "partial",
            summary="Schemathesis subprocess completed.",
            extra={
                "returncode": completed.returncode,
                "duration_sec": round(time.monotonic() - command_started, 3),
                "stdout_preview": self._preview(completed.stdout),
                "stderr_preview": self._preview(completed.stderr),
            },
        )
        signals = self._schemathesis_signals(completed.stdout, completed.stderr, completed.returncode)
        status = "ok" if completed.returncode == 0 else "partial"
        return ToolWrapperResult(
            tool_name=request.tool_name,
            status=status,
            summary=f"Schemathesis finished with exit code {completed.returncode}.",
            signals=signals,
            artifacts=ToolArtifacts(),
            candidate_findings=self._candidate_findings_for(request, signals),
            budget=self._budget_for(request).model_copy(
                update={
                    "used_requests": max_examples,
                    "termination_reason": "completed" if completed.returncode == 0 else "tool_reported_findings",
                }
            ),
            termination_reason="completed" if completed.returncode == 0 else "tool_reported_findings",
            error=None if completed.returncode == 0 else "schemathesis_reported_failures",
        )

    def _schemathesis_command(self, request: ToolWrapperRequest, *, spec_ref: str, max_examples: int) -> list[str]:
        binary = shutil.which("st") or shutil.which("schemathesis") or "schemathesis"
        return [
            binary,
            "--no-color",
            "run",
            str(spec_ref),
            "--url",
            str(request.target_url or request.execution_context.target_url).rstrip("/"),
            "--mode",
            "negative" if request.tool_name == "schemathesis_negative_test" else "all",
            "--max-examples",
            str(max_examples),
            "--generation-deterministic",
            "--continue-on-failure",
        ]

    def _stub_result(
        self,
        request: ToolWrapperRequest,
        *,
        engine: str,
        stdout_path: Path,
        stderr_path: Path,
        fallback_reason: str | None = None,
        termination_reason: str | None = None,
        extra_signals: list[str] | None = None,
    ) -> ToolWrapperResult:
        message = (
            fallback_reason
            or f"{engine} wrapper scaffold is present; CLI/container execution is not wired yet."
        )
        logger.info("Wrapper fallback tool=%s engine=%s reason=%s", request.tool_name, engine, message)
        stdout_path.write_text("", encoding="utf-8")
        stderr_path.write_text(message + "\n", encoding="utf-8")
        signals = ["wrapper_scaffold_ready"]
        for signal in extra_signals or []:
            if signal not in signals:
                signals.append(signal)
        return ToolWrapperResult(
            tool_name=request.tool_name,
            status="partial",
            summary=message,
            signals=signals,
            artifacts=ToolArtifacts(),
            candidate_findings=[],
            fallback_reason=message,
            termination_reason=termination_reason or "scaffold_only",
            error=message if termination_reason in {"tool_unavailable", "missing_openapi"} else None,
        )

    def _candidate_findings_for(self, request: ToolWrapperRequest, signals: list[str]) -> list[dict[str, Any]]:
        if not signals or not request.task:
            return []
        interesting = {"unexpected_2xx", "schema_violation", "5xx", "authz_bypass_candidate", "timeout"}
        if not interesting.intersection(set(signals)):
            return []
        return [
            {
                "task_id": request.task.id,
                "vuln_type": request.task.subtype,
                "endpoint": request.task.endpoint,
                "method": request.task.method.upper(),
                "signals": signals,
                "confidence": 0.45,
                "source_tool": request.tool_name,
                "source_task_id": request.task.id,
            }
        ]

    def _schemathesis_signals(self, stdout: str, stderr: str, returncode: int) -> list[str]:
        text = f"{stdout}\n{stderr}".lower()
        signals = []
        for needle, signal in SCHEMATHESIS_TO_SIGNAL.items():
            if needle in text and signal not in signals:
                signals.append(signal)
        if returncode == 1 and "schema_violation" not in signals:
            signals.append("schema_violation")
        if returncode == 2:
            signals.append("tool_execution_error")
        if "2xx" in text and ("negative" in text or "unauthorized" in text):
            signals.append("unexpected_2xx")
        return signals or ["negative_test_completed"]

    def _prepare_run_dir(self, request: ToolWrapperRequest) -> Path:
        run_id = self._safe_path_segment(str(request.run_id or request.execution_context.run_id or f"run-{uuid.uuid4().hex[:12]}"))
        task_id = self._safe_path_segment(str(getattr(request.task, "id", "") or "no-task"))
        tool_name = self._safe_path_segment(str(request.tool_name or "unknown-tool"))
        root = Path(request.output_dir) if request.output_dir else self.base_output_dir
        run_dir = root / run_id / tool_name / task_id
        run_dir.mkdir(parents=True, exist_ok=True)
        return run_dir

    def _safe_path_segment(self, value: str) -> str:
        return re.sub(r"[^A-Za-z0-9_.-]+", "_", value.strip())[:120] or "unknown"

    def _scope_error(self, request: ToolWrapperRequest) -> str | None:
        allowed_hosts = [str(item or "").strip().lower() for item in (request.execution_context.allowed_hosts or [])]
        allowed_hosts = [item for item in allowed_hosts if item]
        if not allowed_hosts:
            return None
        target = str(request.target_url or request.execution_context.target_url)
        host = urlparse(target).netloc.lower()
        if host not in allowed_hosts:
            return f"Target host '{host}' is outside allowed_hosts"
        return None

    def _run_id(self, request: ToolWrapperRequest) -> str:
        return str(request.run_id or request.execution_context.run_id or "")

    def _budget_for(self, request: ToolWrapperRequest) -> ToolBudget:
        max_requests = int(request.budgets.max_requests or request.execution_context.max_requests or 0)
        max_duration = int(request.budgets.max_duration_sec or request.execution_context.max_duration_sec or 0)
        return ToolBudget(
            max_requests=max_requests,
            used_requests=0,
            duration_sec=0,
            max_duration_sec=max_duration,
            concurrency=max(1, min(int(request.budgets.concurrency or 1), 4)),
        )

    def _max_examples(self, request: ToolWrapperRequest) -> int:
        explicit = int(request.arguments.get("max_examples") or 0)
        budget = int(request.budgets.max_requests or request.execution_context.max_requests or 0)
        value = explicit or budget or 10
        return max(1, min(value, 50))

    def _timeout_seconds(self, request: ToolWrapperRequest) -> int:
        value = int(request.budgets.max_duration_sec or request.execution_context.max_duration_sec or 60)
        return max(5, min(value, 300))

    def _reproduction_for(self, request: ToolWrapperRequest) -> ToolReproduction:
        method = str((request.task.method if request.task else request.arguments.get("method")) or "GET").upper()
        endpoint = str((request.task.endpoint if request.task else request.arguments.get("endpoint")) or "")
        base_url = str(request.target_url or request.execution_context.target_url).rstrip("/")
        url = endpoint if urlparse(endpoint).scheme else urljoin(base_url + "/", endpoint.lstrip("/"))
        headers = request.arguments.get("headers") if isinstance(request.arguments.get("headers"), dict) else {}
        body = request.arguments.get("json_body")
        return ToolReproduction(method=method, url=url, headers=self._redact_headers(headers), body=body)

    def _openapi_ref(self, request: ToolWrapperRequest) -> str:
        return str(request.openapi_spec_path or request.openapi_url or request.execution_context.openapi_url or "")

    def _command_preview(self, request: ToolWrapperRequest) -> list[str]:
        if TOOL_COMMAND_TO_ENGINE.get(request.tool_name) != "schemathesis":
            return [request.tool_name]
        spec_ref = self._openapi_ref(request) or "<missing-openapi-ref>"
        command = self._schemathesis_command(
            request,
            spec_ref=spec_ref,
            max_examples=self._max_examples(request),
        )
        auth_header = self._auth_header(request)
        if auth_header:
            command.extend(["--header", self._redact(auth_header)])
        return command

    def _redact_headers(self, headers: dict[str, Any]) -> dict[str, Any]:
        return {
            str(key): ("<redacted>" if SENSITIVE_HEADER_RE.search(str(key)) else value)
            for key, value in (headers or {}).items()
        }

    def _redact(self, text: str) -> str:
        redacted = re.sub(r"(?i)(authorization|cookie|x-api-key|token|api[-_]?key|secret|session)([=: ]+)(\S+)", r"\1\2<redacted>", text or "")
        return re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer <redacted>", redacted)

    def _redact_command(self, command: list[str]) -> list[str]:
        return [self._redact(str(item)) for item in command]

    def _preview(self, text: Any, limit: int = 300) -> str:
        redacted = self._redact(str(text or ""))
        return redacted if len(redacted) <= limit else redacted[: limit - 3] + "..."

    def _emit_error_event(self, request: ToolWrapperRequest, message: str) -> None:
        append_run_event(
            event_name="tool_execution_error",
            run_id=self._run_id(request),
            task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            tool_name=request.tool_name,
            status="error",
            summary="Tool wrapper request rejected before execution.",
            reason={"exception_type": "ValueError", "exception_message": message},
        )

    def _worker_role(self, request: ToolWrapperRequest) -> str:
        if request.task and request.task.worker_role:
            return request.task.worker_role
        return str(request.task_metadata.get("worker_role") or "")

    def _source_task_id(self, request: ToolWrapperRequest) -> str:
        return str(request.task.id if request.task else request.task_metadata.get("task_id") or "")

    def _auth_context_name(self, request: ToolWrapperRequest) -> str | None:
        explicit = request.arguments.get("auth_context_name") or request.task_metadata.get("auth_context_name")
        if explicit:
            return str(explicit)
        if request.task and request.task.auth_context.owner_role:
            return str(request.task.auth_context.owner_role)
        return None

    def _auth_header(self, request: ToolWrapperRequest) -> str | None:
        headers = request.arguments.get("headers") if isinstance(request.arguments.get("headers"), dict) else {}
        authorization = headers.get("Authorization") or headers.get("authorization")
        if authorization:
            return f"Authorization: {authorization}"
        auth_name = self._auth_context_name(request)
        for role in request.roles_json or request.execution_context.roles or []:
            if not isinstance(role, dict):
                continue
            role_name = str(role.get("name") or role.get("role") or role.get("role_name") or "")
            if auth_name and role_name and role_name != auth_name:
                continue
            role_headers = role.get("auth_headers") or role.get("headers") or {}
            if isinstance(role_headers, dict):
                authorization = role_headers.get("Authorization") or role_headers.get("authorization")
                if authorization:
                    return f"Authorization: {authorization}"
        return None

    def _error_result(self, request: ToolWrapperRequest, message: str) -> ToolWrapperResult:
        return ToolWrapperResult(
            tool_name=request.tool_name,
            source_task_id=self._source_task_id(request),
            worker_role=self._worker_role(request),
            auth_context_name=self._auth_context_name(request),
            status="error",
            summary=message,
            signals=["wrapper_error"],
            termination_reason="wrapper_error",
            error=message,
        )
