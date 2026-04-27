"""Phase 16A — Schemathesis negative-test adapter for ToolExecutor (sync).

Runs Schemathesis CLI against campaign-trusted openapi_url only.
Does not create findings, evidence, or judge inputs.
"""
from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
from typing import Any
from urllib.parse import urlparse

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore

logger = logging.getLogger(__name__)

_TAIL_CAP = 2048
_MAX_TIMEOUT_SEC = 300
_MIN_EXAMPLES = 1
_MAX_EXAMPLES = 50

_SCHEMATHESIS_TO_SIGNAL: dict[str, str] = {
    "server error": "5xx",
    "internal server error": "5xx",
    "undocumented http status code": "schema_violation",
    "response violates schema": "schema_violation",
    "schema violation": "schema_violation",
    "negative data rejection": "negative_test_completed",
}


def _tail(text: str, cap: int = _TAIL_CAP) -> str:
    s = str(text or "")
    if len(s) <= cap:
        return s
    return s[-cap:]


def _redact(text: str) -> str:
    s = str(text or "")
    s = re.sub(r"(?i)(authorization:\s*)([^\n]+)", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(bearer\s+)([^\s\n]+)", r"\1[REDACTED]", s)
    s = re.sub(r"(?i)(cookie:\s*)([^\n]+)", r"\1[REDACTED]", s)
    return s


def _signals(stdout: str, stderr: str, returncode: int) -> list[str]:
    text = f"{stdout}\n{stderr}".lower()
    signals: list[str] = []
    for needle, signal in _SCHEMATHESIS_TO_SIGNAL.items():
        if needle in text and signal not in signals:
            signals.append(signal)
    if returncode == 1 and "schema_violation" not in signals:
        signals.append("schema_violation")
    if returncode == 2:
        signals.append("tool_execution_error")
    if "2xx" in text and ("negative" in text or "unauthorized" in text):
        signals.append("unexpected_2xx")
    return signals or ["negative_test_completed"]


def _target_host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "") or ""
    except Exception:
        return ""


class SchemathesisNegativeTestAdapter:
    def __init__(self) -> None:
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs or {}
        openapi_in = str(inputs.get("openapi_url") or "").strip()
        camp_openapi = str(campaign.openapi_url or "").strip()
        target_in = str(inputs.get("target_url") or "").strip()
        camp_target = str(campaign.target_url or "").strip()
        op_id = str(command.operation_id or inputs.get("operation_id") or "").strip()

        if not openapi_in or not camp_openapi or openapi_in != camp_openapi:
            return self._failed(
                command,
                tool_run_id,
                start_ms,
                "invalid_inputs",
                "inputs.openapi_url must exactly match campaign.openapi_url.",
            )
        parsed_o = urlparse(openapi_in)
        if parsed_o.scheme not in ("http", "https"):
            return self._failed(
                command,
                tool_run_id,
                start_ms,
                "invalid_inputs",
                "openapi_url must use http or https.",
            )
        if not target_in or target_in.rstrip("/") != camp_target.rstrip("/"):
            return self._failed(
                command,
                tool_run_id,
                start_ms,
                "invalid_inputs",
                "inputs.target_url must match campaign.target_url.",
            )

        try:
            raw_me = int(str(inputs.get("max_examples") or "5").strip())
        except ValueError:
            raw_me = 5
        max_examples = max(_MIN_EXAMPLES, min(raw_me, _MAX_EXAMPLES))

        timeout_sec = min(
            int(command.budget.timeout_sec or 60),
            int(campaign.limits.max_duration_sec or 1800),
            _MAX_TIMEOUT_SEC,
        )
        if timeout_sec < 1:
            timeout_sec = 1

        binary = shutil.which("st") or shutil.which("schemathesis")
        if not binary:
            return self._failed(
                command,
                tool_run_id,
                start_ms,
                "tool_runtime_missing",
                "Schemathesis CLI (st or schemathesis) is not available in PATH.",
            )

        cmd_list = [
            binary,
            "--no-color",
            "run",
            openapi_in,
            "--url",
            target_in.rstrip("/"),
            "--mode",
            "negative",
            "--max-examples",
            str(max_examples),
            "--generation-deterministic",
            "--continue-on-failure",
        ]

        logger.info(
            "schemathesis_negative_test start campaign=%s op=%s max_examples=%s timeout=%s",
            command.campaign_id,
            op_id,
            max_examples,
            timeout_sec,
        )
        t0 = time.monotonic()
        try:
            proc = subprocess.run(
                cmd_list,
                capture_output=True,
                text=True,
                timeout=float(timeout_sec),
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            duration_ms = int(time.monotonic() * 1000) - start_ms
            out_t = _tail(_redact(exc.stdout or "" if exc.stdout else ""))
            err_t = _tail(_redact(exc.stderr or "timeout"))
            art = self._summary_artifact(
                command,
                tool_run_id,
                exit_code=None,
                signal_types=["timeout"],
                stdout_tail=out_t,
                stderr_tail=err_t,
                operation_id=op_id,
                target_host=_target_host(target_in),
            )
            return ToolResult(
                tool_run_id=tool_run_id,
                campaign_id=command.campaign_id,
                task_id=command.task_id,
                command_id=command.command_id,
                tool_name=command.tool_name,
                status="failed",
                summary=ToolResultSummary(duration_ms=duration_ms),
                artifacts=[art],
                errors=[
                    ToolResultError(
                        error_type="timeout",
                        message=f"Schemathesis exceeded {timeout_sec}s budget.",
                        recoverable=True,
                    ),
                ],
            )

        duration_ms = int((time.monotonic() - t0) * 1000)
        rc = int(proc.returncode if proc.returncode is not None else -1)
        stdout = _redact(proc.stdout or "")
        stderr = _redact(proc.stderr or "")
        sigs = _signals(stdout, stderr, rc)
        obs: list[ToolResultObservationLite] = []
        if any(s in ("schema_violation", "5xx", "unexpected_2xx") for s in sigs):
            obs.append(
                ToolResultObservationLite(
                    observation_type="schema_mismatch",
                    confidence=0.6 if rc != 0 else 0.3,
                    details={
                        "operation_id": op_id,
                        "tool_name": command.tool_name,
                        "exit_code": rc,
                        "signal_count": len(sigs),
                        "signal_types": sigs[:12],
                    },
                ),
            )

        art = self._summary_artifact(
            command,
            tool_run_id,
            exit_code=rc,
            signal_types=sigs,
            stdout_tail=_tail(stdout),
            stderr_tail=_tail(stderr),
            operation_id=op_id,
            target_host=_target_host(target_in),
        )

        if rc == 0:
            status = "finished"
        elif rc == 2:
            status = "failed"
        else:
            status = "partial"

        errors: list[ToolResultError] = []
        if status == "failed":
            errors.append(
                ToolResultError(
                    error_type="schemathesis_process_error",
                    message="Schemathesis exited with code 2 (execution error).",
                    recoverable=False,
                ),
            )
        elif status == "partial":
            errors.append(
                ToolResultError(
                    error_type="schemathesis_reported_failures",
                    message=f"Schemathesis exit code {rc} with structured signals.",
                    recoverable=True,
                ),
            )

        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status=status,
            summary=ToolResultSummary(
                duration_ms=duration_ms,
                request_count=max_examples,
                success_count=1 if rc == 0 else 0,
            ),
            observations=obs,
            artifacts=[art],
            errors=errors,
        )

    def _summary_artifact(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        *,
        exit_code: int | None,
        signal_types: list[str],
        stdout_tail: str,
        stderr_tail: str,
        operation_id: str,
        target_host: str,
    ) -> ToolArtifactRef:
        payload: dict[str, Any] = {
            "schema_version": "schemathesis-negative-summary/v1",
            "operation_id": operation_id,
            "exit_code": exit_code,
            "signal_count": len(signal_types),
            "signal_types": signal_types[:20],
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "target_host": target_host,
        }
        return self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="schemathesis_negative_summary",
            content=payload,
        )

    def _failed(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        start_ms: int,
        error_type: str,
        message: str,
    ) -> ToolResult:
        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )
