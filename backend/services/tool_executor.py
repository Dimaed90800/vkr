"""Phase 5 — ToolExecutor skeleton.

Consumes a validated WorkerCommand, creates a ToolRun, dispatches
to the appropriate adapter, and produces a ToolResult v1.

Phase 5 constraints:
- Does NOT call Judge or create EvidencePack/findings.
- Async path only creates ToolRun with status=running; no real execution.
- Supported sync adapters are explicitly registered; unsupported tools fail.
- Known but unsupported tools produce a controlled error.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultError,
        ToolResultSummary,
        ToolRun,
        ToolRunProgress,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.adapters.noop_adapter import NoopAdapter
    from backend.services.adapters.http_replay_adapter import HttpReplayAdapter
    from backend.services.adapters.bola_replay_probe_adapter import BolaReplayProbeAdapter
    from backend.services.adapters.zap_discovery_passive_adapter import ZapDiscoveryPassiveAdapter
    from backend.services.adapters.security_header_validator_adapter import SecurityHeaderValidatorAdapter
    from backend.services.artifact_store import ArtifactStore
    from backend.services.campaign_service import CampaignService
    from backend.services.command_validator import CommandValidator
    from backend.services.http.safe_http_client import SafeHttpClient
    from backend.services.tool_registry import ToolRegistry
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolArtifactRef,
        ToolResult,
        ToolResultError,
        ToolResultSummary,
        ToolRun,
        ToolRunProgress,
    )
    from models.worker_command import WorkerCommand
    from services.adapters.noop_adapter import NoopAdapter
    from services.adapters.http_replay_adapter import HttpReplayAdapter
    from services.adapters.bola_replay_probe_adapter import BolaReplayProbeAdapter
    from services.adapters.zap_discovery_passive_adapter import ZapDiscoveryPassiveAdapter
    from services.adapters.security_header_validator_adapter import SecurityHeaderValidatorAdapter
    from services.artifact_store import ArtifactStore
    from services.campaign_service import CampaignService
    from services.command_validator import CommandValidator
    from services.http.safe_http_client import SafeHttpClient
    from services.tool_registry import ToolRegistry
    from storage.memory_store import memory_store


class ToolExecutorStartError(ValueError):
    def __init__(
        self,
        *,
        code: str,
        message: str,
        status_code: int = 400,
        validation: object | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.validation = validation


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_run_id() -> str:
    return f"toolrun_{uuid4().hex[:16]}"


class ToolExecutor:
    def __init__(
        self,
        http_client: SafeHttpClient | None = None,
        zap_passive_client: object | None = None,
    ) -> None:
        self._registry = ToolRegistry()
        self._validator = CommandValidator()
        self._campaigns = CampaignService()
        self._artifact_store = ArtifactStore()
        self._noop = NoopAdapter()
        self._http_replay = HttpReplayAdapter(http_client=http_client)
        self._bola_replay = BolaReplayProbeAdapter(http_client=http_client)
        self._zap_discovery_passive = ZapDiscoveryPassiveAdapter(zap_client=zap_passive_client)
        self._security_header_validator = SecurityHeaderValidatorAdapter(http_client=http_client)

    def execute_sync(self, command: WorkerCommand) -> ToolResult:
        validation = self._validator.validate(command)
        if not validation.valid:
            return self._failed_result(
                command,
                error_type="validation_failed",
                message="; ".join(e.message for e in validation.errors),
            )

        campaign = self._campaigns.get_campaign(command.campaign_id)
        if campaign is None:
            return self._failed_result(
                command,
                error_type="campaign_not_found",
                message=f"Campaign '{command.campaign_id}' not found.",
            )

        tool_run_id = _make_run_id()
        run = self._create_tool_run(command, tool_run_id, execution_mode="sync", status="running")
        memory_store.store_tool_run(tool_run_id, command.campaign_id, run.model_dump(mode="json"))

        if not self._registry.has_adapter(command.tool_name):
            result = self._no_adapter_result(command, tool_run_id)
            self._finish_run(tool_run_id, result)
            return result

        try:
            result = self._execute_adapter(command, campaign, tool_run_id)
        except Exception as exc:
            result = self._error_result(
                command, tool_run_id,
                error_type="adapter_error",
                message=str(exc),
            )

        self._finish_run(tool_run_id, result)
        return result

    def _execute_adapter(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        if command.tool_name == "http_replay_executor":
            return self._http_replay.execute(command, campaign, tool_run_id)
        if command.tool_name == "bola_replay_probe":
            return self._bola_replay.execute(command, campaign, tool_run_id)
        if command.tool_name == "zap_discovery_passive":
            return self._zap_discovery_passive.execute(command, campaign, tool_run_id)
        if command.tool_name == "security_header_validator":
            return self._security_header_validator.execute(command, campaign, tool_run_id)
        return self._noop.execute(command, campaign, tool_run_id)

    def start_async(self, command: WorkerCommand) -> ToolRun:
        validation = self._validator.validate(command)
        if not validation.valid:
            raise ToolExecutorStartError(
                code="validation_failed",
                message="WorkerCommand validation failed.",
                status_code=400,
                validation=validation,
            )
        if not self._registry.has_adapter(command.tool_name):
            raise ToolExecutorStartError(
                code="async_adapter_not_available",
                message=(
                    f"No async adapter available for tool "
                    f"'{command.tool_name}' in Phase 5."
                ),
                status_code=501,
            )
        tool_run_id = _make_run_id()
        run = self._create_tool_run(command, tool_run_id, execution_mode="async", status="running")
        memory_store.store_tool_run(tool_run_id, command.campaign_id, run.model_dump(mode="json"))
        return run

    def get_status(self, tool_run_id: str) -> ToolRun | None:
        data = memory_store.get_tool_run(tool_run_id)
        if data is None:
            return None
        return ToolRun.model_validate(data)

    def collect(self, tool_run_id: str) -> ToolResult | None:
        run_data = memory_store.get_tool_run(tool_run_id)
        if run_data is None:
            return None
        if run_data.get("status") != "finished":
            return None
        result_data = memory_store.get_tool_result(tool_run_id)
        if result_data is None:
            return None
        return ToolResult.model_validate(result_data)

    def mark_finished(self, tool_run_id: str, result: ToolResult) -> None:
        self._finish_run(tool_run_id, result)

    def mark_failed(
        self, tool_run_id: str, error_type: str, message: str,
    ) -> ToolResult:
        run_data = memory_store.get_tool_run(tool_run_id)
        if run_data is None:
            return ToolResult(
                tool_run_id=tool_run_id,
                campaign_id="",
                tool_name="unknown",
                status="failed",
                errors=[ToolResultError(error_type="run_not_found", message="ToolRun not found.")],
            )
        result = ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=run_data.get("campaign_id", ""),
            task_id=run_data.get("task_id", ""),
            command_id=run_data.get("command_id", ""),
            tool_name=run_data.get("tool_name", ""),
            status="failed",
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )
        self._finish_run(tool_run_id, result, status_override="failed")
        return result

    def _create_tool_run(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        execution_mode: str,
        status: str,
    ) -> ToolRun:
        return ToolRun(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            command_id=command.command_id,
            task_id=command.task_id,
            tool_name=command.tool_name,
            execution_mode=execution_mode,
            status=status,
            started_at=_now_iso(),
            progress=ToolRunProgress(
                max_requests=command.budget.max_requests,
            ),
            result_ready=False,
        )

    def _finish_run(
        self,
        tool_run_id: str,
        result: ToolResult,
        status_override: str | None = None,
    ) -> None:
        final_status = status_override or result.status
        memory_store.update_tool_run(tool_run_id, {
            "status": final_status,
            "finished_at": _now_iso(),
            "result_ready": True,
            "artifact_refs": [a.model_dump(mode="json") for a in result.artifacts],
        })
        memory_store.store_tool_result(tool_run_id, result.model_dump(mode="json"))

    def _failed_result(
        self,
        command: WorkerCommand,
        error_type: str,
        message: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id="",
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )

    def _no_adapter_result(
        self,
        command: WorkerCommand,
        tool_run_id: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            errors=[ToolResultError(
                error_type="adapter_not_available",
                message=f"No adapter available for tool '{command.tool_name}' in Phase 5.",
                recoverable=True,
            )],
        )

    def _error_result(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        error_type: str,
        message: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            errors=[ToolResultError(error_type=error_type, message=message, recoverable=False)],
        )
