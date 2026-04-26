"""Phase 11A — ZAP discovery/passive adapter.

Backend-owned adapter that produces ToolResult signals only. It never runs
active scan endpoints and never creates EvidencePack, JudgeDecision, or Finding.
"""
from __future__ import annotations

import re
import time
from typing import Any
from urllib.parse import urljoin, urlparse

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.http.safe_http_client import sanitize_url_for_storage
    from backend.services.request_corpus_service import redact_sensitive_data
    from backend.services.zap_passive_client import (
        ZapPassiveClient,
        ZapPassiveClientError,
    )
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.http.safe_http_client import sanitize_url_for_storage
    from services.request_corpus_service import redact_sensitive_data
    from services.zap_passive_client import (
        ZapPassiveClient,
        ZapPassiveClientError,
    )


class ZapDiscoveryPassiveAdapter:
    def __init__(
        self,
        zap_client: ZapPassiveClient | None = None,
    ) -> None:
        self._zap_client = zap_client
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        start_ms = int(time.monotonic() * 1000)
        inputs = command.inputs or {}
        target_url = str(inputs.get("target_url") or campaign.target_url)
        seed_urls = _string_list(inputs.get("seed_urls") or [])

        scope_error = self._validate_scope(campaign, target_url, seed_urls)
        if scope_error is not None:
            return self._failed_result(
                command,
                tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=scope_error[0],
                message=scope_error[1],
            )

        max_duration = min(
            int(inputs.get("max_duration_sec") or command.budget.timeout_sec or 30),
            int(command.budget.timeout_sec or 30),
            int(campaign.limits.max_duration_sec or 30),
        )
        max_discovered = max(1, int(inputs.get("max_discovered_urls") or 100))
        max_alerts = max(1, int(inputs.get("max_alerts") or 100))
        zap = self._zap_client or ZapPassiveClient(
            str(inputs.get("zap_base_url") or "") or None,
            timeout_sec=min(max_duration, 10),
        )

        try:
            zap_result = zap.run_discovery_passive(
                target_url=target_url,
                seed_urls=seed_urls,
                use_spider=bool(inputs.get("use_spider", True)),
                max_children=int(inputs.get("max_children") or 50),
                max_duration_sec=max_duration,
                max_discovered_urls=max_discovered,
                max_alerts=max_alerts,
            )
        except ZapPassiveClientError as exc:
            if exc.code == "zap_passive_timeout":
                partial_result = self._partial_result_for_passive_timeout(
                    command=command,
                    campaign=campaign,
                    tool_run_id=tool_run_id,
                    duration_ms=int(time.monotonic() * 1000) - start_ms,
                    zap=zap,
                    target_url=target_url,
                    seed_urls=seed_urls,
                    max_discovered=max_discovered,
                    max_alerts=max_alerts,
                    error=exc,
                )
                if partial_result is not None:
                    return partial_result
            return self._failed_result(
                command,
                tool_run_id,
                duration_ms=int(time.monotonic() * 1000) - start_ms,
                error_type=exc.code,
                message=exc.message,
                details=exc.details,
            )

        in_scope_urls, ignored = self._filter_in_scope_urls(campaign, zap_result.discovered_urls)
        in_scope_urls = in_scope_urls[:max_discovered]
        in_scope_alerts = [
            alert for alert in zap_result.alerts
            if self._is_allowed(campaign, str(alert.get("url") or target_url))
        ][:max_alerts]

        observations = [
            self._discovered_endpoint_observation(url, command)
            for url in in_scope_urls
        ]
        observations.extend(
            self._zap_alert_observation(alert, command)
            for alert in in_scope_alerts
        )

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="zap_discovery_passive_summary",
            content={
                "target_url": sanitize_url_for_storage(target_url),
                "discovered_urls": [sanitize_url_for_storage(url) for url in in_scope_urls],
                "alerts": [_sanitize_alert(alert) for alert in in_scope_alerts],
                "ignored_out_of_scope": ignored,
                "metadata": _safe_metadata(zap_result.metadata),
            },
        )

        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=0,
                success_count=len(in_scope_urls),
                duration_ms=duration_ms,
            ),
            observations=observations,
            artifacts=[artifact],
        )

    def _partial_result_for_passive_timeout(
        self,
        *,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
        duration_ms: int,
        zap: Any,
        target_url: str,
        seed_urls: list[str],
        max_discovered: int,
        max_alerts: int,
        error: ZapPassiveClientError,
    ) -> ToolResult | None:
        discovered_urls: list[str] = []
        for base in _dedupe([target_url, *seed_urls]):
            try:
                discovered_urls.extend(zap.core_urls(base))
            except Exception:
                continue
        try:
            alerts = zap.alerts(target_url, count=max_alerts)
        except Exception:
            alerts = []

        in_scope_urls, ignored = self._filter_in_scope_urls(campaign, discovered_urls)
        in_scope_urls = in_scope_urls[:max_discovered]
        in_scope_alerts = [
            alert for alert in alerts
            if self._is_allowed(campaign, str(alert.get("url") or target_url))
        ][:max_alerts]
        if not in_scope_urls and not in_scope_alerts:
            return None

        observations = [
            self._discovered_endpoint_observation(url, command)
            for url in in_scope_urls
        ]
        observations.extend(
            self._zap_alert_observation(alert, command)
            for alert in in_scope_alerts
        )

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="zap_discovery_passive_summary",
            content={
                "target_url": sanitize_url_for_storage(target_url),
                "discovered_urls": [sanitize_url_for_storage(url) for url in in_scope_urls],
                "alerts": [_sanitize_alert(alert) for alert in in_scope_alerts],
                "ignored_out_of_scope": ignored,
                "metadata": {
                    "timeout_diagnostic": {
                        "error_type": error.code,
                        "message": error.message,
                        "details": error.details,
                    },
                    "discovered_url_total": len(in_scope_urls),
                    "alert_total": len(in_scope_alerts),
                },
            },
        )

        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="partial",
            summary=ToolResultSummary(
                request_count=0,
                success_count=len(in_scope_urls),
                duration_ms=duration_ms,
            ),
            observations=observations,
            artifacts=[artifact],
            errors=[ToolResultError(
                error_type="zap_passive_timeout",
                message=error.message,
                recoverable=True,
            )],
        )

        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="zap_discovery_passive_summary",
            content={
                "target_url": sanitize_url_for_storage(target_url),
                "discovered_urls": [sanitize_url_for_storage(url) for url in in_scope_urls],
                "alerts": [_sanitize_alert(alert) for alert in in_scope_alerts],
                "ignored_out_of_scope": ignored,
                "metadata": _safe_metadata(zap_result.metadata),
            },
        )

        duration_ms = int(time.monotonic() * 1000) - start_ms
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="finished",
            summary=ToolResultSummary(
                request_count=0,
                success_count=len(in_scope_urls),
                duration_ms=duration_ms,
            ),
            observations=observations,
            artifacts=[artifact],
        )

    def _validate_scope(
        self,
        campaign: Campaign,
        target_url: str,
        seed_urls: list[str],
    ) -> tuple[str, str] | None:
        if not campaign.allowed_hosts:
            return (
                "allowed_hosts_not_configured",
                "Campaign allowed_hosts is empty; ZAP discovery is blocked.",
            )
        for url in [target_url, *seed_urls]:
            if not self._is_allowed(campaign, url):
                return (
                    "host_not_allowed",
                    f"URL '{sanitize_url_for_storage(url)}' is outside campaign allowed_hosts.",
                )
        return None

    def _filter_in_scope_urls(
        self,
        campaign: Campaign,
        urls: list[str],
    ) -> tuple[list[str], int]:
        kept: list[str] = []
        ignored = 0
        seen: set[str] = set()
        for url in urls:
            if self._is_allowed(campaign, url):
                safe = sanitize_url_for_storage(url)
                if safe not in seen:
                    seen.add(safe)
                    kept.append(safe)
            else:
                ignored += 1
        return kept, ignored

    def _is_allowed(self, campaign: Campaign, raw_url: str) -> bool:
        url = self._resolve_url(campaign, raw_url)
        parsed = urlparse(url)
        if parsed.scheme.lower() not in {"http", "https"}:
            return False
        host = (parsed.hostname or "").lower()
        host_port = f"{host}:{parsed.port}" if parsed.port is not None else host
        allowed = {str(item or "").lower() for item in campaign.allowed_hosts if str(item or "").strip()}
        return bool(allowed) and (host in allowed or host_port in allowed)

    @staticmethod
    def _resolve_url(campaign: Campaign, raw_url: str) -> str:
        raw = str(raw_url or "")
        if urlparse(raw).scheme:
            return raw
        return urljoin(campaign.target_url.rstrip("/") + "/", raw.lstrip("/"))

    def _discovered_endpoint_observation(
        self,
        url: str,
        command: WorkerCommand,
    ) -> ToolResultObservationLite:
        parsed = urlparse(url)
        return ToolResultObservationLite(
            observation_type="discovered_endpoint",
            confidence=0.55,
            details={
                "source": "zap_spider",
                "url": sanitize_url_for_storage(url),
                "path": parsed.path or "/",
                "method": "GET",
                "operation_id": command.operation_id,
            },
        )

    def _zap_alert_observation(
        self,
        alert: dict[str, Any],
        command: WorkerCommand,
    ) -> ToolResultObservationLite:
        sanitized = _sanitize_alert(alert)
        return ToolResultObservationLite(
            observation_type="zap_alert",
            confidence=_alert_confidence(sanitized),
            details={
                **sanitized,
                "source": "zap_passive",
                "operation_id": command.operation_id,
            },
        )

    def _failed_result(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        *,
        duration_ms: int,
        error_type: str,
        message: str,
        details: dict[str, Any] | None = None,
    ) -> ToolResult:
        artifact = self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="zap_discovery_passive_error",
            content={
                "error_type": error_type,
                "message": message,
                "details": details or {},
            },
        )
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            artifacts=[artifact],
            errors=[ToolResultError(
                error_type=error_type,
                message=message,
                recoverable=True,
            )],
        )


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item or "").strip()]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def _sanitize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    safe = {
        "alert_name": str(alert.get("alert") or alert.get("name") or ""),
        "alert_ref": str(alert.get("alertRef") or ""),
        "plugin_id": str(alert.get("pluginId") or ""),
        "risk": str(alert.get("risk") or ""),
        "confidence": str(alert.get("confidence") or ""),
        "cwe_id": str(alert.get("cweid") or ""),
        "wasc_id": str(alert.get("wascid") or ""),
        "param": str(alert.get("param") or ""),
        "url": sanitize_url_for_storage(str(alert.get("url") or "")),
        "path": urlparse(str(alert.get("url") or "")).path or "",
    }
    _, redacted = redact_sensitive_data(None, {
        "evidence": _redact_text(str(alert.get("evidence") or "")[:300]),
        "description": _redact_text(str(alert.get("description") or "")[:500]),
        "solution": _redact_text(str(alert.get("solution") or "")[:500]),
        "reference": _redact_text(str(alert.get("reference") or "")[:500]),
    })
    safe.update(redacted if isinstance(redacted, dict) else {})
    return safe


def _alert_confidence(alert: dict[str, Any]) -> float:
    risk = str(alert.get("risk") or "").lower()
    confidence = str(alert.get("confidence") or "").lower()
    base = {
        "high": 0.75,
        "medium": 0.6,
        "low": 0.45,
        "informational": 0.25,
    }.get(risk, 0.35)
    if confidence == "high":
        return min(base + 0.1, 0.9)
    if confidence == "low":
        return max(base - 0.1, 0.1)
    return base


def _safe_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    allowed_keys = {
        "zap_base_url",
        "version",
        "use_spider",
        "seed_url_total",
        "discovered_url_total",
        "alert_total",
    }
    return {
        key: metadata.get(key)
        for key in allowed_keys
        if key in metadata
    }


def _redact_text(value: str) -> str:
    text = str(value or "")
    text = re.sub(
        r"(?i)(authorization\s*:\s*bearer\s+)[^\s,;]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)(bearer\s+)[^\s,;]+",
        r"\1<redacted>",
        text,
    )
    text = re.sub(
        r"(?i)((?:access_)?token|secret|api[_-]?key|password)(\s*[=:]\s*)[^\s,;&]+",
        r"\1\2<redacted>",
        text,
    )
    return text
