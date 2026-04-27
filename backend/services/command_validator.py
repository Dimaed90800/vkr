"""Phase 4 — CommandValidator.

Validates a WorkerCommand against campaign state, tool allowlists,
budget limits, corpus, and auth profiles. Returns a structured
ValidationResult with errors and warnings.

Phase 4 does NOT execute the tool; that is deferred to Phase 5
ToolExecutor. Phase 4 also does NOT create observations, evidence
packs, findings, or judge inputs.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any
from urllib.parse import urlparse
from uuid import uuid4

try:
    from backend.models.campaign import Campaign, CampaignStatus
    from backend.models.worker_command import (
        ALL_KNOWN_TOOLS,
        ALLOWED_TOOLS_BY_WORKER_CLASS,
        ValidationError,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from backend.services.campaign_service import CampaignService
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign, CampaignStatus
    from models.worker_command import (
        ALL_KNOWN_TOOLS,
        ALLOWED_TOOLS_BY_WORKER_CLASS,
        ValidationError,
        ValidationResult,
        WorkerCommand,
        normalize_worker_class,
    )
    from services.campaign_service import CampaignService
    from services.request_corpus_service import RequestCorpusService
    from storage.memory_store import memory_store


_ABSOLUTE_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_INTERNAL_ZAP_BASE_HOSTS: set[str] = {
    "zap",
    "zap:8080",
    "localhost",
    "localhost:8080",
    "127.0.0.1",
    "127.0.0.1:8080",
}

def _extract_absolute_urls(value: Any, path: str = "inputs") -> list[tuple[str, str]]:
    """Return (path, url) pairs for all nested absolute http(s) URLs."""
    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, nested in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            found.extend(_extract_absolute_urls(nested, child_path))
        return found
    if isinstance(value, list):
        for idx, nested in enumerate(value):
            child_path = f"{path}[{idx}]"
            found.extend(_extract_absolute_urls(nested, child_path))
        return found
    if isinstance(value, tuple):
        for idx, nested in enumerate(value):
            child_path = f"{path}[{idx}]"
            found.extend(_extract_absolute_urls(nested, child_path))
        return found
    if isinstance(value, str) and _ABSOLUTE_URL_RE.match(value):
        found.append((path, value))
    return found


def _command_fingerprint(command: WorkerCommand, normalized_class: str) -> str:
    payload = json.dumps(
        {
            "campaign_id": command.campaign_id,
            "worker_class": normalized_class,
            "strategy": command.strategy,
            "tool_name": command.tool_name,
            "operation_id": command.operation_id,
            "inputs": command.inputs,
        },
        sort_keys=True,
        default=str,
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


class CommandValidator:
    def __init__(self) -> None:
        self._campaigns = CampaignService()
        self._corpus = RequestCorpusService()

    def validate(self, command: WorkerCommand) -> ValidationResult:
        errors: list[ValidationError] = []
        warnings: list[str] = []

        if not command.command_id:
            command.command_id = f"cmd_{uuid4().hex[:16]}"

        normalized_class = normalize_worker_class(command.worker_class)

        campaign = self._campaigns.get_campaign(command.campaign_id)
        if campaign is None:
            errors.append(ValidationError(
                code="campaign_not_found",
                message=f"Campaign '{command.campaign_id}' does not exist.",
                details={"campaign_id": command.campaign_id},
            ))
            return self._result(command, normalized_class or "", errors, warnings)

        if campaign.status != CampaignStatus.running:
            errors.append(ValidationError(
                code="campaign_status_invalid",
                message=f"Campaign status is '{campaign.status.value}', expected 'running'.",
                details={"status": campaign.status.value},
            ))

        if normalized_class is None:
            errors.append(ValidationError(
                code="unknown_worker_class",
                message=f"Worker class '{command.worker_class}' is not recognized.",
                details={"worker_class": command.worker_class},
            ))
            return self._result(command, "", errors, warnings)

        if not (command.strategy or "").strip():
            errors.append(ValidationError(
                code="strategy_empty",
                message="Strategy must not be empty.",
            ))

        self._validate_tool(command, normalized_class, errors)
        self._validate_budget(command, campaign, errors)
        self._validate_allowed_hosts(command, campaign, errors)
        self._validate_seed_request(command, errors)
        self._validate_auth_profiles(command, campaign, errors, warnings)
        self._validate_operation_id(command, warnings)
        if (command.tool_name or "").strip() == "injection_test":
            self._validate_injection_test(command, campaign, errors)
        self._check_fingerprint_duplicate(command, normalized_class, warnings)

        return self._result(command, normalized_class, errors, warnings)

    def _validate_tool(
        self,
        command: WorkerCommand,
        normalized_class: str,
        errors: list[ValidationError],
    ) -> None:
        tool = (command.tool_name or "").strip()
        if not tool:
            errors.append(ValidationError(
                code="tool_name_empty",
                message="tool_name must not be empty.",
            ))
            return

        if tool not in ALL_KNOWN_TOOLS:
            errors.append(ValidationError(
                code="unknown_tool",
                message=f"Tool '{tool}' is not a known tool.",
                details={"tool_name": tool},
            ))
            return

        allowed = ALLOWED_TOOLS_BY_WORKER_CLASS.get(normalized_class, [])
        if tool not in allowed:
            errors.append(ValidationError(
                code="tool_not_allowed_for_worker_class",
                message=f"Tool '{tool}' is not allowed for worker class '{normalized_class}'.",
                details={
                    "tool_name": tool,
                    "worker_class": normalized_class,
                    "allowed_tools": allowed,
                },
            ))

    def _validate_budget(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        if command.budget.max_requests > campaign.limits.max_requests:
            errors.append(ValidationError(
                code="budget_exceeds_campaign_limit",
                message=(
                    f"Command budget max_requests ({command.budget.max_requests}) "
                    f"exceeds campaign limit ({campaign.limits.max_requests})."
                ),
                details={
                    "command_max_requests": command.budget.max_requests,
                    "campaign_max_requests": campaign.limits.max_requests,
                },
            ))
        if command.budget.timeout_sec > campaign.limits.max_duration_sec:
            errors.append(ValidationError(
                code="budget_exceeds_campaign_duration",
                message=(
                    f"Command budget timeout_sec ({command.budget.timeout_sec}) "
                    f"exceeds campaign max_duration_sec ({campaign.limits.max_duration_sec})."
                ),
                details={
                    "command_timeout_sec": command.budget.timeout_sec,
                    "campaign_max_duration_sec": campaign.limits.max_duration_sec,
                },
            ))

    def _validate_allowed_hosts(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        if not campaign.allowed_hosts:
            return
        allowed_hosts = {h.lower() for h in campaign.allowed_hosts}
        for key, url in _extract_absolute_urls(command.inputs):
            parsed = urlparse(url)
            scheme = (parsed.scheme or "").lower()
            host = (parsed.hostname or "").lower()
            host_port = f"{host}:{parsed.port}" if parsed.port is not None else host

            if command.tool_name == "zap_discovery_passive" and key == "inputs.zap_base_url":
                if scheme not in {"http", "https"} or host_port not in _INTERNAL_ZAP_BASE_HOSTS:
                    errors.append(ValidationError(
                        code="invalid_zap_base_url",
                        message=(
                            "inputs.zap_base_url must use http/https and point "
                            "to an approved internal ZAP endpoint."
                        ),
                        details={
                            "key": key,
                            "url": url,
                            "allowed_internal_zap_hosts": sorted(_INTERNAL_ZAP_BASE_HOSTS),
                        },
                    ))
                continue

            if (
                command.tool_name == "schemathesis_negative_test"
                and key == "inputs.openapi_url"
                and scheme in {"http", "https"}
            ):
                trusted = str(campaign.openapi_url or "").strip()
                if trusted and url.strip() == trusted:
                    continue

            if host and host not in allowed_hosts and host_port not in allowed_hosts:
                errors.append(ValidationError(
                    code="host_not_allowed",
                    message=f"Host '{host_port}' from {key} is not in campaign allowed_hosts.",
                    details={
                        "key": key,
                        "url": url,
                        "host": host,
                        "host_port": host_port,
                        "allowed_hosts": campaign.allowed_hosts,
                    },
                ))

    def _validate_seed_request(
        self,
        command: WorkerCommand,
        errors: list[ValidationError],
    ) -> None:
        seed_id = (command.seed_request_id or "").strip()
        if not seed_id:
            return
        item = self._corpus.get_request(seed_id)
        if item is None:
            errors.append(ValidationError(
                code="seed_request_not_found",
                message=f"Seed request '{seed_id}' does not exist.",
                details={"seed_request_id": seed_id},
            ))
            return
        if item.campaign_id != command.campaign_id:
            errors.append(ValidationError(
                code="seed_request_wrong_campaign",
                message=(
                    f"Seed request '{seed_id}' belongs to campaign "
                    f"'{item.campaign_id}', not '{command.campaign_id}'."
                ),
                details={
                    "seed_request_id": seed_id,
                    "seed_campaign_id": item.campaign_id,
                    "command_campaign_id": command.campaign_id,
                },
            ))

    def _validate_auth_profiles(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
        warnings: list[str],
    ) -> None:
        role_keys = {"owner_role", "attacker_role", "auth_profile"}
        referenced_roles: list[str] = []
        for key in role_keys:
            value = command.inputs.get(key)
            if isinstance(value, str) and value.strip():
                referenced_roles.append(value.strip())

        if not referenced_roles:
            return

        if not campaign.roles_json:
            warnings.append("auth_profiles_not_configured")
            return

        configured_names = {
            str(r.get("name") or "").strip().lower()
            for r in campaign.roles_json
            if isinstance(r, dict) and r.get("name")
        }
        for role in referenced_roles:
            if role.lower() not in configured_names:
                errors.append(ValidationError(
                    code="auth_profile_not_found",
                    message=f"Auth profile '{role}' is not configured in campaign roles_json.",
                    details={
                        "role": role,
                        "configured_roles": sorted(configured_names),
                    },
                ))

    def _validate_injection_test(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "contract_fuzzing":
            errors.append(ValidationError(
                code="injection_worker_class_invalid",
                message="injection_test requires worker_class contract_fuzzing.",
                details={"worker_class": command.worker_class},
            ))
        if not (command.operation_id or "").strip():
            errors.append(ValidationError(
                code="operation_id_required_for_injection_test",
                message="operation_id is required for injection_test.",
            ))
        if command.budget.max_requests > 10:
            errors.append(ValidationError(
                code="injection_budget_max_requests",
                message="injection_test max_requests must be <= 10.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 30:
            errors.append(ValidationError(
                code="injection_budget_timeout",
                message="injection_test timeout_sec must be <= 30.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "operation_id",
            "payload_families",
            "max_payloads_per_param",
            "parameter_candidates",
        }
        for k in inputs:
            if k not in allowed_keys:
                errors.append(ValidationError(
                    code="injection_inputs_unknown_key",
                    message=f"inputs.{k} is not allowed for injection_test.",
                    details={"key": k, "allowed": sorted(allowed_keys)},
                ))
        target_url = str(inputs.get("target_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="injection_target_url_required",
                message="inputs.target_url is required for injection_test.",
            ))
        else:
            trusted = (campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted.rstrip("/"):
                errors.append(ValidationError(
                    code="injection_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        iop = str(inputs.get("operation_id") or "").strip()
        if iop and iop != (command.operation_id or "").strip():
            errors.append(ValidationError(
                code="injection_operation_id_mismatch",
                message="inputs.operation_id must match command.operation_id when set.",
            ))
        mpp = inputs.get("max_payloads_per_param")
        if mpp is not None:
            try:
                mppi = int(mpp)
            except (TypeError, ValueError):
                errors.append(ValidationError(
                    code="injection_max_payloads_invalid",
                    message="max_payloads_per_param must be an integer.",
                ))
            else:
                if mppi > 2 or mppi < 1:
                    errors.append(ValidationError(
                        code="injection_max_payloads_out_of_range",
                        message="max_payloads_per_param must be between 1 and 2.",
                    ))

    def _validate_operation_id(
        self,
        command: WorkerCommand,
        warnings: list[str],
    ) -> None:
        op_id = (command.operation_id or "").strip()
        graph_blob = memory_store.get_graph_for_campaign(command.campaign_id)
        if graph_blob is None:
            if op_id:
                warnings.append(f"operation_id_graph_not_built:{op_id}")
            else:
                warnings.append("operation_id_graph_not_built")
            return
        if not op_id:
            warnings.append("operation_id_missing")
            return
        graph_data = graph_blob.get("graph") or graph_blob
        operations = graph_data.get("operations") or []
        op_ids = {str(o.get("operation_id") or "") for o in operations if isinstance(o, dict)}
        if op_id not in op_ids:
            warnings.append(f"operation_id_not_in_graph:{op_id}")

    def _check_fingerprint_duplicate(
        self,
        command: WorkerCommand,
        normalized_class: str,
        warnings: list[str],
    ) -> None:
        fp = _command_fingerprint(command, normalized_class)
        existing = memory_store.command_fingerprints.get(command.campaign_id, set())
        if fp in existing:
            warnings.append(f"duplicate_command_fingerprint:{fp}")

    def _result(
        self,
        command: WorkerCommand,
        normalized_class: str,
        errors: list[ValidationError],
        warnings: list[str],
    ) -> ValidationResult:
        return ValidationResult(
            valid=len(errors) == 0,
            command_id=command.command_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            normalized_worker_class=normalized_class,
            errors=errors,
            warnings=warnings,
        )
