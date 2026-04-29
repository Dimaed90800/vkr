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
        if (command.tool_name or "").strip() == "property_mutation_test":
            self._validate_property_mutation_test(command, campaign, errors)
        if (command.tool_name or "").strip() == "cors_validator":
            self._validate_cors_validator(command, campaign, errors)
        if (command.tool_name or "").strip() == "cookie_flag_validator":
            self._validate_cookie_flag_validator(command, campaign, errors)
        if (command.tool_name or "").strip() == "ssrf_candidate_detector":
            self._validate_ssrf_candidate_detector(command, campaign, errors)
        if (command.tool_name or "").strip() == "ssrf_probe":
            self._validate_ssrf_probe(command, campaign, errors)
        if (command.tool_name or "").strip() == "js_endpoint_extractor":
            self._validate_js_endpoint_extractor(command, campaign, errors)
        if (command.tool_name or "").strip() == "undocumented_endpoint_validator":
            self._validate_undocumented_endpoint_validator(command, campaign, errors)
        if (command.tool_name or "").strip() == "data_exposure_validator":
            self._validate_data_exposure_validator(command, campaign, errors)
        if (command.tool_name or "").strip() == "auth_flow_detector":
            self._validate_auth_flow_detector(command, campaign, errors)
        if (command.tool_name or "").strip() == "test_account_materializer":
            self._validate_test_account_materializer(command, campaign, errors)
        if (command.tool_name or "").strip() == "resource_instance_extractor":
            self._validate_resource_instance_extractor(command, campaign, errors)
        if (command.tool_name or "").strip() == "resource_seed_worker":
            self._validate_resource_seed_worker(command, campaign, errors)
        if (command.tool_name or "").strip() == "bola_object_pair_builder":
            self._validate_bola_object_pair_builder(command, campaign, errors)
        if (command.tool_name or "").strip() == "bola_replay_probe":
            self._validate_bola_replay_probe(command, campaign, errors)
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

            if (
                command.tool_name == "cors_validator"
                and key == "inputs.origin_probe"
                and url.strip() == "https://evil.example.invalid"
            ):
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

    def _validate_property_mutation_test(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "access_control":
            errors.append(ValidationError(
                code="property_mutation_worker_class_invalid",
                message="property_mutation_test requires worker_class access_control.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "property_mutation_probe":
            errors.append(ValidationError(
                code="property_mutation_strategy_invalid",
                message="property_mutation_test requires strategy property_mutation_probe.",
            ))
        op_id = (command.operation_id or "").strip()
        if not op_id:
            errors.append(ValidationError(
                code="operation_id_required_for_property_mutation_test",
                message="operation_id is required for property_mutation_test.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "operation_id",
            "mutation_policy",
            "diagnostic_only",
            "sensitive_fields",
            "max_mutations",
            "seed_request_id",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="disallowed_property_mutation_input",
                    message=f"inputs.{key} is not allowed for property_mutation_test.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="property_mutation_target_required",
                message="inputs.target_url is required for property_mutation_test.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="property_mutation_target_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))

        inputs_op = str(inputs.get("operation_id") or "").strip()
        if inputs_op and inputs_op != op_id:
            errors.append(ValidationError(
                code="property_mutation_operation_mismatch",
                message="inputs.operation_id must match command.operation_id when set.",
            ))

        mutation_policy = str(inputs.get("mutation_policy") or "").strip().lower()
        if mutation_policy != "diagnostic_only":
            errors.append(ValidationError(
                code="invalid_mutation_policy",
                message="mutation_policy must be diagnostic_only in Phase 18A-1.",
            ))

        if inputs.get("diagnostic_only") is not True:
            errors.append(ValidationError(
                code="mutation_requires_diagnostic_only",
                message="diagnostic_only must be true in Phase 18A-1.",
            ))

        max_mutations = inputs.get("max_mutations")
        try:
            mm = int(max_mutations)
        except (TypeError, ValueError):
            mm = -1
        if mm < 0 or mm > 3:
            errors.append(ValidationError(
                code="max_mutations_exceeded",
                message="max_mutations must be between 0 and 3.",
                details={"max_mutations": max_mutations},
            ))

        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="property_mutation_budget_requests",
                message="property_mutation_test max_requests must be 0 or 1 in diagnostic mode.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 30:
            errors.append(ValidationError(
                code="property_mutation_budget_timeout",
                message="property_mutation_test timeout_sec must be <= 30.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

        sensitive_fields = inputs.get("sensitive_fields")
        if sensitive_fields is None:
            return
        if not isinstance(sensitive_fields, list):
            errors.append(ValidationError(
                code="property_mutation_sensitive_fields_invalid",
                message="sensitive_fields must be list[str] when provided.",
            ))
            return
        if len(sensitive_fields) > 20:
            errors.append(ValidationError(
                code="property_mutation_sensitive_fields_too_many",
                message="sensitive_fields must contain at most 20 items.",
            ))
        for value in sensitive_fields:
            if not isinstance(value, str):
                errors.append(ValidationError(
                    code="property_mutation_sensitive_fields_invalid",
                    message="sensitive_fields must contain only strings.",
                ))
                continue
            v = value.strip()
            if not v or len(v) > 64 or re.search(r"[\s:=]", v):
                errors.append(ValidationError(
                    code="property_mutation_sensitive_fields_invalid",
                    message="sensitive_fields entries must be compact field names (no values/tokens).",
                    details={"field": value},
                ))

    def _validate_cors_validator(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "misconfiguration":
            errors.append(ValidationError(
                code="cors_worker_class_invalid",
                message="cors_validator requires worker_class misconfiguration.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "validate_cors_policy":
            errors.append(ValidationError(
                code="cors_strategy_invalid",
                message="cors_validator requires strategy validate_cors_policy.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "request_url",
            "operation_id",
            "path_template",
            "method",
            "origin_probe",
            "validation_mode",
            "max_response_bytes",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="cors_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for cors_validator.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        request_url = str(inputs.get("request_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="cors_target_url_required",
                message="inputs.target_url is required for cors_validator.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="cors_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        if not request_url:
            errors.append(ValidationError(
                code="cors_request_url_required",
                message="inputs.request_url is required for cors_validator.",
            ))

        method = str(inputs.get("method") or "GET").strip().upper()
        if method not in {"GET", "OPTIONS"}:
            errors.append(ValidationError(
                code="cors_method_not_allowed",
                message="cors_validator supports only GET or OPTIONS.",
                details={"method": method},
            ))

        origin_probe = str(inputs.get("origin_probe") or "https://evil.example.invalid").strip()
        if origin_probe != "https://evil.example.invalid":
            errors.append(ValidationError(
                code="cors_origin_probe_invalid",
                message="origin_probe must be https://evil.example.invalid in MVP.",
            ))

        validation_mode = str(inputs.get("validation_mode") or "single_replay_cors_check").strip()
        if validation_mode and validation_mode != "single_replay_cors_check":
            errors.append(ValidationError(
                code="cors_validation_mode_invalid",
                message="validation_mode must be single_replay_cors_check in MVP.",
            ))

        if command.budget.max_requests > 2:
            errors.append(ValidationError(
                code="cors_budget_max_requests",
                message="cors_validator max_requests must be <= 2.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="cors_budget_timeout",
                message="cors_validator timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_cookie_flag_validator(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "misconfiguration":
            errors.append(ValidationError(
                code="cookie_worker_class_invalid",
                message="cookie_flag_validator requires worker_class misconfiguration.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "validate_cookie_flags":
            errors.append(ValidationError(
                code="cookie_strategy_invalid",
                message="cookie_flag_validator requires strategy validate_cookie_flags.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "request_url",
            "operation_id",
            "path_template",
            "method",
            "validation_mode",
            "max_response_bytes",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="cookie_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for cookie_flag_validator.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        request_url = str(inputs.get("request_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="cookie_target_url_required",
                message="inputs.target_url is required for cookie_flag_validator.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="cookie_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        if not request_url:
            errors.append(ValidationError(
                code="cookie_request_url_required",
                message="inputs.request_url is required for cookie_flag_validator.",
            ))

        method = str(inputs.get("method") or "GET").strip().upper()
        if method != "GET":
            errors.append(ValidationError(
                code="cookie_method_not_allowed",
                message="cookie_flag_validator supports only GET.",
                details={"method": method},
            ))

        validation_mode = str(inputs.get("validation_mode") or "baseline_cookie_flag_check").strip()
        if validation_mode and validation_mode != "baseline_cookie_flag_check":
            errors.append(ValidationError(
                code="cookie_validation_mode_invalid",
                message="validation_mode must be baseline_cookie_flag_check in MVP.",
            ))

        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="cookie_budget_max_requests",
                message="cookie_flag_validator max_requests must be <= 1.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="cookie_budget_timeout",
                message="cookie_flag_validator timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_undocumented_endpoint_validator(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "discovery_inventory":
            errors.append(ValidationError(
                code="undocumented_worker_class_invalid",
                message="undocumented_endpoint_validator requires worker_class discovery_inventory.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "validate_undocumented_endpoint":
            errors.append(ValidationError(
                code="undocumented_strategy_invalid",
                message="undocumented_endpoint_validator requires strategy validate_undocumented_endpoint.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "request_url",
            "method",
            "path",
            "source_observation_id",
            "validation_mode",
            "max_response_bytes",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="undocumented_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for undocumented_endpoint_validator.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        request_url = str(inputs.get("request_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="undocumented_target_url_required",
                message="inputs.target_url is required for undocumented_endpoint_validator.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="undocumented_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        if not request_url:
            errors.append(ValidationError(
                code="undocumented_request_url_required",
                message="inputs.request_url is required for undocumented_endpoint_validator.",
            ))

        method = str(inputs.get("method") or "GET").strip().upper()
        if method not in {"GET", "HEAD"}:
            errors.append(ValidationError(
                code="undocumented_method_not_allowed",
                message="undocumented_endpoint_validator supports only GET or HEAD.",
                details={"method": method},
            ))

        validation_mode = str(
            inputs.get("validation_mode") or "one_shot_undocumented_endpoint_check"
        ).strip()
        if validation_mode and validation_mode != "one_shot_undocumented_endpoint_check":
            errors.append(ValidationError(
                code="undocumented_validation_mode_invalid",
                message="validation_mode must be one_shot_undocumented_endpoint_check in MVP.",
            ))

        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="undocumented_budget_max_requests",
                message="undocumented_endpoint_validator max_requests must be <= 1.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="undocumented_budget_timeout",
                message="undocumented_endpoint_validator timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_ssrf_candidate_detector(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "input_validation":
            errors.append(ValidationError(
                code="ssrf_candidate_worker_class_invalid",
                message="ssrf_candidate_detector requires worker_class input_validation.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "detect_ssrf_candidate_fields":
            errors.append(ValidationError(
                code="ssrf_candidate_strategy_invalid",
                message="ssrf_candidate_detector requires strategy detect_ssrf_candidate_fields.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "operation_id",
            "path_template",
            "method",
            "validation_mode",
            "candidate_fields",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="ssrf_candidate_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for ssrf_candidate_detector.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="ssrf_candidate_target_url_required",
                message="inputs.target_url is required for ssrf_candidate_detector.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="ssrf_candidate_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))

        operation_id = str(command.operation_id or inputs.get("operation_id") or "").strip()
        if not operation_id:
            errors.append(ValidationError(
                code="ssrf_candidate_operation_id_required",
                message="operation_id is required for ssrf_candidate_detector.",
            ))
        path_template = str(inputs.get("path_template") or "").strip()
        if not path_template:
            errors.append(ValidationError(
                code="ssrf_candidate_path_required",
                message="inputs.path_template is required for ssrf_candidate_detector.",
            ))

        validation_mode = str(inputs.get("validation_mode") or "ssrf_candidate_detection").strip()
        if validation_mode != "ssrf_candidate_detection":
            errors.append(ValidationError(
                code="ssrf_candidate_validation_mode_invalid",
                message="validation_mode must be ssrf_candidate_detection.",
                details={"validation_mode": validation_mode},
            ))
        if command.budget.max_requests > 0:
            errors.append(ValidationError(
                code="ssrf_candidate_budget_max_requests",
                message="ssrf_candidate_detector max_requests must be 0.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="ssrf_candidate_budget_timeout",
                message="ssrf_candidate_detector timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_auth_flow_detector(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "auth_context":
            errors.append(ValidationError(
                code="auth_flow_worker_class_invalid",
                message="auth_flow_detector requires worker_class auth_context.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "detect_auth_flow":
            errors.append(ValidationError(
                code="auth_flow_strategy_invalid",
                message="auth_flow_detector requires strategy detect_auth_flow.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {"validation_mode", "max_operations_scanned"}
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="auth_flow_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for auth_flow_detector.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        mode = str(inputs.get("validation_mode") or "auth_flow_detection").strip()
        if mode != "auth_flow_detection":
            errors.append(ValidationError(
                code="auth_flow_validation_mode_invalid",
                message="validation_mode must be auth_flow_detection.",
                details={"validation_mode": mode},
            ))

        mos = inputs.get("max_operations_scanned")
        if mos is not None:
            try:
                n = int(mos)
                if n < 1 or n > 500:
                    raise ValueError
            except Exception:
                errors.append(ValidationError(
                    code="auth_flow_max_operations_invalid",
                    message="max_operations_scanned must be an integer between 1 and 500.",
                ))

        if command.budget.max_requests > 0:
            errors.append(ValidationError(
                code="auth_flow_budget_max_requests",
                message="auth_flow_detector max_requests must be 0 (no HTTP execution).",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="auth_flow_budget_timeout",
                message="auth_flow_detector timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        _ = campaign

    def _validate_ssrf_probe(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass not in {"ssrf_external", "input_validation"}:
            errors.append(ValidationError(
                code="ssrf_probe_worker_class_invalid",
                message="ssrf_probe requires worker_class ssrf_external or input_validation.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "callback_ssrf_probe":
            errors.append(ValidationError(
                code="ssrf_probe_strategy_invalid",
                message="ssrf_probe requires strategy callback_ssrf_probe.",
            ))
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "validation_mode",
            "operation_id",
            "method",
            "path",
            "field_name",
            "field_path",
            "auth_mode",
            "auth_profile_id",
            "role_hint",
            "correlation_id",
            "request_draft",
            "required_body_fields",
            "allowed_body_fields",
            "body_field_summaries",
            "schema_summary_source",
            "ssrf_target_field",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="ssrf_probe_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for ssrf_probe.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {
                "authorization", "cookie", "token", "bearer", "password",
                "raw_secret", "raw_headers", "raw_body", "callback_base_url",
                "url", "request_url",
            }:
                errors.append(ValidationError(
                    code="ssrf_probe_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for ssrf_probe.",
                    details={"key": key},
                ))
        validation_mode = str(inputs.get("validation_mode") or "ssrf_callback_probe").strip() or "ssrf_callback_probe"
        if validation_mode != "ssrf_callback_probe":
            errors.append(ValidationError(
                code="ssrf_probe_validation_mode_invalid",
                message="validation_mode must be ssrf_callback_probe.",
                details={"validation_mode": validation_mode},
            ))
        if not str(inputs.get("operation_id") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_operation_id_required",
                message="inputs.operation_id is required for ssrf_probe.",
            ))
        if not str(inputs.get("method") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_method_required",
                message="inputs.method is required for ssrf_probe.",
            ))
        if not str(inputs.get("path") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_path_required",
                message="inputs.path is required for ssrf_probe.",
            ))
        if not str(inputs.get("field_name") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_field_name_required",
                message="inputs.field_name is required for ssrf_probe.",
            ))
        if not str(inputs.get("field_path") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_field_path_required",
                message="inputs.field_path is required for ssrf_probe.",
            ))
        auth_mode = str(inputs.get("auth_mode") or "unauthenticated").strip()
        if auth_mode not in {"unauthenticated", "authenticated"}:
            errors.append(ValidationError(
                code="ssrf_probe_auth_mode_invalid",
                message="inputs.auth_mode must be unauthenticated or authenticated.",
                details={"auth_mode": auth_mode},
            ))
        if auth_mode == "authenticated" and not str(inputs.get("auth_profile_id") or "").strip():
            errors.append(ValidationError(
                code="ssrf_probe_auth_profile_required",
                message="inputs.auth_profile_id is required for authenticated ssrf_probe.",
            ))
        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="ssrf_probe_budget_max_requests",
                message="ssrf_probe max_requests must be <= 1.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="ssrf_probe_budget_timeout",
                message="ssrf_probe timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        request_draft = inputs.get("request_draft")
        if request_draft is not None:
            if not isinstance(request_draft, dict):
                errors.append(ValidationError(
                    code="ssrf_probe_request_draft_invalid",
                    message="inputs.request_draft must be an object.",
                ))
            else:
                blob = json.dumps(request_draft, ensure_ascii=False).lower()
                for bad in (
                    "authorization", "cookie", "token", "password", "bearer",
                    "secret", "api_key", "raw_body", "raw_headers", "localhost",
                    "127.0.0.1", "0.0.0.0", "169.254.169.254", "file://", "gopher://", "ftp://",
                ):
                    if bad in blob:
                        errors.append(ValidationError(
                            code="ssrf_probe_request_draft_forbidden_content",
                            message="inputs.request_draft contains forbidden content.",
                            details={"forbidden": bad},
                        ))
                        break
        _ = campaign

    def _validate_test_account_materializer(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "auth_context":
            errors.append(ValidationError(
                code="test_account_materializer_worker_class_invalid",
                message="test_account_materializer requires worker_class auth_context.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "materialize_test_accounts":
            errors.append(ValidationError(
                code="test_account_materializer_strategy_invalid",
                message="test_account_materializer requires strategy materialize_test_accounts.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "signup_operation_id",
            "login_operation_id",
            "validation_mode",
            "max_accounts",
            "max_response_bytes",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="test_account_materializer_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for test_account_materializer.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="test_account_materializer_target_url_required",
                message="inputs.target_url is required for test_account_materializer.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="test_account_materializer_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))

        if not str(inputs.get("signup_operation_id") or "").strip():
            errors.append(ValidationError(
                code="test_account_materializer_signup_operation_required",
                message="signup_operation_id is required for test_account_materializer.",
            ))
        if not str(inputs.get("login_operation_id") or "").strip():
            errors.append(ValidationError(
                code="test_account_materializer_login_operation_required",
                message="login_operation_id is required for test_account_materializer.",
            ))

        validation_mode = str(inputs.get("validation_mode") or "test_account_materialization").strip()
        if validation_mode != "test_account_materialization":
            errors.append(ValidationError(
                code="test_account_materializer_validation_mode_invalid",
                message="validation_mode must be test_account_materialization.",
                details={"validation_mode": validation_mode},
            ))
        try:
            max_accounts = int(inputs.get("max_accounts") or 2)
        except Exception:
            max_accounts = 999
        if max_accounts < 1 or max_accounts > 2:
            errors.append(ValidationError(
                code="test_account_materializer_max_accounts_invalid",
                message="max_accounts must be between 1 and 2.",
                details={"max_accounts": inputs.get("max_accounts")},
            ))
        if command.budget.max_requests > 6:
            errors.append(ValidationError(
                code="test_account_materializer_budget_max_requests",
                message="test_account_materializer max_requests must be <= 6.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="test_account_materializer_budget_timeout",
                message="test_account_materializer timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_data_exposure_validator(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "access_control":
            errors.append(ValidationError(
                code="data_exposure_worker_class_invalid",
                message="data_exposure_validator requires worker_class access_control.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "validate_response_field_exposure":
            errors.append(ValidationError(
                code="data_exposure_strategy_invalid",
                message="data_exposure_validator requires strategy validate_response_field_exposure.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "request_url",
            "operation_id",
            "path_template",
            "method",
            "validation_mode",
            "max_response_bytes",
            "max_depth",
            "max_fields",
            "auth_profile_id",
            "auth_mode",
            "follow_same_origin_redirects",
            "max_redirects",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="data_exposure_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for data_exposure_validator.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {"authorization", "cookie", "token", "bearer", "raw_secret"}:
                errors.append(ValidationError(
                    code="data_exposure_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for data_exposure_validator.",
                    details={"key": key},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        request_url = str(inputs.get("request_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="data_exposure_target_url_required",
                message="inputs.target_url is required for data_exposure_validator.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="data_exposure_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        if not request_url:
            errors.append(ValidationError(
                code="data_exposure_request_url_required",
                message="inputs.request_url is required for data_exposure_validator.",
            ))

        method = str(inputs.get("method") or "GET").strip().upper() or "GET"
        if method != "GET":
            errors.append(ValidationError(
                code="data_exposure_method_not_allowed",
                message="data_exposure_validator supports only GET.",
                details={"method": method},
            ))

        validation_mode = str(
            inputs.get("validation_mode") or "response_field_inventory_check"
        ).strip() or "response_field_inventory_check"
        if validation_mode != "response_field_inventory_check":
            errors.append(ValidationError(
                code="data_exposure_validation_mode_invalid",
                message="validation_mode must be response_field_inventory_check.",
                details={"validation_mode": validation_mode},
            ))
        auth_mode = str(inputs.get("auth_mode") or "unauthenticated").strip() or "unauthenticated"
        if auth_mode not in {"unauthenticated", "authenticated"}:
            errors.append(ValidationError(
                code="data_exposure_auth_mode_invalid",
                message="auth_mode must be unauthenticated or authenticated.",
                details={"auth_mode": auth_mode},
            ))
        auth_profile_id = str(inputs.get("auth_profile_id") or "").strip()
        if auth_mode == "authenticated" and not auth_profile_id:
            errors.append(ValidationError(
                code="data_exposure_auth_profile_required",
                message="auth_profile_id is required when auth_mode=authenticated.",
            ))
        max_depth = int(inputs.get("max_depth") or 6)
        if max_depth > 6 or max_depth < 1:
            errors.append(ValidationError(
                code="data_exposure_max_depth_invalid",
                message="max_depth must be between 1 and 6.",
                details={"max_depth": max_depth},
            ))
        max_fields = int(inputs.get("max_fields") or 200)
        if max_fields > 200 or max_fields < 1:
            errors.append(ValidationError(
                code="data_exposure_max_fields_invalid",
                message="max_fields must be between 1 and 200.",
                details={"max_fields": max_fields},
            ))
        max_response_bytes = int(inputs.get("max_response_bytes") or 262144)
        if max_response_bytes > 524288 or max_response_bytes < 1024:
            errors.append(ValidationError(
                code="data_exposure_max_response_bytes_invalid",
                message="max_response_bytes must be between 1024 and 524288.",
                details={"max_response_bytes": max_response_bytes},
            ))
        follow_same_origin_redirects = inputs.get("follow_same_origin_redirects", True)
        if not isinstance(follow_same_origin_redirects, bool):
            errors.append(ValidationError(
                code="data_exposure_follow_redirects_invalid",
                message="follow_same_origin_redirects must be a boolean.",
                details={"follow_same_origin_redirects": follow_same_origin_redirects},
            ))
        max_redirects = int(inputs.get("max_redirects") or 2)
        if max_redirects < 0 or max_redirects > 2:
            errors.append(ValidationError(
                code="data_exposure_max_redirects_invalid",
                message="max_redirects must be between 0 and 2.",
                details={"max_redirects": max_redirects},
            ))

        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="data_exposure_budget_max_requests",
                message="data_exposure_validator max_requests must be <= 1.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="data_exposure_budget_timeout",
                message="data_exposure_validator timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_resource_instance_extractor(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "auth_context":
            errors.append(ValidationError(
                code="resource_instance_worker_class_invalid",
                message="resource_instance_extractor requires worker_class auth_context.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "extract_resource_instances":
            errors.append(ValidationError(
                code="resource_instance_strategy_invalid",
                message="resource_instance_extractor requires strategy extract_resource_instances.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "source_observation_id",
            "source_operation_id",
            "source_path",
            "auth_profile_id",
            "role_hint",
            "validation_mode",
            "max_instances",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="resource_instance_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for resource_instance_extractor.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {"authorization", "cookie", "token", "bearer", "password", "raw_secret", "object_id"}:
                errors.append(ValidationError(
                    code="resource_instance_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for resource_instance_extractor.",
                    details={"key": key},
                ))

        source_observation_id = str(inputs.get("source_observation_id") or "").strip()
        if not source_observation_id:
            errors.append(ValidationError(
                code="resource_instance_source_observation_required",
                message="inputs.source_observation_id is required for resource_instance_extractor.",
            ))

        validation_mode = str(inputs.get("validation_mode") or "resource_instance_extraction").strip() or "resource_instance_extraction"
        if validation_mode != "resource_instance_extraction":
            errors.append(ValidationError(
                code="resource_instance_validation_mode_invalid",
                message="validation_mode must be resource_instance_extraction.",
                details={"validation_mode": validation_mode},
            ))

        max_instances = int(inputs.get("max_instances") or 20)
        if max_instances < 1 or max_instances > 50:
            errors.append(ValidationError(
                code="resource_instance_max_instances_invalid",
                message="max_instances must be between 1 and 50.",
                details={"max_instances": max_instances},
            ))
        if command.budget.max_requests > 0:
            errors.append(ValidationError(
                code="resource_instance_budget_max_requests",
                message="resource_instance_extractor max_requests must be <= 0.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="resource_instance_budget_timeout",
                message="resource_instance_extractor timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_resource_seed_worker(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "auth_context":
            errors.append(ValidationError(
                code="resource_seed_worker_class_invalid",
                message="resource_seed_worker requires worker_class auth_context.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "seed_resource_instance":
            errors.append(ValidationError(
                code="resource_seed_strategy_invalid",
                message="resource_seed_worker requires strategy seed_resource_instance.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "validation_mode",
            "owner_auth_profile_id",
            "max_seed_attempts",
            "max_followup_requests",
            "seed_operation_id",
            "followup_operation_id",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="resource_seed_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for resource_seed_worker.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {"authorization", "cookie", "token", "bearer", "password", "raw_secret", "raw_body", "object_id"}:
                errors.append(ValidationError(
                    code="resource_seed_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for resource_seed_worker.",
                    details={"key": key},
                ))

        validation_mode = str(inputs.get("validation_mode") or "resource_seed").strip() or "resource_seed"
        if validation_mode != "resource_seed":
            errors.append(ValidationError(
                code="resource_seed_validation_mode_invalid",
                message="validation_mode must be resource_seed.",
                details={"validation_mode": validation_mode},
            ))
        owner_auth_profile_id = str(inputs.get("owner_auth_profile_id") or "").strip()
        if not owner_auth_profile_id:
            errors.append(ValidationError(
                code="resource_seed_owner_auth_profile_required",
                message="owner_auth_profile_id is required for resource_seed_worker.",
            ))

        try:
            max_seed_attempts = int(inputs.get("max_seed_attempts") or 1)
        except Exception:
            max_seed_attempts = 999
        if max_seed_attempts < 1 or max_seed_attempts > 3:
            errors.append(ValidationError(
                code="resource_seed_max_seed_attempts_invalid",
                message="max_seed_attempts must be between 1 and 3.",
                details={"max_seed_attempts": inputs.get("max_seed_attempts")},
            ))
        try:
            max_followup = int(inputs.get("max_followup_requests") or 1)
        except Exception:
            max_followup = 999
        if max_followup < 0 or max_followup > 1:
            errors.append(ValidationError(
                code="resource_seed_max_followup_requests_invalid",
                message="max_followup_requests must be between 0 and 1.",
                details={"max_followup_requests": inputs.get("max_followup_requests")},
            ))

        if command.budget.max_requests > 3:
            errors.append(ValidationError(
                code="resource_seed_budget_max_requests",
                message="resource_seed_worker max_requests must be <= 3.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="resource_seed_budget_timeout",
                message="resource_seed_worker timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        _ = campaign

    def _validate_js_endpoint_extractor(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "discovery_inventory":
            errors.append(ValidationError(
                code="js_extractor_worker_class_invalid",
                message="js_endpoint_extractor requires worker_class discovery_inventory.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "extract_js_endpoints":
            errors.append(ValidationError(
                code="js_extractor_strategy_invalid",
                message="js_endpoint_extractor requires strategy extract_js_endpoints.",
            ))

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "target_url",
            "js_url",
            "source_observation_id",
            "validation_mode",
            "max_js_bytes",
            "max_endpoints",
            "max_route_fragments",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="js_extractor_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for js_endpoint_extractor.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))

        target_url = str(inputs.get("target_url") or "").strip()
        js_url = str(inputs.get("js_url") or "").strip()
        if not target_url:
            errors.append(ValidationError(
                code="js_extractor_target_url_required",
                message="inputs.target_url is required for js_endpoint_extractor.",
            ))
        else:
            trusted = str(campaign.target_url or "").rstrip("/")
            if target_url.rstrip("/") != trusted:
                errors.append(ValidationError(
                    code="js_extractor_target_url_mismatch",
                    message="inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
                ))
        if not js_url:
            errors.append(ValidationError(
                code="js_extractor_js_url_required",
                message="inputs.js_url is required for js_endpoint_extractor.",
            ))
        else:
            parsed = urlparse(js_url)
            path = (parsed.path or js_url.split("?", 1)[0].split("#", 1)[0]).lower()
            if not path.endswith(".js"):
                errors.append(ValidationError(
                    code="js_extractor_url_not_js",
                    message="js_endpoint_extractor requires js_url ending with .js.",
                    details={"js_url": js_url},
                ))

        validation_mode = str(
            inputs.get("validation_mode") or "static_js_endpoint_extraction"
        ).strip()
        if validation_mode and validation_mode != "static_js_endpoint_extraction":
            errors.append(ValidationError(
                code="js_extractor_validation_mode_invalid",
                message="validation_mode must be static_js_endpoint_extraction in MVP.",
            ))

        max_js_bytes = int(inputs.get("max_js_bytes") or 3000000)
        if max_js_bytes > 3000000:
            errors.append(ValidationError(
                code="js_extractor_max_js_bytes_invalid",
                message="js_endpoint_extractor max_js_bytes must be <= 3000000.",
                details={"max_js_bytes": max_js_bytes},
            ))
        max_endpoints = int(inputs.get("max_endpoints") or 50)
        if max_endpoints > 100:
            errors.append(ValidationError(
                code="js_extractor_max_endpoints_invalid",
                message="js_endpoint_extractor max_endpoints must be <= 100.",
                details={"max_endpoints": max_endpoints},
            ))
        max_route_fragments = int(inputs.get("max_route_fragments") or 100)
        if max_route_fragments > 100:
            errors.append(ValidationError(
                code="js_extractor_max_route_fragments_invalid",
                message="js_endpoint_extractor max_route_fragments must be <= 100.",
                details={"max_route_fragments": max_route_fragments},
            ))
        if command.budget.max_requests > 1:
            errors.append(ValidationError(
                code="js_extractor_budget_max_requests",
                message="js_endpoint_extractor max_requests must be <= 1.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="js_extractor_budget_timeout",
                message="js_endpoint_extractor timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))

    def _validate_bola_object_pair_builder(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "access_control":
            errors.append(ValidationError(
                code="bola_object_pair_worker_class_invalid",
                message="bola_object_pair_builder requires worker_class access_control.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "build_bola_object_pairs":
            errors.append(ValidationError(
                code="bola_object_pair_strategy_invalid",
                message="bola_object_pair_builder requires strategy build_bola_object_pairs.",
            ))
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {
            "validation_mode",
            "owner_auth_profile_id",
            "attacker_auth_profile_id",
            "resource_instances_count",
            "object_refs_count",
            "resource_types",
            "max_object_pairs",
            "object_ref_id",
            "object_id_ref",
        }
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="bola_object_pair_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for bola_object_pair_builder.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {"authorization", "cookie", "token", "bearer", "password", "raw_secret", "raw_body", "object_id", "raw_object_id"}:
                errors.append(ValidationError(
                    code="bola_object_pair_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for bola_object_pair_builder.",
                    details={"key": key},
                ))
        vm = str(inputs.get("validation_mode") or "bola_object_pair_building").strip() or "bola_object_pair_building"
        if vm != "bola_object_pair_building":
            errors.append(ValidationError(
                code="bola_object_pair_validation_mode_invalid",
                message="validation_mode must be bola_object_pair_building.",
                details={"validation_mode": vm},
            ))
        if not str(inputs.get("owner_auth_profile_id") or "").strip():
            errors.append(ValidationError(
                code="bola_object_pair_owner_auth_profile_required",
                message="owner_auth_profile_id is required for bola_object_pair_builder.",
            ))
        if not str(inputs.get("attacker_auth_profile_id") or "").strip():
            errors.append(ValidationError(
                code="bola_object_pair_attacker_auth_profile_required",
                message="attacker_auth_profile_id is required for bola_object_pair_builder.",
            ))
        try:
            max_pairs = int(inputs.get("max_object_pairs") or 10)
        except Exception:
            max_pairs = 999
        if max_pairs < 1 or max_pairs > 10:
            errors.append(ValidationError(
                code="bola_object_pair_max_pairs_invalid",
                message="max_object_pairs must be between 1 and 10.",
                details={"max_object_pairs": inputs.get("max_object_pairs")},
            ))
        if command.budget.max_requests > 0:
            errors.append(ValidationError(
                code="bola_object_pair_budget_max_requests",
                message="bola_object_pair_builder max_requests must be <= 0.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="bola_object_pair_budget_timeout",
                message="bola_object_pair_builder timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        _ = campaign

    def _validate_bola_replay_probe(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        errors: list[ValidationError],
    ) -> None:
        nclass = normalize_worker_class(command.worker_class)
        if nclass != "access_control":
            errors.append(ValidationError(
                code="bola_replay_worker_class_invalid",
                message="bola_replay_probe requires worker_class access_control.",
                details={"worker_class": command.worker_class},
            ))
        if (command.strategy or "").strip() != "replay_bola_object_pair":
            errors.append(ValidationError(
                code="bola_replay_strategy_invalid",
                message="bola_replay_probe requires strategy replay_bola_object_pair.",
            ))
        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        allowed_keys = {"validation_mode", "object_pair_id", "max_requests"}
        for key in inputs:
            if key not in allowed_keys:
                errors.append(ValidationError(
                    code="bola_replay_inputs_unknown_key",
                    message=f"inputs.{key} is not allowed for bola_replay_probe.",
                    details={"key": key, "allowed": sorted(allowed_keys)},
                ))
            lowered = str(key).strip().lower()
            if lowered in {"authorization", "cookie", "token", "bearer", "password", "raw_secret", "raw_body", "object_id", "raw_object_id", "url", "path", "request_url"}:
                errors.append(ValidationError(
                    code="bola_replay_forbidden_secret_input",
                    message=f"inputs.{key} is not allowed for bola_replay_probe.",
                    details={"key": key},
                ))
        validation_mode = str(inputs.get("validation_mode") or "bola_replay").strip() or "bola_replay"
        if validation_mode != "bola_replay":
            errors.append(ValidationError(
                code="bola_replay_validation_mode_invalid",
                message="validation_mode must be bola_replay.",
                details={"validation_mode": validation_mode},
            ))
        if not str(inputs.get("object_pair_id") or "").strip():
            errors.append(ValidationError(
                code="bola_replay_object_pair_id_required",
                message="object_pair_id is required for bola_replay_probe.",
            ))
        try:
            max_requests_input = int(inputs.get("max_requests") or 1)
        except Exception:
            max_requests_input = 999
        if max_requests_input < 1 or max_requests_input > 2:
            errors.append(ValidationError(
                code="bola_replay_input_max_requests_invalid",
                message="inputs.max_requests must be <= 2.",
                details={"max_requests": inputs.get("max_requests")},
            ))
        if command.budget.max_requests > 2:
            errors.append(ValidationError(
                code="bola_replay_budget_max_requests",
                message="bola_replay_probe max_requests must be <= 2.",
                details={"max_requests": command.budget.max_requests},
            ))
        if command.budget.timeout_sec > 15:
            errors.append(ValidationError(
                code="bola_replay_budget_timeout",
                message="bola_replay_probe timeout_sec must be <= 15.",
                details={"timeout_sec": command.budget.timeout_sec},
            ))
        _ = campaign

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
