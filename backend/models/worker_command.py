"""Phase 4 — WorkerCommand normalization data contracts.

WorkerCommand is the single way an agent/worker asks the backend
to execute a tool. CommandValidator validates the command before
acceptance; Phase 5 ToolExecutor will consume accepted commands.
"""
from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class WorkerClass(str, Enum):
    access_control = "access_control"
    contract_fuzzing = "contract_fuzzing"
    stateful_flow = "stateful_flow"
    discovery_inventory = "discovery_inventory"
    misconfiguration = "misconfiguration"
    ssrf_external = "ssrf_external"


WORKER_CLASS_COMPAT: dict[str, str] = {
    "authorization": "access_control",
    "injection": "contract_fuzzing",
    "business_logic": "stateful_flow",
}

ALLOWED_TOOLS_BY_WORKER_CLASS: dict[str, list[str]] = {
    "access_control": [
        "custom_request_executor",
        "auth_test_access",
        "replay_http_sequence",
        "property_mutation_test",
        "akto_inventory_discovery",
        "akto_authz_scan",
        "astf_top10_suite",
        "jwt_tool",
        "zap",
    ],
    "contract_fuzzing": [
        "schemathesis_negative_test",
        "schemathesis_stateful_test",
        "cats_fuzz_test",
        "custom_request_executor",
        "injection_test",
        "reflection_probe",
        "path_fuzz_probe",
        "data_exposure_test",
        "runtime_inventory",
        "resource_abuse_test",
        "astf_top10_suite",
    ],
    "stateful_flow": [
        "restler_compile",
        "restler_fuzz",
        "restler_replay",
        "schemathesis_stateful_test",
        "replay_http_sequence",
        "logic_test",
        "bounded_burst_helper",
        "resource_abuse_test",
        "runtime_inventory",
        "version_diff_test",
        "misconfiguration_test",
        "akto_inventory_discovery",
        "akto_authz_scan",
        "cats_fuzz_test",
        "astf_top10_suite",
        "custom_request_executor",
    ],
    "discovery_inventory": [
        "httpx",
        "ffuf",
        "kiterunner",
        "arjun",
        "runtime_inventory",
        "import_har_capture",
        "capture_authenticated_traffic",
        "capture_anonymous_traffic",
        "zap_spider",
        "playwright_capture",
        "mitmproxy_import",
    ],
    "misconfiguration": [
        "nuclei",
        "zap",
        "httpx",
        "custom_request_executor",
        "custom_header_checker",
    ],
    "ssrf_external": [
        "custom_ssrf_checker",
        "nuclei",
        "custom_request_executor",
    ],
}

ALL_KNOWN_TOOLS: set[str] = set()
for _tools in ALLOWED_TOOLS_BY_WORKER_CLASS.values():
    ALL_KNOWN_TOOLS.update(_tools)


def normalize_worker_class(raw: str) -> str | None:
    lowered = (raw or "").strip().lower()
    if lowered in {wc.value for wc in WorkerClass}:
        return lowered
    return WORKER_CLASS_COMPAT.get(lowered)


class CommandBudget(BaseModel):
    max_requests: int = 10
    timeout_sec: int = 60


class WorkerCommand(BaseModel):
    schema_version: str = "worker-command/v1"
    command_id: str = ""
    campaign_id: str
    task_id: str = ""
    worker_class: str
    strategy: str
    tool_name: str
    operation_id: str = ""
    seed_request_id: str = ""
    inputs: dict[str, Any] = Field(default_factory=dict)
    budget: CommandBudget = Field(default_factory=CommandBudget)
    success_criteria: list[str] = Field(default_factory=list)


class ValidationError(BaseModel):
    code: str
    message: str
    details: dict[str, Any] = Field(default_factory=dict)


class ValidationResult(BaseModel):
    valid: bool
    command_id: str = ""
    campaign_id: str = ""
    task_id: str = ""
    normalized_worker_class: str = ""
    errors: list[ValidationError] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class CommandSubmitResponse(BaseModel):
    command_id: str
    campaign_id: str
    task_id: str = ""
    status: str = "accepted"
    validation: ValidationResult = Field(default_factory=ValidationResult)
