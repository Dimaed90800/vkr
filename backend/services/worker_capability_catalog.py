"""Phase 17A.1 — Static catalog of worker/tool capabilities (metadata only)."""
from __future__ import annotations

try:
    from backend.models.worker_capability import (
        WorkerCapability,
        WorkerCapabilityCatalogResponse,
    )
except ModuleNotFoundError:  # pragma: no cover
    from models.worker_capability import (
        WorkerCapability,
        WorkerCapabilityCatalogResponse,
    )

_WORKERS: tuple[WorkerCapability, ...] = (
    WorkerCapability(
        worker_name="zap_discovery_passive",
        tool_name="zap_discovery_passive",
        worker_class="discovery_inventory",
        scenario_types=["discovery_expansion", "passive_signal_validation"],
        observation_types=["zap_alert", "discovered_endpoint"],
        owasp_categories=[
            "API8_SECURITY_MISCONFIGURATION",
            "API9_IMPROPER_INVENTORY_MANAGEMENT",
        ],
        status="implemented",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        risk_level="medium",
        notes="Passive discovery; raw zap_alert/discovered_endpoint are not judge-ready by default.",
    ),
    WorkerCapability(
        worker_name="security_header_validator",
        tool_name="security_header_validator",
        worker_class="misconfiguration",
        scenario_types=["security_header_validation", "passive_signal_validation"],
        observation_types=["validated_security_header_issue"],
        owasp_categories=["API8_SECURITY_MISCONFIGURATION"],
        status="implemented",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_auth=False,
        requires_seed=False,
        requires_openapi=False,
        requires_corpus=False,
        risk_level="low",
        notes="Validated header replay path to EvidencePack and Dify Judge.",
    ),
    WorkerCapability(
        worker_name="schemathesis_negative_test",
        tool_name="schemathesis_negative_test",
        worker_class="contract_fuzzing",
        scenario_types=["schema_negative_testing"],
        observation_types=["schema_mismatch"],
        owasp_categories=[
            "API4_UNRESTRICTED_RESOURCE_CONSUMPTION",
            "API8_SECURITY_MISCONFIGURATION",
        ],
        status="implemented",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_openapi=True,
        risk_level="medium",
        notes="ScenarioPlan-driven negative schema testing; EvidencePack for strong signals.",
    ),
    WorkerCapability(
        worker_name="bola_replay_probe",
        tool_name="bola_replay_probe",
        worker_class="access_control",
        scenario_types=["access_control_bola"],
        observation_types=["cross_role_access_signal"],
        owasp_categories=["API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_auth=True,
        requires_seed=True,
        requires_corpus=True,
        risk_level="high",
        notes="Requires roles, object_pairs, and corpus seeds for full planner + Dify loop.",
    ),
    WorkerCapability(
        worker_name="http_replay_executor",
        tool_name="http_replay_executor",
        worker_class="access_control",
        scenario_types=[],
        observation_types=[],
        owasp_categories=[],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        risk_level="medium",
        notes="Adapter-backed replay; not primary ScenarioPlan/Dify E2E worker yet.",
    ),
    WorkerCapability(
        worker_name="safe_injection_probe_worker",
        tool_name="injection_test",
        worker_class="contract_fuzzing",
        scenario_types=["injection_testing"],
        observation_types=["injection_signal"],
        owasp_categories=[
            "API8_SECURITY_MISCONFIGURATION",
            "API10_UNSAFE_CONSUMPTION_OF_APIS",
        ],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_openapi=False,
        requires_seed=False,
        requires_corpus=False,
        risk_level="high",
        notes=(
            "Phase 17B-1/2: bounded injection_test; injection_signal triage and potential_injection "
            "evidence path. Phase 17B-3b: ScenarioPlanCompiler emits injection_test candidates; "
            "full autonomous Dify E2E with compiler-driven selection still optional."
        ),
    ),
    WorkerCapability(
        worker_name="mass_assignment_validator",
        tool_name="property_mutation_test",
        worker_class="access_control",
        scenario_types=["mass_assignment"],
        observation_types=["mass_assignment_signal"],
        owasp_categories=["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_openapi=True,
        requires_seed=False,
        requires_corpus=False,
        risk_level="high",
        notes=(
            "Phase 18C: diagnostic-only property_mutation_test emits mass_assignment_signal and supports "
            "triage/evidence/judge path; confirmed finding remains blocked unless runtime_effect_proven:true. "
            "Active mutation behavior is intentionally not implemented."
        ),
    ),
    WorkerCapability(
        worker_name="data_exposure_validator",
        tool_name="data_exposure_validator",
        worker_class="access_control",
        scenario_types=["excessive_data_exposure", "mass_assignment"],
        observation_types=[
            "response_field_inventory",
            "data_exposure_signal",
            "data_exposure_probe_result",
        ],
        owasp_categories=["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        requires_openapi=True,
        requires_auth=False,
        requires_corpus=False,
        risk_level="medium",
        notes=(
            "Coverage-3A-1: bounded GET JSON field-name inventory; classifies sensitive names only, "
            "never stores raw values, headers, cookies, or tokens. "
            "data_exposure_probe_result is store-only diagnostic (per-run outcome: non_200, non_json, "
            "empty body, parse failure, no fields, inventory, sensitive hit)."
        ),
    ),
    WorkerCapability(
        worker_name="bfla_validator",
        tool_name="auth_test_access",
        worker_class="access_control",
        scenario_types=["access_control_bfla"],
        observation_types=["auth_anomaly", "cross_role_access_signal"],
        owasp_categories=["API5_BROKEN_FUNCTION_LEVEL_AUTHORIZATION"],
        status="planned",
        adapter_available=False,
        execution_mode="sync",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_auth=True,
        requires_corpus=True,
        risk_level="high",
        notes="Planned function-level authorization replay.",
    ),
    WorkerCapability(
        worker_name="cors_validator",
        tool_name="cors_validator",
        worker_class="misconfiguration",
        scenario_types=["passive_signal_validation"],
        observation_types=["validated_cors_issue"],
        owasp_categories=["API8_SECURITY_MISCONFIGURATION"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        risk_level="medium",
        notes=(
            "Phase 19A-1: bounded cors_validator replay with fixed origin probe; "
            "stores sanitized CORS policy metadata only (no raw headers/body/cookies/tokens). "
            "MVP emits finding-capable signal only for strong CORS issues."
        ),
    ),
    WorkerCapability(
        worker_name="cookie_flag_validator",
        tool_name="cookie_flag_validator",
        worker_class="misconfiguration",
        scenario_types=["passive_signal_validation"],
        observation_types=["validated_cookie_flag_issue"],
        owasp_categories=["API8_SECURITY_MISCONFIGURATION"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        risk_level="medium",
        notes=(
            "Phase API8-2: bounded cookie_flag_validator replay with sanitized Set-Cookie flag metadata only; "
            "no raw Set-Cookie/header/body/token values are stored."
        ),
    ),
    WorkerCapability(
        worker_name="ssrf_candidate_detector",
        tool_name="ssrf_candidate_detector",
        worker_class="input_validation",
        scenario_types=["ssrf_candidate_detection"],
        observation_types=["ssrf_candidate_signal"],
        owasp_categories=["API7_SERVER_SIDE_REQUEST_FORGERY"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=False,
        requires_openapi=True,
        risk_level="low",
        notes=(
            "Diagnostic-only SSRF candidate detector; inspects safe OpenAPI-derived field names only, "
            "does not perform network SSRF probes, callbacks, or raw request/response storage."
        ),
    ),
    WorkerCapability(
        worker_name="auth_flow_detector",
        tool_name="auth_flow_detector",
        worker_class="auth_context",
        scenario_types=["auth_flow_detection"],
        observation_types=["auth_flow_signal"],
        owasp_categories=["API2_AUTH"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=False,
        requires_openapi=True,
        requires_auth=False,
        requires_corpus=False,
        risk_level="low",
        notes=(
            "Diagnostic-only: detects signup/login/token/profile candidates from OpenAPI graph metadata; "
            "does not execute login/signup or store secrets."
        ),
    ),
    WorkerCapability(
        worker_name="test_account_materializer",
        tool_name="test_account_materializer",
        worker_class="auth_context",
        scenario_types=["auth_context_materialization"],
        observation_types=["test_account_materialization_result"],
        owasp_categories=["API2_AUTH"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        requires_openapi=True,
        risk_level="medium",
        notes=(
            "Context-producing only: creates bounded owner/attacker test accounts and stores only runtime "
            "auth profile refs plus sanitized metadata; no raw passwords, tokens, cookies, headers, or bodies."
        ),
    ),
    WorkerCapability(
        worker_name="undocumented_endpoint_validator",
        tool_name="undocumented_endpoint_validator",
        worker_class="discovery_inventory",
        scenario_types=["passive_signal_validation", "inventory_gap_validation"],
        observation_types=["undocumented_endpoint_signal"],
        owasp_categories=["API9_IMPROPER_INVENTORY_MANAGEMENT"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        risk_level="low",
        notes=(
            "Safe one-shot replay for runtime-discovered endpoints that are absent from the OpenAPI graph; "
            "stores only method/path/status metadata and no raw body/header/cookie/token data."
        ),
    ),
    WorkerCapability(
        worker_name="js_endpoint_extractor",
        tool_name="js_endpoint_extractor",
        worker_class="discovery_inventory",
        scenario_types=["discovery_expansion", "inventory_gap_validation"],
        observation_types=["discovered_endpoint", "js_endpoint_extraction_result"],
        owasp_categories=["API9_IMPROPER_INVENTORY_MANAGEMENT"],
        status="partial",
        adapter_available=True,
        execution_mode="sync",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        risk_level="low",
        notes=(
            "Surface expansion only: extracts API-like paths from in-scope JS assets without executing JS; "
            "emits sanitized discovered_endpoint observations and does not store raw JS/header/body/token data."
        ),
    ),
    WorkerCapability(
        worker_name="rate_limit_validator",
        tool_name="rate_limit_validator",
        worker_class="stateful_flow",
        scenario_types=[],
        observation_types=["timeout_signal"],
        owasp_categories=["API4_UNRESTRICTED_RESOURCE_CONSUMPTION"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_corpus=True,
        risk_level="high",
        notes="Planned bounded burst / rate-limit behavior probe; strict budgets required.",
    ),
    WorkerCapability(
        worker_name="business_logic_sequence_worker",
        tool_name="replay_http_sequence",
        worker_class="stateful_flow",
        scenario_types=[],
        observation_types=["state_changed_after_invalid_payload"],
        owasp_categories=["API6_UNRESTRICTED_ACCESS_TO_SENSITIVE_BUSINESS_FLOWS"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_corpus=True,
        risk_level="high",
        notes="Planned multi-step replay; high flakiness and scope risk.",
    ),
    WorkerCapability(
        worker_name="nuclei_signal_worker",
        tool_name="nuclei",
        worker_class="misconfiguration",
        scenario_types=["passive_signal_validation", "discovery_expansion"],
        observation_types=["nuclei_match"],
        owasp_categories=["API8_SECURITY_MISCONFIGURATION"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=True,
        evidence_support=True,
        judge_support=True,
        risk_level="medium",
        notes="Planned nuclei as normalized signals only; no direct findings from templates alone.",
    ),
    WorkerCapability(
        worker_name="httpx_discovery_worker",
        tool_name="httpx",
        worker_class="discovery_inventory",
        scenario_types=["discovery_expansion"],
        observation_types=["discovered_endpoint"],
        owasp_categories=["API9_IMPROPER_INVENTORY_MANAGEMENT"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        requires_corpus=False,
        risk_level="medium",
        notes="Planned httpx-based inventory expansion with host scope enforcement.",
    ),
    WorkerCapability(
        worker_name="ffuf_discovery_worker",
        tool_name="ffuf",
        worker_class="discovery_inventory",
        scenario_types=["discovery_expansion"],
        observation_types=["discovered_endpoint", "hidden_parameter"],
        owasp_categories=["API9_IMPROPER_INVENTORY_MANAGEMENT"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=True,
        evidence_support=False,
        judge_support=False,
        risk_level="high",
        notes="Planned ffuf discovery; strict wordlist and host allowlists required.",
    ),
    WorkerCapability(
        worker_name="restler_fuzz_worker",
        tool_name="restler_fuzz",
        worker_class="stateful_flow",
        scenario_types=["schema_negative_testing"],
        observation_types=["schema_mismatch", "unexpected_500"],
        owasp_categories=["API8_SECURITY_MISCONFIGURATION"],
        status="planned",
        adapter_available=False,
        execution_mode="async",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_openapi=True,
        requires_corpus=True,
        risk_level="high",
        notes="Planned long-running RESTler fuzz via ToolRun; not for thin Dify loop without budget.",
    ),
    WorkerCapability(
        worker_name="auth_materialization_worker",
        tool_name="",
        worker_class="access_control",
        scenario_types=["access_control_bola", "access_control_bfla"],
        observation_types=[],
        owasp_categories=[],
        status="planned",
        adapter_available=False,
        execution_mode="none",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_auth=True,
        requires_corpus=True,
        risk_level="medium",
        notes="Planned campaign/corpus service to materialize auth profiles; not a ToolExecutor tool.",
    ),
    WorkerCapability(
        worker_name="object_seed_materialization_worker",
        tool_name="",
        worker_class="access_control",
        scenario_types=["access_control_bola"],
        observation_types=[],
        owasp_categories=["API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"],
        status="planned",
        adapter_available=False,
        execution_mode="none",
        triage_support=False,
        evidence_support=False,
        judge_support=False,
        requires_corpus=True,
        requires_openapi=True,
        risk_level="medium",
        notes="Planned derivation of object_pairs / seeds from graph+corpus; not a ToolExecutor tool.",
    ),
)


class WorkerCapabilityCatalog:
    """Read-only catalog; does not consult live ToolRuns or campaigns."""

    __slots__ = ()

    def list_capabilities(self) -> list[WorkerCapability]:
        return list(_WORKERS)

    def get_by_tool_name(self, tool_name: str) -> WorkerCapability | None:
        key = (tool_name or "").strip()
        if not key:
            return None
        for w in _WORKERS:
            if w.tool_name == key:
                return w
        return None

    def get_by_worker_name(self, worker_name: str) -> WorkerCapability | None:
        key = (worker_name or "").strip().lower()
        if not key:
            return None
        for w in _WORKERS:
            if w.worker_name.lower() == key:
                return w
        return None

    def filter_by_status(self, status: str) -> list[WorkerCapability]:
        s = (status or "").strip().lower()
        return [w for w in _WORKERS if w.status == s]

    def filter_by_scenario_type(self, scenario_type: str) -> list[WorkerCapability]:
        st = (scenario_type or "").strip()
        if not st:
            return []
        return [w for w in _WORKERS if st in w.scenario_types]

    def response(self) -> WorkerCapabilityCatalogResponse:
        workers = self.list_capabilities()
        counts: dict[str, int] = {}
        for w in workers:
            counts[w.status] = counts.get(w.status, 0) + 1
        return WorkerCapabilityCatalogResponse(workers=workers, counts=counts)
