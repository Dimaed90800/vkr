"""Phase 12A — backend WorkerCommand planner tests."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation, ObservationType, SecurityRelevance
from backend.models.api_graph import ApiGraph, Operation
from backend.models.planner import PlannerRequest
from backend.models.tool_run import (
    ToolExecutionMode,
    ToolResult,
    ToolResultObservationLite,
    ToolRun,
    ToolRunStatus,
)
from backend.services.command_validator import CommandValidator
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.injection_scenario_parameter_candidates import INJECTION_COMPILER_PAYLOAD_FAMILIES
from backend.services.llm_candidate_advisor import LlmCandidateAdvisor
from backend.services.planner_service import PlannerService
from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "corpus_items", "corpus_by_campaign", "resource_instances",
        "resources_by_campaign", "graphs_by_campaign", "commands",
        "commands_by_campaign", "command_fingerprints", "tool_runs",
        "tool_runs_by_campaign", "tool_results", "artifacts",
        "artifacts_by_run", "observations", "observations_by_campaign",
        "observations_by_tool_run", "verification_plans",
        "verification_plans_by_campaign", "evidence_packs",
        "evidence_packs_by_campaign", "evidence_packs_by_observation",
        "evidence_packs_by_verification_plan", "judge_decisions",
        "judge_decisions_by_campaign", "judge_decisions_by_evidence",
        "confirmed_findings", "confirmed_findings_by_campaign",
        "findings_by_fingerprint", "evidence_pack_apply_meta",
        "observation_apply_meta", "auth_profiles", "auth_profiles_by_campaign",
        "runtime_token_secrets", "runtime_credential_secrets",
        "runtime_response_json_secrets", "runtime_object_id_secrets",
        "runtime_resource_instances", "runtime_resource_instances_by_campaign",
        "runtime_bola_object_pairs", "runtime_bola_object_pairs_by_campaign",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _campaign(
    campaign_id: str = "cmp_plan",
    *,
    allowed_hosts: list[str] | None = None,
    max_duration_sec: int = 1800,
    openapi_url: str | None = None,
) -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://target.local",
        openapi_url=openapi_url,
        allowed_hosts=["target.local"] if allowed_hosts is None else allowed_hosts,
        roles_json=[
            {"name": "owner", "headers": {"X-Role": "owner"}},
            {"name": "attacker", "headers": {"X-Role": "attacker"}},
        ],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=max_duration_sec),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _store_graph_vehicle_op(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
                method="GET",
                path_template="/api/v1/vehicles/{vehicleId}",
                owasp_candidates=["API1_BOLA"],
                risk_hints=["object_id_in_path"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _schema_scenario_payload(
    *,
    scenario_id: str = "scn_schema",
    operation_ids: list[str] | None = None,
    candidate_workers: list[str] | None = None,
    rationale: str = "schema test",
    status: str = "accepted",
    scenario_type: str = "schema_negative_testing",
) -> dict:
    return {
        "scenario_id": scenario_id,
        "status": status,
        "scenario_type": scenario_type,
        "vulnerability_classes": ["SCHEMA"],
        "operation_ids": operation_ids or ["op_GET_/api/v1/vehicles/{vehicleId}"],
        "resource_type": "",
        "required_preconditions": ["openapi_schema"],
        "candidate_workers": candidate_workers or ["schemathesis_negative_test"],
        "confidence": 0.7,
        "rationale": rationale,
        "blocking_codes": [],
        "errors": [],
        "warnings": [],
    }


def _injection_scenario_payload(
    *,
    scenario_id: str = "scn_inj",
    operation_ids: list[str] | None = None,
    rationale: str = "injection probe from graph",
    status: str = "accepted",
    resource_type: str = "",
) -> dict:
    return {
        "scenario_id": scenario_id,
        "status": status,
        "scenario_type": "injection_testing",
        "vulnerability_classes": ["INJECTION"],
        "operation_ids": operation_ids or ["op_GET_/api/v1/search"],
        "resource_type": resource_type,
        "required_preconditions": [
            "openapi_schema",
            "parameter_context",
            "safe_payload_allowlist",
        ],
        "candidate_workers": ["injection_test"],
        "confidence": 0.4,
        "rationale": rationale,
        "blocking_codes": [],
        "errors": [],
        "warnings": [],
    }


def _mass_assignment_scenario_payload(
    *,
    scenario_id: str = "scn_mass",
    operation_ids: list[str] | None = None,
    rationale: str = "mass assignment diagnostic probe",
    status: str = "accepted",
) -> dict:
    return {
        "scenario_id": scenario_id,
        "status": status,
        "scenario_type": "mass_assignment",
        "vulnerability_classes": ["BOPLA"],
        "operation_ids": operation_ids or ["op_PATCH_/api/v1/users/{userId}"],
        "resource_type": "user",
        "required_preconditions": ["openapi_schema", "parameter_context"],
        "candidate_workers": ["property_mutation_test"],
        "confidence": 0.45,
        "rationale": rationale,
        "blocking_codes": [],
        "errors": [],
        "warnings": [],
    }


def _store_graph_search_get(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/search",
                method="GET",
                path_template="/api/v1/search",
                query_params=["q", "limit"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _store_graph_mass_assignment_patch(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_PATCH_/api/v1/users/{userId}",
                method="PATCH",
                path_template="/api/v1/users/{userId}",
                body_fields=["displayName", "isAdmin", "owner_id", "description"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _store_corpus_seed(
    *,
    campaign_id: str = "cmp_plan",
    request_id: str = "req_seed_1",
    operation_id: str = "op_PATCH_/api/v1/users/{userId}",
    method: str = "PATCH",
    path_template: str = "/api/v1/users/{userId}",
    status_code: int = 200,
    classification: str = "successful_seed",
) -> None:
    memory_store.store_corpus_item(
        request_id,
        campaign_id,
        {
            "request_id": request_id,
            "campaign_id": campaign_id,
            "operation_id": operation_id,
            "method": method,
            "path_template": path_template,
            "status_code": status_code,
            "classification": classification,
        },
    )


def _store_graph_search_sensitive_mixed(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/search",
                method="GET",
                path_template="/api/v1/search",
                query_params=["token", "password", "q"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _store_graph_search_sensitive_only(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/search",
                method="GET",
                path_template="/api/v1/search",
                query_params=["access_token", "api_key"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _store_graph_post_with_query(campaign_id: str = "cmp_plan") -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id="op_POST_/api/v1/search",
                method="POST",
                path_template="/api/v1/search",
                query_params=["q"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _bola_pair(**overrides) -> dict:
    data = {
        "object_id": "veh_123",
        "attacker_own_object_id": "veh_456",
        "object_url": "http://target.local/api/v1/vehicles/veh_123",
        "attacker_own_object_url": "http://target.local/api/v1/vehicles/veh_456",
        "collection_url": "http://target.local/api/v1/vehicles",
        "owner_role": "owner",
        "attacker_role": "attacker",
        "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
        "path_template": "/api/v1/vehicles/{vehicleId}",
        "collection_path_template": "/api/v1/vehicles",
    }
    data.update(overrides)
    return data


def _request_with_bola(**overrides) -> PlannerRequest:
    data = {
        "zap": {"enabled": False},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
    }
    data.update(overrides)
    return PlannerRequest.model_validate(data)


def _store_runtime_bola_pair(
    *,
    campaign_id: str = "cmp_plan",
    object_pair_id: str = "objpair_veh_1",
    target_operation_id: str = "op_GET_/api/v1/vehicles/{vehicleId}",
    target_path_template: str = "/api/v1/vehicles/{vehicleId}",
    target_method: str = "GET",
    path_param_name: str = "vehicleId",
    confidence: str = "high",
    resource_type: str = "vehicle",
) -> None:
    memory_store.store_runtime_bola_object_pair(
        object_pair_id,
        campaign_id,
        {
            "object_pair_id": object_pair_id,
            "campaign_id": campaign_id,
            "resource_type": resource_type,
            "object_ref_id": "objref_veh_1",
            "object_id_ref": "objidref_veh_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": target_operation_id,
            "target_path_template": target_path_template,
            "target_method": target_method,
            "path_param_name": path_param_name,
            "confidence": confidence,
            "created_by": "bola_object_pair_builder",
            "reason_codes": ["path_param_resource_match"],
        },
    )


def _store_tool_run(
    *,
    tool_run_id: str = "toolrun_existing",
    campaign_id: str = "cmp_plan",
    tool_name: str = "zap_discovery_passive",
    status: ToolRunStatus = ToolRunStatus.finished,
) -> ToolRun:
    run = ToolRun(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name=tool_name,
        execution_mode=ToolExecutionMode.sync,
        status=status,
        result_ready=True,
    )
    memory_store.store_tool_run(tool_run_id, campaign_id, run.model_dump(mode="json"))
    return run


def _store_command(
    *,
    command_id: str,
    campaign_id: str,
    inputs: dict,
    tool_name: str = "zap_discovery_passive",
    worker_class: str = "discovery_inventory",
    strategy: str = "zap_discovery_passive",
) -> None:
    memory_store.store_command(
        command_id,
        campaign_id,
        {
            "command_id": command_id,
            "campaign_id": campaign_id,
            "worker_class": worker_class,
            "strategy": strategy,
            "tool_name": tool_name,
            "inputs": inputs,
        },
    )


def _store_zap_alert_observation(
    *,
    observation_id: str = "obs_zap_header",
    campaign_id: str = "cmp_plan",
    alert_name: str = "X-Frame-Options Header Not Set",
    url: str = "http://target.local/frame?token=abc",
    path: str = "/frame",
    operation_id: str = "op_GET_/frame",
) -> None:
    obs = Observation(
        observation_id=observation_id,
        campaign_id=campaign_id,
        type=ObservationType.zap_alert,
        operation_id=operation_id,
        confidence=0.6,
        security_relevance=SecurityRelevance.medium,
        details={
            "alert_name": alert_name,
            "url": url,
            "path": path,
            "operation_id": operation_id,
        },
    )
    memory_store.store_observation(obs.observation_id, campaign_id, "", obs.model_dump(mode="json"))


def _store_discovered_endpoint_observation(
    *,
    observation_id: str = "obs_discovered",
    campaign_id: str = "cmp_plan",
    url: str = "http://target.local/api/discovered?token=abc",
    path: str = "/api/discovered",
    operation_id: str = "op_GET_/api/discovered",
) -> None:
    obs = Observation(
        observation_id=observation_id,
        campaign_id=campaign_id,
        type=ObservationType.discovered_endpoint,
        operation_id=operation_id,
        confidence=0.5,
        security_relevance=SecurityRelevance.low,
        details={
            "url": url,
            "path": path,
            "operation_id": operation_id,
        },
    )
    memory_store.store_observation(obs.observation_id, campaign_id, "", obs.model_dump(mode="json"))


def _store_raw_observation(
    *,
    observation_id: str,
    campaign_id: str,
    observation_type: str,
    details: dict,
) -> None:
    memory_store.store_observation(
        observation_id,
        campaign_id,
        "",
        {
            "schema_version": "observation/v1",
            "observation_id": observation_id,
            "campaign_id": campaign_id,
            "tool_run_id": "",
            "task_id": "",
            "command_id": "",
            "source": "",
            "type": observation_type,
            "operation_id": str(details.get("operation_id") or ""),
            "request_id": "",
            "auth_profile": "",
            "status_code": 0,
            "confidence": 0.85,
            "security_relevance": "medium",
            "judge_worthy": False,
            "recommended_next_action": "",
            "details": details,
            "artifact_refs": [],
            "created_at": "",
        },
    )


def test_planner_missing_campaign_route_returns_404():
    _reset_store()
    client = TestClient(app)

    response = client.post("/v1/planner/cmp_missing/candidates", json={})

    assert response.status_code == 404
    assert response.json()["error"] == "campaign_not_found"


def test_planner_returns_zap_candidate_when_no_prior_zap_run():
    _reset_store()
    _campaign()

    response = PlannerService().plan("cmp_plan", PlannerRequest(bola={"enabled": False}))

    assert response.ready_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "zap_discovery_passive"
    assert candidate.status == "ready"
    assert candidate.command is not None
    assert candidate.command.worker_class == "discovery_inventory"
    assert candidate.command.tool_name == "zap_discovery_passive"


def test_planner_skips_zap_candidate_after_existing_finished_run():
    _reset_store()
    _campaign()
    _store_command(
        command_id="cmd_zap_existing",
        campaign_id="cmp_plan",
        inputs={
            "target_url": "http://target.local",
            "seed_urls": [],
        },
    )
    _store_tool_run(tool_run_id="toolrun_existing", status=ToolRunStatus.finished)
    memory_store.update_tool_run("toolrun_existing", {"command_id": "cmd_zap_existing"})

    response = PlannerService().plan("cmp_plan", PlannerRequest(bola={"enabled": False}))

    assert response.skipped_existing_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "zap_discovery_passive"
    assert candidate.status == "skipped_existing"
    assert candidate.command is None


def test_planner_returns_blocked_bola_when_no_object_pairs():
    _reset_store()
    _campaign()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest(zap={"enabled": False}, bola={"enabled": True}),
    )

    assert response.blocked_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "bola_replay_probe"
    assert candidate.status == "blocked"
    assert candidate.missing_inputs == ["bola.object_pairs"]


def test_planner_returns_bola_candidate_from_complete_hints():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}}),
    )

    assert response.ready_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "bola_replay_probe"
    assert candidate.status == "ready"
    assert candidate.command is not None
    assert candidate.command.worker_class == "access_control"
    assert candidate.command.strategy == "replay_bola_object_pair"
    assert candidate.command.inputs["object_pair_id"] == "objpair_veh_1"


def test_planner_blocks_bola_candidate_for_missing_required_hint():
    _reset_store()
    _campaign()
    request = _request_with_bola(
        bola={"enabled": True, "object_pairs": [_bola_pair(object_url="")]},
    )

    response = PlannerService().plan("cmp_plan", request)

    candidate = response.candidates[0]
    assert candidate.status == "blocked"
    assert "object_url" in candidate.missing_inputs
    assert candidate.command is None


def test_planner_blocks_bola_candidate_for_out_of_scope_url():
    _reset_store()
    _campaign()
    request = _request_with_bola(
        bola={
            "enabled": True,
            "object_pairs": [_bola_pair(object_url="http://evil.local/api/v1/vehicles/veh_123")],
        },
    )

    response = PlannerService().plan("cmp_plan", request)

    candidate = response.candidates[0]
    assert candidate.status == "blocked"
    assert "host_not_allowed" in candidate.missing_inputs
    assert candidate.summary["validation_errors"][0]["code"] == "host_not_allowed"


def test_planner_skips_bola_candidate_when_cross_role_signal_exists():
    _reset_store()
    _campaign()
    obs = Observation(
        observation_id="obs_existing",
        campaign_id="cmp_plan",
        type=ObservationType.cross_role_access_signal,
        operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        confidence=0.9,
        security_relevance=SecurityRelevance.high,
        details={
            "object_id": "veh_123",
            "attacker_own_object_id": "veh_456",
            "owner_role": "owner",
            "attacker_role": "attacker",
            "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
        },
    )
    memory_store.store_observation(obs.observation_id, "cmp_plan", "", obs.model_dump(mode="json"))

    response = PlannerService().plan("cmp_plan", _request_with_bola())

    candidate = response.candidates[0]
    assert candidate.status == "skipped_existing"
    assert candidate.command is None


def test_planner_skips_bola_candidate_when_tool_result_signal_exists():
    _reset_store()
    _campaign()
    run = _store_tool_run(tool_name="bola_replay_probe")
    result = ToolResult(
        tool_run_id=run.tool_run_id,
        campaign_id="cmp_plan",
        tool_name="bola_replay_probe",
        observations=[
            ToolResultObservationLite(
                observation_type="cross_role_access_signal",
                confidence=0.9,
                details={
                    "object_id": "veh_123",
                    "attacker_own_object_id": "veh_456",
                    "owner_role": "owner",
                    "attacker_role": "attacker",
                    "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                },
            )
        ],
    )
    memory_store.store_tool_result(run.tool_run_id, result.model_dump(mode="json"))

    response = PlannerService().plan("cmp_plan", _request_with_bola())

    assert response.candidates[0].status == "skipped_existing"


def test_planner_returned_ready_command_validates():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}}),
    )
    command = response.candidates[0].command

    assert command is not None
    validation = CommandValidator().validate(command)
    assert validation.valid


def test_planner_does_not_create_tool_run():
    _reset_store()
    _campaign()

    PlannerService().plan("cmp_plan", _request_with_bola())

    assert memory_store.tool_runs == {}
    assert memory_store.tool_results == {}


def test_planner_does_not_create_evidence_judge_finding():
    _reset_store()
    _campaign()

    PlannerService().plan("cmp_plan", _request_with_bola())

    assert memory_store.evidence_packs == {}
    assert memory_store.judge_decisions == {}
    assert memory_store.confirmed_findings == {}
    assert memory_store.evidence_records == []
    assert memory_store.findings == []


def test_planner_does_not_mutate_legacy_scheduler_state():
    _reset_store()
    _campaign()
    before_evidence_by_session = dict(memory_store.evidence_by_session)
    before_findings_by_session = dict(memory_store.findings_by_session)

    PlannerService().plan("cmp_plan", _request_with_bola())

    assert dict(memory_store.evidence_by_session) == before_evidence_by_session
    assert dict(memory_store.findings_by_session) == before_findings_by_session
    assert memory_store.commands == {}


def test_planner_orders_bola_before_zap():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()
    request = PlannerRequest.model_validate({
        "zap": {"enabled": True},
        "bola": {"enabled": True},
    })

    response = PlannerService().plan("cmp_plan", request)

    assert [candidate.kind.value for candidate in response.candidates[:2]] == [
        "bola_replay_probe",
        "zap_discovery_passive",
    ]


def test_planner_respects_max_candidates():
    _reset_store()
    _campaign()
    request = PlannerRequest.model_validate({
        "max_candidates": 1,
        "zap": {"enabled": True},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
    })

    response = PlannerService().plan("cmp_plan", request)

    assert response.candidates_total == 1
    assert len(response.candidates) == 1


def test_planner_blocks_ready_candidates_when_allowed_hosts_empty():
    _reset_store()
    _campaign(allowed_hosts=[])
    request = PlannerRequest.model_validate({
        "zap": {"enabled": True},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
    })

    response = PlannerService().plan("cmp_plan", request)

    assert response.ready_count == 0
    assert response.blocked_count == 2
    assert "allowed_hosts_not_configured" in response.warnings
    assert {tuple(c.missing_inputs) for c in response.candidates} == {
        ("campaign.allowed_hosts",),
    }


def test_planner_route_returns_planner_response():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()
    client = TestClient(app)

    response = client.post(
        "/v1/planner/cmp_plan/candidates",
        json={
            "zap": {"enabled": False},
            "bola": {"enabled": True},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["campaign_id"] == "cmp_plan"
    assert payload["ready_count"] == 1
    assert payload["candidates"][0]["command"]["tool_name"] == "bola_replay_probe"


def test_planner_response_exposes_safe_ready_candidate_summaries_only() -> None:
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate(
            {
                "zap": {"enabled": False},
                "bola": {"enabled": True},
            }
        ),
    )

    assert response.ready_candidates_by_kind_count.get("bola_replay_probe") == 1
    assert len(response.ready_candidates_sample) == 1
    row = response.ready_candidates_sample[0]
    assert row["candidate_id"].startswith("pcand_")
    assert row["kind"] == "bola_replay_probe"
    assert row["operation_id"] == "op_GET_/api/v1/vehicles/{vehicleId}"
    assert row["method"] == "GET"
    assert row["path_template"] == "/api/v1/vehicles/{vehicleId}"
    assert row["object_pair_id"] == "objpair_veh_1"
    assert row["resource_type"] == "vehicle"
    assert row["validation_mode"] == "bola_replay"
    blob = json.dumps(row, ensure_ascii=False)
    for bad in ("Authorization", "Cookie", "password", "request_body", "response_body", "object_id", "raw_headers", "token="):
        assert bad not in blob


def test_planner_zap_dedup_not_too_broad_by_target_or_seed():
    _reset_store()
    _campaign()
    _store_command(
        command_id="cmd_zap_existing",
        campaign_id="cmp_plan",
        inputs={
            "target_url": "http://target.local",
            "seed_urls": ["http://target.local/a"],
        },
    )
    _store_tool_run(tool_run_id="toolrun_existing", status=ToolRunStatus.finished)
    memory_store.update_tool_run("toolrun_existing", {"command_id": "cmd_zap_existing"})

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "bola": {"enabled": False},
            "zap": {
                "enabled": True,
                "target_url": "http://target.local",
                "seed_urls": ["http://target.local/b"],
            },
        }),
    )

    assert response.ready_count == 1
    assert response.candidates[0].status == "ready"
    assert response.candidates[0].command is not None


def test_planner_zap_dedup_skips_same_target_and_seed():
    _reset_store()
    _campaign()
    _store_command(
        command_id="cmd_zap_existing",
        campaign_id="cmp_plan",
        inputs={
            "target_url": "http://target.local",
            "seed_urls": ["http://target.local/a"],
        },
    )
    _store_tool_run(tool_run_id="toolrun_existing", status=ToolRunStatus.running)
    memory_store.update_tool_run("toolrun_existing", {"command_id": "cmd_zap_existing"})

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "bola": {"enabled": False},
            "zap": {
                "enabled": True,
                "target_url": "http://target.local",
                "seed_urls": ["http://target.local/a"],
            },
        }),
    )

    assert response.skipped_existing_count == 1
    assert response.candidates[0].status == "skipped_existing"


def test_planner_skips_zap_when_zap_alert_observations_exist():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": True},
            "bola": {"enabled": False},
        }),
    )

    zap_candidate = next(candidate for candidate in response.candidates if candidate.kind == "zap_discovery_passive")
    assert zap_candidate.status == "skipped_existing"
    assert zap_candidate.command is None
    assert "already produced observations" in zap_candidate.reason


def test_planner_prefers_security_header_validator_over_zap_after_zap_alerts_exist():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": True},
            "bola": {"enabled": False},
        }),
    )

    assert [candidate.kind.value for candidate in response.candidates[:2]] == [
        "security_header_validator",
        "zap_discovery_passive",
    ]


def test_planner_emits_authenticated_ssrf_probe_candidate_from_ssrf_candidate_signal() -> None:
    _reset_store()
    _campaign("cmp_plan")

    owner = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )
    attacker = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="attacker",
        user_label="attacker",
        auth_type="bearer",
        raw_token="attacker-token",
        created_by="test",
    )
    memory_store.store_observation(
        "obs_mat",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_mat",
            campaign_id="cmp_plan",
            type=ObservationType.test_account_materialization_result,
            details={
                "source": "test_account_materializer",
                "test_account_materialization_status": "materialized",
                "auth_profiles_created_count": 2,
                "owner_auth_profile_id": owner.auth_profile_id,
                "attacker_auth_profile_id": attacker.auth_profile_id,
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_ssrf",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/api/hooks",
                "method": "POST",
                "path": "/api/hooks",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )

    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    candidates = [c for c in response.candidates if c.kind.value == "ssrf_probe"]
    assert candidates
    ready = next(c for c in candidates if c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.tool_name == "ssrf_probe"
    assert ready.command.inputs["auth_mode"] == "authenticated"
    assert ready.command.inputs["auth_profile_id"] == owner.auth_profile_id


def test_planner_blocks_ssrf_probe_when_path_params_present() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_ssrf2",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf2",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_PUT_/api/videos/{video_id}",
                "method": "PUT",
                "path": "/api/videos/{video_id}",
                "field_name": "video_url",
                "field_path": "$.video_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )

    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    blocked = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "blocked")
    assert "path_params_seed" in blocked.missing_inputs


def test_ssrf_probe_rotation_failed_candidate_does_not_block_next_candidate() -> None:
    _reset_store()
    _campaign("cmp_plan")
    owner = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )
    memory_store.store_observation(
        "obs_mat",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_mat",
            campaign_id="cmp_plan",
            type=ObservationType.test_account_materialization_result,
            details={
                "source": "test_account_materializer",
                "test_account_materialization_status": "materialized",
                "auth_profiles_created_count": 2,
                "owner_auth_profile_id": owner.auth_profile_id,
            },
        ).model_dump(mode="json"),
    )
    # Candidate A: image-like path (lower score), already attempted and failed.
    memory_store.store_observation(
        "obs_ssrf_a",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf_a",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/workshop/api/shop/products",
                "method": "POST",
                "path": "/workshop/api/shop/products",
                "field_name": "image_url",
                "field_path": "$.image_url",
                "schema_format": "uri",
                "confidence": "medium",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_probe_a",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_probe_a",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_probe_result,
            details={
                "validation_mode": "ssrf_callback_probe",
                "operation_id": "op_POST_/workshop/api/shop/products",
                "field_path": "$.image_url",
                "auth_mode": "authenticated",
                "auth_profile_id": owner.auth_profile_id,
                "result": "target_non_2xx",
                "callback_received": False,
            },
        ).model_dump(mode="json"),
    )
    # Candidate B: contact/api-like path should be next ready.
    memory_store.store_observation(
        "obs_ssrf_b",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf_b",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "path": "/workshop/api/merchant/contact_mechanic",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )

    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = [c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready"]
    assert len(ready) == 1
    assert ready[0].command is not None
    assert ready[0].command.operation_id == "op_POST_/workshop/api/merchant/contact_mechanic"


def test_ssrf_probe_rotation_stops_when_callback_received_true() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_ssrf",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "path": "/workshop/api/merchant/contact_mechanic",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_probe_ok",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_probe_ok",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_probe_result,
            details={
                "validation_mode": "ssrf_callback_probe",
                "operation_id": "op_POST_/workshop/api/merchant/contact_mechanic",
                "field_path": "$.mechanic_api",
                "auth_mode": "unauthenticated",
                "auth_profile_id": "",
                "result": "callback_received",
                "callback_received": True,
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = [c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready"]
    assert not ready


def test_ssrf_probe_emits_at_most_one_ready_per_cycle() -> None:
    _reset_store()
    _campaign("cmp_plan")
    for i, (op, field) in enumerate((
        ("op_POST_/a", "$.target_url"),
        ("op_POST_/b", "$.callback_url"),
        ("op_POST_/c", "$.notify_api"),
    )):
        memory_store.store_observation(
            f"obs_ssrf_{i}",
            "cmp_plan",
            "",
            Observation(
                observation_id=f"obs_ssrf_{i}",
                campaign_id="cmp_plan",
                type=ObservationType.ssrf_candidate_signal,
                details={
                    "validation_mode": "ssrf_candidate_detection",
                    "operation_id": op,
                    "method": "POST",
                    "path": f"/{chr(97+i)}",
                    "field_name": field.strip("$."),
                    "field_path": field,
                    "schema_format": "uri",
                    "confidence": "high",
                },
            ).model_dump(mode="json"),
        )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = [c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready"]
    assert len(ready) <= 1


def test_ssrf_probe_dedup_key_includes_operation_field_and_auth_profile() -> None:
    _reset_store()
    _campaign("cmp_plan")
    owner = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )
    memory_store.store_observation(
        "obs_mat",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_mat",
            campaign_id="cmp_plan",
            type=ObservationType.test_account_materialization_result,
            details={
                "source": "test_account_materializer",
                "test_account_materialization_status": "materialized",
                "owner_auth_profile_id": owner.auth_profile_id,
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_ssrf",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/hooks",
                "method": "POST",
                "path": "/hooks",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert "op_POST_/hooks" in ready.dedup_key
    assert "$.callback_url" in ready.dedup_key
    assert owner.auth_profile_id in ready.dedup_key


def test_ssrf_probe_ranking_prefers_contact_api_over_product_image() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_img",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_img",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/workshop/api/shop/products",
                "method": "POST",
                "path": "/workshop/api/shop/products",
                "field_name": "image_url",
                "field_path": "$.image_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_contact",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_contact",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/workshop/api/merchant/contact_mechanic",
                "method": "POST",
                "path": "/workshop/api/merchant/contact_mechanic",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.operation_id == "op_POST_/workshop/api/merchant/contact_mechanic"


def test_ssrf_probe_pool_retains_more_than_two_candidates_and_keeps_deprioritized_rows() -> None:
    _reset_store()
    _campaign("cmp_plan")
    for i, (op_id, path, field_name, field_path) in enumerate(
        (
            ("op_POST_/alpha/contact", "/alpha/contact", "callback_url", "$.callback_url"),
            ("op_POST_/beta/integration", "/beta/integration", "target_api", "$.target_api"),
            ("op_POST_/gamma/notify", "/gamma/notify", "notify_url", "$.notify_url"),
            ("op_POST_/delta/report", "/delta/report", "service_endpoint", "$.service_endpoint"),
            ("op_POST_/epsilon/connect", "/epsilon/connect", "destination_url", "$.destination_url"),
        )
    ):
        memory_store.store_observation(
            f"obs_ssrf_pool_{i}",
            "cmp_plan",
            "",
            Observation(
                observation_id=f"obs_ssrf_pool_{i}",
                campaign_id="cmp_plan",
                type=ObservationType.ssrf_candidate_signal,
                details={
                    "validation_mode": "ssrf_candidate_detection",
                    "operation_id": op_id,
                    "method": "POST",
                    "path": path,
                    "field_name": field_name,
                    "field_path": field_path,
                    "schema_format": "uri",
                    "confidence": "high",
                },
            ).model_dump(mode="json"),
        )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ssrf_rows = [c for c in response.candidates if c.kind.value == "ssrf_probe"]
    assert len(ssrf_rows) >= 5
    assert len([c for c in ssrf_rows if c.status.value == "ready"]) == 1
    assert len([c for c in ssrf_rows if c.status.value == "skipped_existing"]) >= 3


def test_ssrf_probe_uses_openapi_fallback_when_candidate_signal_missing_contact_like_operation() -> None:
    _reset_store()
    _campaign("cmp_plan")
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/store/products",
                method="POST",
                path_template="/store/products",
                body_fields=["image_url"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/integrations/contact-service",
                method="POST",
                path_template="/integrations/contact-service",
                body_fields=["service_endpoint"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    memory_store.store_observation(
        "obs_only_product",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_only_product",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/store/products",
                "method": "POST",
                "path": "/store/products",
                "field_name": "image_url",
                "field_path": "$.image_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.operation_id == "op_POST_/integrations/contact-service"


def test_ssrf_probe_penalizes_previous_target_non_2xx_and_selects_next_eligible_candidate() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_candidate_1",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_candidate_1",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/services/product-media",
                "method": "POST",
                "path": "/services/product-media",
                "field_name": "image_url",
                "field_path": "$.image_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_candidate_2",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_candidate_2",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/services/contact-notify",
                "method": "POST",
                "path": "/services/contact-notify",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    memory_store.store_observation(
        "obs_prev_fail",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_prev_fail",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_probe_result,
            details={
                "validation_mode": "ssrf_callback_probe",
                "operation_id": "op_POST_/services/product-media",
                "field_path": "$.image_url",
                "auth_mode": "unauthenticated",
                "auth_profile_id": "",
                "result": "target_non_2xx",
                "callback_received": False,
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.operation_id == "op_POST_/services/contact-notify"


def test_ssrf_scoring_logic_is_generic_and_not_hardcoded_to_specific_crapi_paths() -> None:
    code = Path("backend/services/planner_service.py").read_text(encoding="utf-8")
    assert "workshop/api/merchant/contact_mechanic" not in code
    assert "mechanic_api should rank" not in code


def test_ssrf_detector_resolves_ref_request_body_schema() -> None:
    _reset_store()
    _campaign("cmp_plan")
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/api/contact",
                method="POST",
                path_template="/api/contact",
                body_fields=["mechanic_api", "problem_details"],
                body_required_fields=["mechanic_api", "problem_details"],
                body_field_summaries=[
                    {"name": "mechanic_api", "field_path": "$.mechanic_api", "schema_type": "string"},
                    {"name": "problem_details", "field_path": "$.problem_details", "schema_type": "string"},
                ],
                tags=["contact"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    detector = next(c for c in response.candidates if c.kind.value == "ssrf_candidate_detector")
    sample = detector.summary.get("candidate_fields_sample")[0]
    assert sample["field_path"] == "$.mechanic_api"
    assert "url_like_field_name" in sample["reason_codes"]
    assert "request_body_ref_resolved" in sample["reason_codes"]


def test_ssrf_detector_detects_service_endpoint_with_uri_format() -> None:
    _reset_store()
    _campaign("cmp_plan")
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[Operation(
            operation_id="op_POST_/api/integration/connect",
            method="POST",
            path_template="/api/integration/connect",
            body_fields=["service_endpoint"],
            body_field_summaries=[{"name": "service_endpoint", "field_path": "$.service_endpoint", "schema_type": "string", "schema_format": "uri"}],
            sources=["openapi"],
        )],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    detector = next(c for c in response.candidates if c.kind.value == "ssrf_candidate_detector")
    sample = detector.summary.get("candidate_fields_sample")[0]
    assert sample["confidence"] == "high"
    assert sample["schema_format"] == "uri"


def test_ssrf_candidate_summary_contains_required_and_allowed_body_fields() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_ssrf_schema",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf_schema",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/hooks",
                "method": "POST",
                "path": "/hooks",
                "field_name": "callback_url",
                "field_path": "$.callback_url",
                "schema_format": "uri",
                "confidence": "high",
                "required_body_fields": ["callback_url", "problem_details"],
                "allowed_body_fields": ["callback_url", "problem_details"],
                "body_field_summaries": [{"name": "callback_url", "schema_type": "string"}],
                "schema_summary_source": "api_graph",
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.summary.get("required_body_fields") == ["callback_url", "problem_details"]
    assert "callback_url" in (ready.summary.get("allowed_body_fields") or [])


def test_high_value_ssrf_signal_becomes_ready_probe() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_ssrf_hv",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf_hv",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/api/contact",
                "method": "POST",
                "path": "/api/contact",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.operation_id == "op_POST_/api/contact"


def test_ssrf_ready_probe_carries_schema_context() -> None:
    _reset_store()
    _campaign("cmp_plan")
    memory_store.store_observation(
        "obs_ssrf_schema_ctx",
        "cmp_plan",
        "",
        Observation(
            observation_id="obs_ssrf_schema_ctx",
            campaign_id="cmp_plan",
            type=ObservationType.ssrf_candidate_signal,
            details={
                "validation_mode": "ssrf_candidate_detection",
                "operation_id": "op_POST_/api/contact",
                "method": "POST",
                "path": "/api/contact",
                "field_name": "mechanic_api",
                "field_path": "$.mechanic_api",
                "schema_format": "uri",
                "confidence": "high",
                "required_body_fields": ["mechanic_api", "problem_details"],
                "allowed_body_fields": ["mechanic_api", "problem_details"],
                "body_field_summaries": [{"name": "mechanic_api", "schema_type": "string"}],
                "schema_summary_source": "api_graph",
                "ssrf_target_field": {"field_name": "mechanic_api", "field_path": "$.mechanic_api"},
            },
        ).model_dump(mode="json"),
    )
    response = PlannerService().plan("cmp_plan", PlannerRequest(max_candidates=50))
    ready = next(c for c in response.candidates if c.kind.value == "ssrf_probe" and c.status.value == "ready")
    assert ready.command is not None
    assert ready.command.inputs.get("required_body_fields") == ["mechanic_api", "problem_details"]
    assert ready.command.inputs.get("schema_summary_source") == "api_graph"


def test_planner_still_returns_zap_ready_when_no_zap_output_exists():
    _reset_store()
    _campaign()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": True},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "zap_discovery_passive"
    assert candidate.status == "ready"
    assert candidate.command is not None


def test_planner_zap_skip_is_campaign_scoped():
    _reset_store()
    _campaign(campaign_id="cmp_plan")
    _campaign(campaign_id="cmp_other")
    _store_zap_alert_observation(campaign_id="cmp_other")

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": True},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "zap_discovery_passive"
    assert candidate.status == "ready"
    assert candidate.command is not None


def test_planner_zap_skip_does_not_suppress_different_target_if_target_can_be_distinguished():
    _reset_store()
    _campaign()
    _store_discovered_endpoint_observation(
        url="http://target.local/admin/users?token=abc",
        path="/admin/users",
    )

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {
                "enabled": True,
                "target_url": "http://target.local/public",
            },
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "zap_discovery_passive"
    assert candidate.status == "ready"
    assert candidate.command is not None


def test_planner_bola_dedup_respects_attacker_own_object_id():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()
    obs = Observation(
        observation_id="obs_existing",
        campaign_id="cmp_plan",
        type=ObservationType.cross_role_access_signal,
        operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        confidence=0.9,
        security_relevance=SecurityRelevance.high,
        details={
            "object_id": "veh_123",
            "attacker_own_object_id": "veh_999",
            "owner_role": "owner",
            "attacker_role": "attacker",
            "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
        },
    )
    memory_store.store_observation(obs.observation_id, "cmp_plan", "", obs.model_dump(mode="json"))

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}}),
    )

    assert response.candidates[0].status == "ready"
    assert response.candidates[0].command is not None


def test_planner_cross_campaign_existing_signal_does_not_suppress_candidate():
    _reset_store()
    _campaign(campaign_id="cmp_plan")
    _campaign(campaign_id="cmp_other")
    _store_runtime_bola_pair()
    obs = Observation(
        observation_id="obs_other",
        campaign_id="cmp_other",
        type=ObservationType.cross_role_access_signal,
        operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        confidence=0.9,
        security_relevance=SecurityRelevance.high,
        details={
            "object_id": "veh_123",
            "attacker_own_object_id": "veh_456",
            "owner_role": "owner",
            "attacker_role": "attacker",
            "operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
        },
    )
    memory_store.store_observation(obs.observation_id, "cmp_other", "", obs.model_dump(mode="json"))

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}}),
    )

    assert response.candidates[0].status == "ready"
    assert response.candidates[0].command is not None


def test_planner_returns_security_header_validator_candidate_for_supported_zap_alert():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    assert response.ready_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "security_header_validator"
    assert candidate.status == "ready"
    assert candidate.command is not None
    assert candidate.command.worker_class == "misconfiguration"
    assert candidate.command.tool_name == "security_header_validator"
    assert candidate.command.inputs["header_name"] == "X-Frame-Options"
    assert candidate.command.inputs["source_observation_id"] == "obs_zap_header"


def test_planner_blocks_security_header_validator_when_zap_alert_has_no_url():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(url="", path="")

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "security_header_validator"
    assert candidate.status == "blocked"
    assert candidate.missing_inputs == ["request_url"]


def test_planner_blocks_security_header_validator_for_unsupported_alert_mapping():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(alert_name="Cache-Control Header Weak")

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "security_header_validator"
    assert candidate.status == "blocked"
    assert candidate.missing_inputs == ["supported_security_header_mapping"]


def test_planner_blocks_security_header_alias_not_accepted_by_adapter():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(alert_name="X-Content-Type-Options Header Not Set")

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.kind == "security_header_validator"
    assert candidate.status == "blocked"
    assert "supported_security_header_mapping" in candidate.missing_inputs


def test_planner_skips_security_header_validator_when_validated_issue_exists():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()
    _store_raw_observation(
        observation_id="obs_validated",
        campaign_id="cmp_plan",
        observation_type="validated_security_header_issue",
        details={
            "source_observation_id": "obs_zap_header",
            "header_name": "X-Frame-Options",
            "url": "http://target.local/frame?token=%3Credacted%3E",
        },
    )

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.status == "skipped_existing"
    assert candidate.command is None


def test_planner_security_header_canonical_path_redacts_query_values():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(url="", path="/login?token=secret&x=1")

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.status == "ready"
    assert "token=secret" not in candidate.dedup_key
    assert "x=1" not in candidate.dedup_key
    assert "token=<redacted>" in candidate.dedup_key
    assert "x=<redacted>" in candidate.dedup_key
    assert candidate.summary["canonical_url"] == "/login?token=<redacted>&x=<redacted>"


def test_planner_skips_security_header_validator_when_matching_tool_run_exists():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()
    _store_command(
        command_id="cmd_header_existing",
        campaign_id="cmp_plan",
        tool_name="security_header_validator",
        worker_class="misconfiguration",
        strategy="validate_security_header",
        inputs={
            "request_url": "http://target.local/frame?token=abc",
            "target_url": "http://target.local/frame?token=abc",
            "header_name": "X-Frame-Options",
            "source_observation_id": "obs_zap_header",
        },
    )
    _store_tool_run(
        tool_run_id="toolrun_header_existing",
        campaign_id="cmp_plan",
        tool_name="security_header_validator",
        status=ToolRunStatus.running,
    )
    memory_store.update_tool_run("toolrun_header_existing", {"command_id": "cmd_header_existing"})

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.status == "skipped_existing"
    assert candidate.command is None


def test_planner_security_header_dedup_not_too_broad_same_campaign():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_zap_a",
        url="http://target.local/frame-a?token=abc",
        path="/frame-a",
    )
    _store_zap_alert_observation(
        observation_id="obs_zap_b",
        url="http://target.local/frame-b?token=abc",
        path="/frame-b",
    )
    _store_raw_observation(
        observation_id="obs_validated_a",
        campaign_id="cmp_plan",
        observation_type="validated_security_header_issue",
        details={
            "source_observation_id": "obs_zap_a",
            "header_name": "X-Frame-Options",
            "url": "http://target.local/frame-a?token=%3Credacted%3E",
        },
    )

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    by_source = {
        str(candidate.summary.get("source_observation_id") or ""): candidate
        for candidate in response.candidates
        if candidate.kind == "security_header_validator"
    }
    assert by_source["obs_zap_a"].status == "skipped_existing"
    assert by_source["obs_zap_b"].status == "ready"
    assert by_source["obs_zap_b"].command is not None


def test_planner_security_header_candidate_command_validates():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )
    command = response.candidates[0].command

    assert command is not None
    validation = CommandValidator().validate(command)
    assert validation.valid


def test_planner_security_header_cross_campaign_existing_issue_does_not_suppress():
    _reset_store()
    _campaign(campaign_id="cmp_plan")
    _campaign(campaign_id="cmp_other")
    _store_zap_alert_observation(campaign_id="cmp_plan")
    _store_raw_observation(
        observation_id="obs_validated_other",
        campaign_id="cmp_other",
        observation_type="validated_security_header_issue",
        details={
            "source_observation_id": "obs_zap_header",
            "header_name": "X-Frame-Options",
            "url": "http://target.local/frame?token=%3Credacted%3E",
        },
    )

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.status == "ready"
    assert candidate.command is not None


def test_planner_orders_security_header_after_bola_ready_before_blocked():
    _reset_store()
    _campaign()
    _store_runtime_bola_pair()
    _store_zap_alert_observation()
    request = PlannerRequest.model_validate({
        "zap": {"enabled": False},
        "bola": {"enabled": True},
    })

    response = PlannerService().plan("cmp_plan", request)

    assert [candidate.kind.value for candidate in response.candidates[:2]] == [
        "bola_replay_probe",
        "security_header_validator",
    ]


def test_planner_security_header_dedup_uses_sanitized_canonical_url():
    _reset_store()
    _campaign()
    _store_zap_alert_observation(url="http://user:pass@target.local/frame?token=abc", path="/frame")
    _store_raw_observation(
        observation_id="obs_validated",
        campaign_id="cmp_plan",
        observation_type="validated_security_header_issue",
        details={
            "source_observation_id": "obs_zap_header",
            "header_name": "X-Frame-Options",
            "url": "http://target.local/frame?token=%3Credacted%3E",
        },
    )

    response = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )

    candidate = response.candidates[0]
    assert candidate.status == "skipped_existing"
    assert "token=abc" not in candidate.dedup_key
    assert "%3Credacted%3E" in candidate.dedup_key


def test_planner_route_invalid_body_returns_controlled_400():
    _reset_store()
    _campaign()
    client = TestClient(app)

    response = client.post(
        "/v1/planner/cmp_plan/candidates",
        json={"max_candidates": "oops"},
    )

    assert response.status_code == 400
    payload = response.json()
    assert payload["error"] == "invalid_planner_request"


def test_planner_without_scenario_plan_unchanged():
    _reset_store()
    _campaign()

    def _shape(r):
        return {
            "totals": (r.candidates_total, r.ready_count, r.blocked_count, r.skipped_existing_count),
            "candidates": [
                (c.kind.value, c.status.value, c.dedup_key, tuple(c.missing_inputs))
                for c in r.candidates
            ],
        }

    req_a = PlannerRequest(zap={"enabled": False}, bola={"enabled": True, "object_pairs": [_bola_pair()]})
    req_b = PlannerRequest.model_validate({
        "zap": {"enabled": False},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
        "scenario_plan": None,
        "include_scenario_compiler": True,
    })
    r1 = PlannerService().plan("cmp_plan", req_a)
    r2 = PlannerService().plan("cmp_plan", req_b)
    assert _shape(r1) == _shape(r2)


def test_planner_scenario_schema_negative_testing_adds_schemathesis_candidate_when_openapi_source_available():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "max_candidates": 20,
        "scenario_plan": {
            "source": "llm_openapi_scenario_planner",
            "scenarios": [_schema_scenario_payload()],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    st = [c for c in resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert len(st) == 1
    assert st[0].status == "ready"
    assert st[0].command is not None
    assert st[0].command.tool_name == "schemathesis_negative_test"
    assert st[0].command.strategy == "schema_negative_testing"
    assert st[0].command.operation_id == "op_GET_/api/v1/vehicles/{vehicleId}"


def test_planner_scenario_schema_negative_testing_blocked_without_openapi_source():
    _reset_store()
    _campaign(openapi_url=None)
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "test",
            "scenarios": [_schema_scenario_payload()],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    st = [c for c in resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert not st
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("openapi_source" in c.missing_inputs for c in audit)


def test_planner_scenario_candidate_command_validates():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_schema_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    cmd = next(c.command for c in resp.candidates if c.kind.value == "schemathesis_negative_test" and c.command)
    assert CommandValidator().validate(cmd).valid


def test_planner_scenario_does_not_trust_llm_worker_name_for_tool_choice():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(candidate_workers=["totally_fake_tool_name"])],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    cmd = next(c.command for c in resp.candidates if c.command and c.kind.value == "schemathesis_negative_test")
    assert cmd.tool_name == "schemathesis_negative_test"


def test_planner_scenario_rejects_or_blocks_unknown_operation_id():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(operation_ids=["op_UNKNOWN_missing"])],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("unknown_operation_id" in (m or "") for c in audit for m in c.missing_inputs)


def test_planner_schemathesis_partial_tool_run_skips_existing():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()

    run_id = "toolrun_sch_partial"
    memory_store.store_tool_run(
        run_id,
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": run_id,
            "campaign_id": "cmp_plan",
            "tool_name": "schemathesis_negative_test",
            "status": "partial",
            "command_id": "cmd_missing_in_store",
            "result_ready": True,
        },
    )
    memory_store.store_tool_result(
        run_id,
        ToolResult(
            tool_run_id=run_id,
            campaign_id="cmp_plan",
            tool_name="schemathesis_negative_test",
            status="partial",
            observations=[
                ToolResultObservationLite(
                    observation_type="schema_mismatch",
                    confidence=0.6,
                    details={"operation_id": "op_GET_/api/v1/vehicles/{vehicleId}"},
                ),
            ],
        ).model_dump(mode="json"),
    )

    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_schema_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    st = [c for c in resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert len(st) == 1
    assert st[0].status == "skipped_existing"


def test_planner_schemathesis_partial_run_without_command_id_dedups_by_tool_result_observation():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()

    run_id = "toolrun_sch_partial_no_cmd"
    memory_store.store_tool_run(
        run_id,
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": run_id,
            "campaign_id": "cmp_plan",
            "tool_name": "schemathesis_negative_test",
            "status": "partial",
            "command_id": "",
            "result_ready": True,
        },
    )
    memory_store.store_tool_result(
        run_id,
        ToolResult(
            tool_run_id=run_id,
            campaign_id="cmp_plan",
            tool_name="schemathesis_negative_test",
            status="partial",
            observations=[
                ToolResultObservationLite(
                    observation_type="schema_mismatch",
                    confidence=0.6,
                    details={"operation_id": "op_GET_/api/v1/vehicles/{vehicleId}"},
                ),
            ],
        ).model_dump(mode="json"),
    )

    same_op_body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(operation_ids=["op_GET_/api/v1/vehicles/{vehicleId}"])],
        },
    }
    same_op_resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(same_op_body))
    same_op_st = [c for c in same_op_resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert len(same_op_st) == 1
    assert same_op_st[0].status == "skipped_existing"

    different_op_body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(operation_ids=["op_POST_/api/v1/vehicles"])],
        },
    }
    different_op_resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(different_op_body))
    diff_st = [c for c in different_op_resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert len(diff_st) == 0
    audit = [c for c in different_op_resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("unknown_operation_id:op_POST_/api/v1/vehicles" in (m or "") for c in audit for m in c.missing_inputs)


def test_planner_schemathesis_dedup_uses_operation_id_not_scenario_id():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _schema_scenario_payload(scenario_id="scn_a"),
                _schema_scenario_payload(scenario_id="scn_b"),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    st = [c for c in resp.candidates if c.kind.value == "schemathesis_negative_test"]
    assert len(st) == 1
    assert st[0].summary["source_scenario_ids"] == ["scn_a", "scn_b"]


def test_planner_scenario_raw_url_rejected_or_blocked():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(rationale="see https://evil.example/x")],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("raw_url_not_allowed" in c.missing_inputs for c in audit)


def test_planner_scenario_secret_rejected_or_blocked():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [_schema_scenario_payload(rationale="Bearer leaked-secret-token")],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("secret_pattern_in_scenario_fields" in c.missing_inputs for c in audit)


def test_planner_bola_scenario_without_object_pairs_blocked_no_command():
    _reset_store()
    _campaign()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": True, "object_pairs": []},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                {
                    "scenario_id": "scn_bola",
                    "status": "accepted",
                    "scenario_type": "access_control_bola",
                    "vulnerability_classes": ["BOLA"],
                    "operation_ids": ["op_GET_/api/v1/vehicles/{vehicleId}"],
                    "resource_type": "",
                    "required_preconditions": ["two_authenticated_roles"],
                    "candidate_workers": ["bola_replay_probe"],
                    "confidence": 0.5,
                    "rationale": "bola",
                    "blocking_codes": [],
                    "errors": [],
                    "warnings": [],
                },
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    bola_audit = [c for c in audit if (c.summary or {}).get("audit_code") == "bola_scenario_blocked"]
    assert bola_audit
    assert bola_audit[0].command is None
    assert "object_pairs" in bola_audit[0].missing_inputs


def test_planner_security_header_scenario_boosts_existing_validator_candidates():
    _reset_store()
    _campaign()
    _store_zap_alert_observation()
    body_no = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
    }
    body_yes = {
        **body_no,
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                {
                    "scenario_id": "scn_hdr",
                    "status": "accepted",
                    "scenario_type": "security_header_validation",
                    "vulnerability_classes": ["MISCONFIG"],
                    "operation_ids": [],
                    "resource_type": "",
                    "required_preconditions": ["passive_signal_context"],
                    "candidate_workers": ["security_header_validator"],
                    "confidence": 0.5,
                    "rationale": "hdr",
                    "blocking_codes": [],
                    "errors": [],
                    "warnings": [],
                },
            ],
        },
    }
    r0 = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body_no))
    r1 = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body_yes))
    c0 = next(c for c in r0.candidates if c.kind.value == "security_header_validator")
    c1 = next(c for c in r1.candidates if c.kind.value == "security_header_validator")
    assert c1.priority > c0.priority
    assert (c1.summary or {}).get("scenario_priority_boost")


def test_planner_security_header_scenario_without_passive_context_blocked():
    _reset_store()
    _campaign()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                {
                    "scenario_id": "scn_hdr",
                    "status": "accepted",
                    "scenario_type": "security_header_validation",
                    "vulnerability_classes": ["MISCONFIG"],
                    "operation_ids": [],
                    "resource_type": "",
                    "required_preconditions": ["passive_signal_context"],
                    "candidate_workers": ["security_header_validator"],
                    "confidence": 0.5,
                    "rationale": "hdr",
                    "blocking_codes": [],
                    "errors": [],
                    "warnings": [],
                },
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("passive_signal_context" in c.missing_inputs for c in audit)


def test_planner_creates_ready_cors_validator_candidate_from_cors_zap_alert() -> None:
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_zap_cors",
        alert_name="CORS Header Misconfiguration",
        url="http://target.local/api/v1/users?token=abc",
        path="/api/v1/users",
        operation_id="op_GET_/api/v1/users",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "enable_cors_baseline": True,
        }),
    )
    cors = [c for c in resp.candidates if c.kind.value == "cors_validator"]
    assert len(cors) == 1
    cand = cors[0]
    assert cand.status.value == "ready"
    assert cand.command is not None
    assert cand.command.tool_name == "cors_validator"
    assert cand.summary.get("cors_candidate_source") != "baseline"
    assert cand.command.inputs.get("origin_probe") == "https://evil.example.invalid"
    assert cand.command.inputs.get("validation_mode") == "single_replay_cors_check"
    summary_blob = str(cand.summary).lower()
    for bad in ("authorization", "cookie", "set-cookie", "request_body", "response_body", "token=abc"):
        assert bad not in summary_blob


def test_planner_creates_baseline_cors_candidate_without_cors_zap_alert() -> None:
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_zap_non_cors",
        alert_name="X-Frame-Options Header Not Set",
        url="http://target.local/frame",
        path="/frame",
        operation_id="op_GET_/frame",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "enable_cors_baseline": True,
        }),
    )
    cors = [c for c in resp.candidates if c.kind.value == "cors_validator"]
    assert len(cors) == 1
    cand = cors[0]
    assert cand.status.value == "ready"
    assert cand.command is not None
    assert cand.summary.get("cors_candidate_source") == "baseline"
    assert cand.command.inputs.get("method") == "GET"
    assert cand.command.inputs.get("origin_probe") == "https://evil.example.invalid"
    assert cand.command.budget.max_requests <= 2
    assert cand.command.budget.timeout_sec <= 15


def test_planner_blocks_cors_validator_on_unsafe_method() -> None:
    _reset_store()
    _campaign()
    obs = Observation(
        observation_id="obs_zap_cors_post",
        campaign_id="cmp_plan",
        type=ObservationType.zap_alert,
        operation_id="op_POST_/api/v1/users",
        confidence=0.6,
        security_relevance=SecurityRelevance.medium,
        details={
            "alert_name": "CORS Header Misconfiguration",
            "url": "http://target.local/api/v1/users",
            "path": "/api/v1/users",
            "method": "POST",
            "operation_id": "op_POST_/api/v1/users",
        },
    )
    memory_store.store_observation(obs.observation_id, "cmp_plan", "", obs.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "enable_cors_baseline": True,
        }),
    )
    cors = [c for c in resp.candidates if c.kind.value == "cors_validator"]
    assert len(cors) == 1
    assert cors[0].status.value == "blocked"
    assert "method_not_safe" in cors[0].missing_inputs


def test_planner_cors_zap_alert_path_avoids_duplicate_baseline_candidate() -> None:
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_zap_cors_only",
        alert_name="CORS Header Misconfiguration",
        url="http://target.local/api/v1/users",
        path="/api/v1/users",
        operation_id="op_GET_/api/v1/users",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}}),
    )
    cors = [c for c in resp.candidates if c.kind.value == "cors_validator"]
    assert len(cors) == 1
    assert cors[0].summary.get("cors_candidate_source") != "baseline"


def test_planner_creates_baseline_cookie_flag_validator_candidate() -> None:
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_zap_hdr_for_cookie",
        alert_name="X-Frame-Options Header Not Set",
        url="http://target.local/frame?token=abc",
        path="/frame",
        operation_id="op_GET_/frame",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "enable_cookie_baseline": True,
        }),
    )
    cookies = [c for c in resp.candidates if c.kind.value == "cookie_flag_validator"]
    assert len(cookies) == 1
    cand = cookies[0]
    assert cand.status.value == "ready"
    assert cand.command is not None
    assert cand.command.tool_name == "cookie_flag_validator"
    assert cand.summary.get("cookie_candidate_source") == "baseline"
    assert cand.command.inputs.get("validation_mode") == "baseline_cookie_flag_check"
    assert cand.command.inputs.get("method") == "GET"
    assert cand.command.budget.max_requests <= 1
    assert cand.command.budget.timeout_sec <= 15
    summary_blob = json.dumps(cand.summary, sort_keys=True).lower()
    for bad in ("set-cookie", "request_body", "response_body", "headers", "bearer ", "token=abc"):
        assert bad not in summary_blob


def test_planner_cookie_flag_validator_disabled_without_flag() -> None:
    _reset_store()
    _campaign()
    _store_zap_alert_observation(
        observation_id="obs_passive_cookie_disabled",
        alert_name="X-Frame-Options Header Not Set",
        url="http://target.local/frame",
        path="/frame",
        operation_id="op_GET_/frame",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
        }),
    )
    cookies = [c for c in resp.candidates if c.kind.value == "cookie_flag_validator"]
    assert cookies == []


def test_planner_creates_undocumented_endpoint_validator_candidate_from_discovery() -> None:
    _reset_store()
    _campaign()
    _store_graph_vehicle_op()
    _store_raw_observation(
        observation_id="obs_disc_hidden",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/api/hidden?token=abc",
            "path": "/api/hidden",
            "method": "GET",
            "source": "zap_spider",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "undocumented_endpoint_validator"]
    assert len(matches) == 1
    cand = matches[0]
    assert cand.status.value == "ready"
    assert cand.command is not None
    assert cand.command.tool_name == "undocumented_endpoint_validator"
    assert cand.command.inputs.get("validation_mode") == "one_shot_undocumented_endpoint_check"
    assert cand.command.inputs.get("method") == "GET"
    assert cand.summary.get("path") == "/api/hidden"
    assert cand.summary.get("matched_operation_id") == ""
    blob = json.dumps(cand.summary, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=abc", "request_body", "response_body", "headers", "bearer "):
        assert bad not in blob


def test_planner_creates_js_endpoint_extractor_candidate_from_js_discovery() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_disc_js",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/static/app.js?token=abc",
            "path": "/static/app.js",
            "method": "GET",
            "source": "zap_spider",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "js_endpoint_extractor"]
    assert len(matches) == 1
    cand = matches[0]
    assert cand.status.value == "ready"
    assert cand.command is not None
    assert cand.command.tool_name == "js_endpoint_extractor"
    assert cand.command.inputs.get("validation_mode") == "static_js_endpoint_extraction"
    assert cand.command.inputs.get("js_url") == "http://target.local/static/app.js?token=abc"
    assert cand.summary.get("js_candidate_source") == "zap_spider"
    assert cand.summary.get("js_url_sanitized") == "http://target.local/static/app.js"
    blob = json.dumps(cand.summary, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "token=abc", "request_body", "response_body", "headers", "bearer "):
        assert bad not in blob


def test_planner_non_js_discovered_endpoint_does_not_create_js_extractor_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_disc_non_js",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/api/v1/users",
            "path": "/api/v1/users",
            "method": "GET",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    assert [c for c in resp.candidates if c.kind.value == "js_endpoint_extractor"] == []


def test_planner_blocks_out_of_scope_js_endpoint_extractor_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_disc_js_oos",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://evil.local/static/app.js?token=abc",
            "path": "/static/app.js",
            "method": "GET",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "js_endpoint_extractor"]
    assert len(matches) == 1
    assert matches[0].status.value == "blocked"
    assert "host_not_allowed" in matches[0].missing_inputs


def test_planner_skips_js_extractor_when_js_endpoint_extraction_result_marker_exists() -> None:
    _reset_store()
    _campaign()
    js_url = "http://target.local/static/app.js?token=abc"
    sanitized = "http://target.local/static/app.js"
    ref = hashlib.sha256(sanitized.encode("utf-8")).hexdigest()[:16]
    _store_raw_observation(
        observation_id="obs_disc_js",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": js_url,
            "path": "/static/app.js",
            "method": "GET",
            "source": "zap_spider",
        },
    )
    _store_raw_observation(
        observation_id="obs_js_marker",
        campaign_id="cmp_plan",
        observation_type=ObservationType.js_endpoint_extraction_result.value,
        details={
            "source": "js_endpoint_extractor",
            "js_url_sanitized": sanitized,
            "source_js_ref": ref,
            "source_observation_id": "",
            "result": "route_fragments_found",
            "absolute_paths_count": 0,
            "route_fragments_count": 2,
            "route_fragments_matched_count": 0,
            "endpoints_extracted_count": 0,
            "endpoints_emitted_count": 0,
            "filtered_count": 0,
            "multi_match_skipped": 0,
            "fragment_no_graph_match": 2,
            "reason_codes": ["fragment_no_graph_match"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "js_endpoint_extractor"]
    assert len(matches) == 1
    assert matches[0].status.value == "skipped_existing"
    assert matches[0].summary.get("prior_result") == "route_fragments_found"
    assert matches[0].summary.get("prior_reason_codes") == ["fragment_no_graph_match"]


def test_planner_skips_existing_js_extractor_candidate_for_same_js_url() -> None:
    _reset_store()
    _campaign()
    js_url = "http://target.local/static/app.js?token=abc"
    _store_raw_observation(
        observation_id="obs_disc_js",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": js_url,
            "path": "/static/app.js",
            "method": "GET",
        },
    )
    _store_raw_observation(
        observation_id="obs_disc_from_js",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "source": "js_endpoint_extractor",
            "path": "/api/hidden",
            "url": "http://target.local/api/hidden",
            "method": "GET",
            "source_js_ref": hashlib.sha256("http://target.local/static/app.js".encode("utf-8")).hexdigest()[:16],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "js_endpoint_extractor"]
    assert len(matches) == 1
    assert matches[0].status.value == "skipped_existing"


def test_planner_blocks_discovered_endpoint_that_matches_openapi() -> None:
    _reset_store()
    _campaign()
    _store_graph_vehicle_op()
    _store_raw_observation(
        observation_id="obs_disc_known",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/api/v1/vehicles/veh_1",
            "path": "/api/v1/vehicles/veh_1",
            "method": "GET",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "undocumented_endpoint_validator"]
    assert len(matches) == 1
    cand = matches[0]
    assert cand.status.value == "blocked"
    assert "openapi_match_present" in cand.missing_inputs
    assert cand.summary.get("matched_operation_id") == "op_GET_/api/v1/vehicles/{vehicleId}"


def test_planner_blocks_static_asset_discovered_endpoint() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_disc_asset",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/static/app.css",
            "path": "/static/app.css",
            "method": "GET",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "undocumented_endpoint_validator"]
    assert len(matches) == 1
    assert matches[0].status.value == "blocked"
    assert "static_asset_ignored" in matches[0].missing_inputs


def test_planner_skips_existing_undocumented_endpoint_signal_by_method_path() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_disc_hidden",
        campaign_id="cmp_plan",
        observation_type=ObservationType.discovered_endpoint.value,
        details={
            "url": "http://target.local/api/hidden",
            "path": "/api/hidden",
            "method": "GET",
        },
    )
    _store_raw_observation(
        observation_id="obs_undoc_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.undocumented_endpoint_signal.value,
        details={
            "method": "GET",
            "path": "/api/hidden",
            "url_sanitized": "http://target.local/api/hidden",
            "status_code": 200,
            "openapi_match": False,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 30}),
    )
    matches = [c for c in resp.candidates if c.kind.value == "undocumented_endpoint_validator"]
    assert len(matches) == 1
    assert matches[0].status.value == "skipped_existing"


def test_planner_scenario_duplicate_schema_ops_deduped():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    oid = "op_GET_/api/v1/vehicles/{vehicleId}"
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _schema_scenario_payload(scenario_id="scn_a", operation_ids=[oid]),
                _schema_scenario_payload(scenario_id="scn_b", operation_ids=[oid]),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    st = [c for c in resp.candidates if c.kind.value == "schemathesis_negative_test" and c.status == "ready"]
    assert len(st) == 1
    assert any("scenario_duplicate_schema_op_merged" in w for w in resp.warnings)


def test_planner_scenario_ordering_bola_header_schemathesis_zap_blocked():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_runtime_bola_pair()
    _store_graph_vehicle_op()
    _store_zap_alert_observation()
    body = {
        "zap": {"enabled": True},
        "bola": {"enabled": True},
        "max_candidates": 30,
        "scenario_plan": {"source": "t", "scenarios": [_schema_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    ready_kinds = [c.kind.value for c in resp.candidates if c.status == "ready"]
    assert ready_kinds[:3] == [
        "bola_replay_probe",
        "security_header_validator",
        "schemathesis_negative_test",
    ]


def test_planner_scenarios_do_not_create_toolrun_evidence_finding():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    cmds_before = len(memory_store.commands)
    runs_before = len(memory_store.tool_runs)
    ev_before = len(memory_store.evidence_packs)
    fin_before = len(memory_store.confirmed_findings)
    PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "scenario_plan": {"source": "t", "scenarios": [_schema_scenario_payload()]},
        }),
    )
    assert len(memory_store.commands) == cmds_before
    assert len(memory_store.tool_runs) == runs_before
    assert len(memory_store.evidence_packs) == ev_before
    assert len(memory_store.confirmed_findings) == fin_before


def test_planner_include_scenario_compiler_false_disables_scenario_influence():
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    _store_graph_vehicle_op()
    _store_zap_alert_observation()
    cmds_before = len(memory_store.commands)
    runs_before = len(memory_store.tool_runs)
    ev_before = len(memory_store.evidence_packs)
    fin_before = len(memory_store.confirmed_findings)
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "include_scenario_compiler": False,
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _schema_scenario_payload(),
                {
                    "scenario_id": "scn_hdr",
                    "status": "accepted",
                    "scenario_type": "security_header_validation",
                    "vulnerability_classes": ["MISCONFIG"],
                    "operation_ids": [],
                    "resource_type": "",
                    "required_preconditions": ["passive_signal_context"],
                    "candidate_workers": ["security_header_validator"],
                    "confidence": 0.99,
                    "rationale": "would boost if compiler on",
                    "blocking_codes": [],
                    "errors": [],
                    "warnings": [],
                },
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    assert not any(c.kind.value == "schemathesis_negative_test" for c in resp.candidates)
    assert not any("scenario_priority_boost" in (c.summary or {}) for c in resp.candidates)
    hdr = [c for c in resp.candidates if c.kind.value == "security_header_validator"]
    assert hdr and hdr[0].status == "ready"
    assert hdr[0].command is not None
    assert len(memory_store.commands) == cmds_before
    assert len(memory_store.tool_runs) == runs_before
    assert len(memory_store.evidence_packs) == ev_before
    assert len(memory_store.confirmed_findings) == fin_before


def test_planner_schemathesis_command_validates_with_external_campaign_openapi_url():
    """Phase 16A: trusted campaign.openapi_url may differ from allowed_hosts (spec host)."""
    _reset_store()
    spec = "https://raw.githubusercontent.com/OWASP/crAPI/develop/openapi-spec/crapi-openapi-spec.json"
    _campaign(openapi_url=spec, allowed_hosts=["target.local"])
    _store_graph_vehicle_op()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_schema_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    cmd = next(c.command for c in resp.candidates if c.kind.value == "schemathesis_negative_test" and c.command)
    assert cmd.inputs.get("openapi_url") == spec
    v = CommandValidator().validate(cmd)
    assert v.valid, v.errors


def test_planner_injection_testing_creates_ready_candidate() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "max_candidates": 20,
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    inj = [c for c in resp.candidates if c.kind.value == "injection_test" and c.status == "ready"]
    assert len(inj) == 1
    cmd = inj[0].command
    assert cmd is not None
    assert cmd.tool_name == "injection_test"
    assert cmd.worker_class == "contract_fuzzing"
    assert cmd.strategy == "injection_probe"
    assert cmd.operation_id == "op_GET_/api/v1/search"
    assert cmd.inputs.get("target_url") == "http://target.local"
    assert cmd.inputs.get("operation_id") == "op_GET_/api/v1/search"
    assert cmd.inputs.get("payload_families") == list(INJECTION_COMPILER_PAYLOAD_FAMILIES)
    assert cmd.inputs.get("max_payloads_per_param") == 1
    pcs = cmd.inputs.get("parameter_candidates") or []
    assert {"name": "q", "in": "query"} in pcs
    assert {"name": "limit", "in": "query"} in pcs
    assert cmd.success_criteria == ["injection_probe_completed"]
    assert CommandValidator().validate(cmd).valid


def test_planner_injection_testing_uses_graph_params_not_scenario_text() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _injection_scenario_payload(
                    rationale="prefer evil_param and password override",
                    resource_type="evil_param_injection_sink",
                ),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    cmd = next(c.command for c in resp.candidates if c.kind.value == "injection_test" and c.command)
    names = {p.get("name") for p in (cmd.inputs.get("parameter_candidates") or []) if isinstance(p, dict)}
    assert names == {"q", "limit"}
    assert "evil_param" not in names


def test_planner_injection_testing_only_sensitive_query_params_blocked() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_sensitive_only()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    assert not any(c.kind.value == "injection_test" and c.status == "ready" for c in resp.candidates)
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("no_safe_query_parameter_candidates" in c.missing_inputs for c in audit)


def test_planner_injection_testing_filters_sensitive_query_params() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_sensitive_mixed()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    inj = [c for c in resp.candidates if c.kind.value == "injection_test" and c.command]
    assert len(inj) == 1
    names = [p.get("name") for p in inj[0].command.inputs.get("parameter_candidates") or []]
    assert names == ["q"]


def test_planner_injection_testing_blocks_post_only_operation() -> None:
    _reset_store()
    _campaign()
    _store_graph_post_with_query()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _injection_scenario_payload(operation_ids=["op_POST_/api/v1/search"]),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    assert not any(c.kind.value == "injection_test" and c.status == "ready" for c in resp.candidates)
    audit = [c for c in resp.candidates if c.kind.value == "scenario_plan_blocked"]
    assert any("no_safe_query_parameter_candidates" in c.missing_inputs for c in audit)


def test_planner_injection_testing_dedup_existing_partial_run() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    run_id = "toolrun_inj_partial"
    memory_store.store_tool_run(
        run_id,
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": run_id,
            "campaign_id": "cmp_plan",
            "tool_name": "injection_test",
            "status": "partial",
            "command_id": "cmd_missing_inj",
            "result_ready": True,
        },
    )
    memory_store.store_tool_result(
        run_id,
        ToolResult(
            tool_run_id=run_id,
            campaign_id="cmp_plan",
            tool_name="injection_test",
            status="partial",
            observations=[
                ToolResultObservationLite(
                    observation_type="injection_signal",
                    confidence=0.6,
                    details={"operation_id": "op_GET_/api/v1/search"},
                ),
            ],
        ).model_dump(mode="json"),
    )
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    inj = [c for c in resp.candidates if c.kind.value == "injection_test"]
    assert len(inj) == 1
    assert inj[0].status == "skipped_existing"


def test_planner_injection_testing_dedup_uses_tool_result_fallback_without_command_id() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    run_id = "toolrun_inj_no_cmd"
    memory_store.store_tool_run(
        run_id,
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": run_id,
            "campaign_id": "cmp_plan",
            "tool_name": "injection_test",
            "status": "partial",
            "command_id": "",
            "result_ready": True,
        },
    )
    memory_store.store_tool_result(
        run_id,
        ToolResult(
            tool_run_id=run_id,
            campaign_id="cmp_plan",
            tool_name="injection_test",
            status="partial",
            observations=[
                ToolResultObservationLite(
                    observation_type="injection_signal",
                    confidence=0.5,
                    details={"operation_id": "op_GET_/api/v1/search", "parameter_name": "q"},
                ),
            ],
        ).model_dump(mode="json"),
    )
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    inj = [c for c in resp.candidates if c.kind.value == "injection_test"]
    assert len(inj) == 1
    assert inj[0].status == "skipped_existing"


def test_planner_injection_testing_include_scenario_compiler_false_disables_injection() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "include_scenario_compiler": False,
        "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    assert not any(c.kind.value == "injection_test" for c in resp.candidates)


def test_planner_injection_testing_does_not_create_toolrun_evidence_finding() -> None:
    _reset_store()
    _campaign()
    _store_graph_search_get()
    cmds_before = len(memory_store.commands)
    runs_before = len(memory_store.tool_runs)
    ev_before = len(memory_store.evidence_packs)
    fin_before = len(memory_store.confirmed_findings)
    PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({
            "zap": {"enabled": False},
            "bola": {"enabled": False},
            "scenario_plan": {"source": "t", "scenarios": [_injection_scenario_payload()]},
        }),
    )
    assert len(memory_store.commands) == cmds_before
    assert len(memory_store.tool_runs) == runs_before
    assert len(memory_store.evidence_packs) == ev_before
    assert len(memory_store.confirmed_findings) == fin_before


def test_planner_mass_assignment_creates_diagnostic_property_mutation_candidate() -> None:
    _reset_store()
    _campaign()
    _store_graph_mass_assignment_patch()
    _store_corpus_seed(request_id="req_seed_mass_1")
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "max_candidates": 20,
        "scenario_plan": {"source": "t", "scenarios": [_mass_assignment_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    rows = [c for c in resp.candidates if c.kind.value == "property_mutation_test" and c.status == "ready"]
    assert len(rows) == 1
    cmd = rows[0].command
    assert cmd is not None
    assert cmd.worker_class == "access_control"
    assert cmd.strategy == "property_mutation_probe"
    assert cmd.tool_name == "property_mutation_test"
    assert cmd.operation_id == "op_PATCH_/api/v1/users/{userId}"
    assert cmd.seed_request_id == "req_seed_mass_1"
    assert cmd.inputs.get("mutation_policy") == "diagnostic_only"
    assert cmd.inputs.get("diagnostic_only") is True
    assert cmd.inputs.get("seed_request_id") == "req_seed_mass_1"
    assert cmd.inputs.get("max_mutations") == 1
    assert cmd.inputs.get("target_url") == "http://target.local"
    assert cmd.inputs.get("operation_id") == "op_PATCH_/api/v1/users/{userId}"
    assert "isAdmin" in (cmd.inputs.get("sensitive_fields") or [])
    assert "owner_id" in (cmd.inputs.get("sensitive_fields") or [])
    assert "displayName" not in (cmd.inputs.get("sensitive_fields") or [])
    assert "description" not in (cmd.inputs.get("sensitive_fields") or [])
    assert cmd.budget.max_requests == 0
    assert cmd.budget.timeout_sec == 30
    assert cmd.success_criteria == ["property_mutation_probe_completed"]
    summary = rows[0].summary or {}
    assert summary.get("mass_assignment_candidate_result") == "ready"
    assert summary.get("seed_request_id_present") is True
    assert summary.get("fields_selected_count", 0) >= 2
    for forbidden in (
        "Authorization",
        "authorization",
        "Cookie",
        "cookie",
        "headers",
        "request_body",
        "response_body",
        "payload",
        "token",
    ):
        assert forbidden not in cmd.inputs
    assert CommandValidator().validate(cmd).valid


def test_planner_mass_assignment_without_seed_stays_safe_and_marks_audit_flag() -> None:
    _reset_store()
    _campaign()
    _store_graph_mass_assignment_patch()
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_mass_assignment_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    rows = [c for c in resp.candidates if c.kind.value == "property_mutation_test"]
    assert len(rows) == 1
    assert rows[0].status.value == "blocked"
    assert rows[0].command is None
    summary = rows[0].summary or {}
    assert summary.get("mass_assignment_candidate_result") == "blocked_missing_seed_context"
    assert summary.get("seed_request_id_present") is False
    assert "missing_seed_context" in summary.get("audit_flags", [])
    assert "missing_seed_context" in summary.get("reason_codes", [])


def test_planner_mass_assignment_with_empty_body_fields_adds_no_sensitive_fields_audit_flag() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_PATCH_/api/v1/users/{userId}",
                method="PATCH",
                path_template="/api/v1/users/{userId}",
                body_fields=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_corpus_seed(request_id="req_seed_mass_2")
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_mass_assignment_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    rows = [c for c in resp.candidates if c.kind.value == "property_mutation_test"]
    assert len(rows) == 1
    assert rows[0].status.value == "blocked"
    assert rows[0].command is None
    summary = rows[0].summary or {}
    assert summary.get("mass_assignment_candidate_result") == "blocked_no_sensitive_fields"
    assert "no_sensitive_fields" in summary.get("audit_flags", [])
    assert "no_writable_sensitive_fields" in summary.get("reason_codes", [])
    assert summary.get("fields_selected_count") == 0


def test_planner_mass_assignment_content_only_body_fields_blocked() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_PATCH_/api/v1/users/{userId}",
                method="PATCH",
                path_template="/api/v1/users/{userId}",
                body_fields=["content"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_corpus_seed(request_id="req_seed_mass_3")
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_mass_assignment_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    rows = [c for c in resp.candidates if c.kind.value == "property_mutation_test"]
    assert len(rows) == 1
    assert rows[0].status.value == "blocked"
    summary = rows[0].summary or {}
    assert summary.get("mass_assignment_candidate_result") == "blocked_no_sensitive_fields"
    assert summary.get("fields_considered_count") == 1
    assert summary.get("fields_selected_count") == 0


def test_planner_mass_assignment_dedup_existing_run_skips_candidate() -> None:
    _reset_store()
    _campaign()
    _store_graph_mass_assignment_patch()
    memory_store.store_command(
        "cmd_mass_existing",
        "cmp_plan",
        {
            "command_id": "cmd_mass_existing",
            "campaign_id": "cmp_plan",
            "worker_class": "access_control",
            "strategy": "property_mutation_probe",
            "tool_name": "property_mutation_test",
            "operation_id": "op_PATCH_/api/v1/users/{userId}",
            "inputs": {"operation_id": "op_PATCH_/api/v1/users/{userId}"},
        },
    )
    memory_store.store_tool_run(
        "toolrun_mass_existing",
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": "toolrun_mass_existing",
            "campaign_id": "cmp_plan",
            "tool_name": "property_mutation_test",
            "status": "finished",
            "command_id": "cmd_mass_existing",
            "result_ready": True,
        },
    )
    body = {
        "zap": {"enabled": False},
        "bola": {"enabled": False},
        "scenario_plan": {"source": "t", "scenarios": [_mass_assignment_scenario_payload()]},
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    rows = [c for c in resp.candidates if c.kind.value == "property_mutation_test"]
    assert len(rows) == 1
    assert rows[0].status == "skipped_existing"
    assert rows[0].command is None


def test_planner_ordering_injection_test_after_schemathesis_before_zap() -> None:
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
                method="GET",
                path_template="/api/v1/vehicles/{vehicleId}",
                owasp_candidates=["API1_BOLA"],
                risk_hints=["object_id_in_path"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/v1/search",
                method="GET",
                path_template="/api/v1/search",
                query_params=["q", "limit"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_zap_alert_observation()
    body = {
        "zap": {"enabled": True},
        "bola": {"enabled": False},
        "max_candidates": 30,
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _schema_scenario_payload(),
                _injection_scenario_payload(),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    ready_kinds = [c.kind.value for c in resp.candidates if c.status == "ready"]
    assert ready_kinds[0] == "security_header_validator"
    assert ready_kinds.index("schemathesis_negative_test") < ready_kinds.index("injection_test")
    if "zap_discovery_passive" in ready_kinds:
        assert ready_kinds.index("injection_test") < ready_kinds.index("zap_discovery_passive")


def test_planner_ordering_property_mutation_after_injection_before_zap() -> None:
    _reset_store()
    _campaign(openapi_url="http://target.local/openapi.json")
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
                method="GET",
                path_template="/api/v1/vehicles/{vehicleId}",
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/v1/search",
                method="GET",
                path_template="/api/v1/search",
                query_params=["q"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_PATCH_/api/v1/users/{userId}",
                method="PATCH",
                path_template="/api/v1/users/{userId}",
                body_fields=["isAdmin"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_corpus_seed(
        request_id="req_seed_mass_order",
        operation_id="op_PATCH_/api/v1/users/{userId}",
        method="PATCH",
        path_template="/api/v1/users/{userId}",
    )
    _store_zap_alert_observation()
    body = {
        "zap": {"enabled": True},
        "bola": {"enabled": False},
        "max_candidates": 30,
        "scenario_plan": {
            "source": "t",
            "scenarios": [
                _schema_scenario_payload(),
                _injection_scenario_payload(),
                _mass_assignment_scenario_payload(),
            ],
        },
    }
    resp = PlannerService().plan("cmp_plan", PlannerRequest.model_validate(body))
    ready_kinds = [c.kind.value for c in resp.candidates if c.status == "ready"]
    assert "injection_test" in ready_kinds
    assert "property_mutation_test" in ready_kinds
    assert ready_kinds.index("injection_test") < ready_kinds.index("property_mutation_test")
    if "zap_discovery_passive" in ready_kinds:
        assert ready_kinds.index("property_mutation_test") < ready_kinds.index("zap_discovery_passive")


def test_planner_data_exposure_validator_ready_for_get_operations_only() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/items",
                method="GET",
                path_template="/api/v1/items",
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/api/v1/items",
                method="POST",
                path_template="/api/v1/items",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator" and c.status.value == "ready"]
    assert len(rows) == 1
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "data_exposure_validator"
    assert rows[0].command.inputs.get("method") == "GET"
    assert rows[0].command.operation_id == "op_GET_/api/v1/items"


def test_planner_ssrf_candidate_detector_ready_for_url_like_request_fields() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/workshop/api/mechanic/receive_report",
                method="POST",
                path_template="/workshop/api/mechanic/receive_report",
                body_fields=["mechanic_api", "title"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "ssrf_candidate_detector"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "ssrf_candidate_detector"
    assert rows[0].command.worker_class == "input_validation"
    assert rows[0].command.strategy == "detect_ssrf_candidate_fields"
    assert rows[0].command.inputs.get("validation_mode") == "ssrf_candidate_detection"
    assert rows[0].summary.get("ssrf_candidate_source") == "openapi_schema"
    assert rows[0].summary.get("candidate_field_count") == 1
    sample = rows[0].summary.get("candidate_fields_sample") or []
    assert sample[0]["field_name"] == "mechanic_api"


def test_ssrf_candidate_detector_ranks_contact_like_field_above_product_image_field() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/integrations/contact-service",
                method="POST",
                path_template="/integrations/contact-service",
                body_fields=["image_url", "mechanic_api"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "ssrf_candidate_detector"]
    assert len(rows) == 1
    command = rows[0].command
    assert command is not None
    fields = command.inputs.get("candidate_fields") if isinstance(command.inputs.get("candidate_fields"), list) else []
    assert len(fields) >= 2
    assert fields[0]["field_name"] == "mechanic_api"
    assert any(item["field_name"] == "image_url" for item in fields)


def test_ssrf_candidate_detector_caps_candidate_fields_to_ten_after_scoring() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/services/bulk-connect",
                method="POST",
                path_template="/services/bulk-connect",
                body_fields=[
                    "callback_url", "notify_url", "service_endpoint", "target_url", "destination_url",
                    "integration_url", "connect_uri", "request_url", "webhook_url", "contact_api",
                    "backup_url", "avatar_url", "image_url",
                ],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "ssrf_candidate_detector"]
    assert len(rows) == 1
    command = rows[0].command
    assert command is not None
    fields = command.inputs.get("candidate_fields") if isinstance(command.inputs.get("candidate_fields"), list) else []
    assert len(fields) == 10


def test_planner_ssrf_candidate_detector_not_created_without_request_fields() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/ping",
                method="GET",
                path_template="/api/v1/ping",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    assert [c for c in resp.candidates if c.kind.value == "ssrf_candidate_detector"] == []


def test_planner_ssrf_candidate_detector_skipped_when_signal_exists() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/api/v1/hooks",
                method="POST",
                path_template="/api/v1/hooks",
                body_fields=["callback_url"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_ssrf_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.ssrf_candidate_signal.value,
        details={
            "operation_id": "op_POST_/api/v1/hooks",
            "field_name": "callback_url",
            "field_path": "$.callback_url",
            "validation_mode": "ssrf_candidate_detection",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "ssrf_candidate_detector"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_data_exposure_validator_skips_static_get_paths() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/static/app.js",
                method="GET",
                path_template="/static/app.js",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    assert [c for c in resp.candidates if c.kind.value == "data_exposure_validator"] == []


def test_planner_data_exposure_validator_skipped_when_inventory_exists() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/profile",
                method="GET",
                path_template="/api/v1/profile",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_inv_1",
        campaign_id="cmp_plan",
        observation_type=ObservationType.response_field_inventory.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/profile",
            "path": "/api/v1/profile",
            "method": "GET",
            "field_count": 2,
            "sensitive_field_count": 0,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"
    assert rows[0].reason == "Data exposure validator already executed for this operation."
    assert "prior_result" not in rows[0].summary


def test_planner_data_exposure_probe_result_skips_duplicate_candidate() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/workshop/api/mechanic/receive_report",
                method="GET",
                path_template="/workshop/api/mechanic/receive_report",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_dex_probe_1",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_probe_result.value,
        details={
            "source": "data_exposure_validator",
            "operation_id": "op_GET_/workshop/api/mechanic/receive_report",
            "path": "/workshop/api/mechanic/receive_report",
            "method": "GET",
            "status_code": 400,
            "content_type": "application/json",
            "result": "non_200_response",
            "field_count": 0,
            "sensitive_field_count": 0,
            "sensitive_categories": [],
            "reason_codes": ["non_200_response"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"
    assert rows[0].reason == "Data exposure validator already executed for this operation."
    assert rows[0].summary.get("prior_result") == "non_200_response"
    assert rows[0].summary.get("prior_status_code") == 400
    assert rows[0].summary.get("prior_reason_codes") == ["non_200_response"]


def test_planner_data_exposure_probe_on_one_operation_other_still_ready() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/workshop/api/mechanic/receive_report",
                method="GET",
                path_template="/workshop/api/mechanic/receive_report",
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/v1/ping",
                method="GET",
                path_template="/api/v1/ping",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_dex_probe_only_a",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_probe_result.value,
        details={
            "source": "data_exposure_validator",
            "operation_id": "op_GET_/workshop/api/mechanic/receive_report",
            "path": "/workshop/api/mechanic/receive_report",
            "method": "GET",
            "status_code": 400,
            "content_type": "application/json",
            "result": "non_200_response",
            "field_count": 0,
            "sensitive_field_count": 0,
            "sensitive_categories": [],
            "reason_codes": ["non_200_response"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    dex = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    by_op = {c.summary.get("operation_id"): c for c in dex}
    assert by_op["op_GET_/workshop/api/mechanic/receive_report"].status.value == "skipped_existing"
    assert by_op["op_GET_/api/v1/ping"].status.value == "ready"


def test_planner_data_exposure_path_fallback_dedup_when_probe_missing_operation_id() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/workshop/api/mechanic/receive_report",
                method="GET",
                path_template="/workshop/api/mechanic/receive_report",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_dex_probe_no_opid",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_probe_result.value,
        details={
            "source": "data_exposure_validator",
            "path": "/workshop/api/mechanic/receive_report",
            "method": "GET",
            "status_code": 400,
            "content_type": "application/json",
            "result": "non_200_response",
            "field_count": 0,
            "sensitive_field_count": 0,
            "sensitive_categories": [],
            "reason_codes": ["non_200_response"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"
    assert rows[0].summary.get("prior_result") == "non_200_response"


def test_planner_data_exposure_signal_still_dedups_candidate() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/signal",
                method="GET",
                path_template="/api/v1/signal",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_dex_sig_dedup",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_signal.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/signal",
            "path": "/api/v1/signal",
            "method": "GET",
            "status_code": 200,
            "sensitive_field_count": 1,
            "sensitive_categories": ["identity"],
            "sensitive_fields": [{"field_name": "email", "field_path": "$.email", "category": "identity"}],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_auth_flow_detector_ready_when_graph_exists() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/ping",
                method="GET",
                path_template="/api/ping",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "auth_flow_detector"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "auth_flow_detector"
    assert rows[0].command.worker_class == "auth_context"
    assert rows[0].command.strategy == "detect_auth_flow"
    blob = json.dumps(rows[0].summary, ensure_ascii=False).lower()
    assert "bearer " not in blob
    assert "authorization" not in blob


def test_planner_auth_flow_skipped_when_existing_signal() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/ping",
                method="GET",
                path_template="/api/ping",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_af_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.auth_flow_signal.value,
        details={
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": False,
            "signup_candidates": [],
            "login_candidates": [],
            "token_response_candidates": [],
            "profile_candidates": [],
            "missing_prerequisites": [],
            "reason_codes": ["no_auth_flow_patterns"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "auth_flow_detector"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_test_account_materializer_ready_from_auth_flow_signal() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/identity/api/auth/signup",
                method="POST",
                path_template="/identity/api/auth/signup",
                body_fields=["name", "email", "number", "password"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/identity/api/auth/login",
                method="POST",
                path_template="/identity/api/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_auth_flow_materializer",
        campaign_id="cmp_plan",
        observation_type=ObservationType.auth_flow_signal.value,
        details={
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": True,
            "signup_candidates": [{"operation_id": "op_POST_/identity/api/auth/signup", "method": "POST", "path": "/identity/api/auth/signup"}],
            "login_candidates": [{"operation_id": "op_POST_/identity/api/auth/login", "method": "POST", "path": "/identity/api/auth/login"}],
            "token_response_candidates": [{"operation_id": "op_POST_/identity/api/auth/login", "method": "POST", "path": "/identity/api/auth/login"}],
            "profile_candidates": [],
            "missing_prerequisites": [],
            "reason_codes": [],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "test_account_materializer"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "test_account_materializer"
    assert rows[0].command.worker_class == "auth_context"
    assert rows[0].command.strategy == "materialize_test_accounts"


def test_planner_test_account_materializer_skipped_when_already_materialized() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/identity/api/auth/signup",
                method="POST",
                path_template="/identity/api/auth/signup",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/identity/api/auth/login",
                method="POST",
                path_template="/identity/api/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_auth_flow_materializer_skip",
        campaign_id="cmp_plan",
        observation_type=ObservationType.auth_flow_signal.value,
        details={
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": True,
            "signup_candidates": [{"operation_id": "op_POST_/identity/api/auth/signup", "method": "POST", "path": "/identity/api/auth/signup"}],
            "login_candidates": [{"operation_id": "op_POST_/identity/api/auth/login", "method": "POST", "path": "/identity/api/auth/login"}],
            "token_response_candidates": [],
            "profile_candidates": [],
            "missing_prerequisites": [],
            "reason_codes": [],
        },
    )
    _store_raw_observation(
        observation_id="obs_materialized_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "auth_profiles_created_count": 2,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "test_account_materializer"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_test_account_materializer_blocked_when_signup_or_login_missing() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_POST_/identity/api/auth/login",
                method="POST",
                path_template="/identity/api/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_auth_flow_materializer_blocked",
        campaign_id="cmp_plan",
        observation_type=ObservationType.auth_flow_signal.value,
        details={
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": True,
            "signup_candidates": [],
            "login_candidates": [{"operation_id": "op_POST_/identity/api/auth/login", "method": "POST", "path": "/identity/api/auth/login"}],
            "token_response_candidates": [],
            "profile_candidates": [],
            "missing_prerequisites": [],
            "reason_codes": [],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "test_account_materializer"]
    assert len(rows) == 1
    assert rows[0].status.value == "blocked"
    assert "signup_operation_id_missing" in (rows[0].missing_inputs or [])


def test_planner_data_exposure_llm_advisor_orders_collection_before_parameterized_get() -> None:
    _reset_store()
    _campaign()

    def llm(_sys: str, user: str) -> str:
        assert "Bearer" not in user
        assert "Authorization" not in user
        return json.dumps(
            {
                "ranked_candidates": [
                    {
                        "operation_id": "op_GET_/api/v1/orders/{orderId}",
                        "recommended": True,
                        "priority": 0,
                        "requires_seed": True,
                        "requires_auth": True,
                        "reason": "LLM prefers first",
                    },
                    {
                        "operation_id": "op_GET_/api/v1/me",
                        "recommended": True,
                        "priority": 1,
                        "requires_seed": False,
                        "requires_auth": False,
                        "reason": "LLM second",
                    },
                ],
                "warnings": [],
            }
        )

    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                successful_seed_request_ids=[],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/v1/orders/{orderId}",
                method="GET",
                path_template="/api/v1/orders/{orderId}",
                path_params=["orderId"],
                successful_seed_request_ids=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    req = PlannerRequest.model_validate(
        {"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40, "enable_llm_candidate_advisor": True}
    )
    resp = PlannerService(advisor=LlmCandidateAdvisor(llm_complete=llm)).plan("cmp_plan", req)
    dex = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(dex) == 2
    by_path = {str(c.summary.get("path_template")): c for c in dex}
    blocked = by_path["/api/v1/orders/{orderId}"]
    ready = by_path["/api/v1/me"]
    assert blocked.status.value == "blocked"
    assert "path_params_without_seed" in (blocked.missing_inputs or [])
    assert ready.status.value == "ready"
    assert ready.summary.get("llm_candidate_advisor_used") is True
    assert blocked.summary.get("llm_candidate_priority") == 0
    assert ready.summary.get("llm_candidate_priority") == 1


def test_planner_data_exposure_parameterized_stays_blocked_even_if_llm_prioritizes_it() -> None:
    _reset_store()
    _campaign()

    def llm(_sys: str, _user: str) -> str:
        return json.dumps(
            {
                "ranked_candidates": [
                    {
                        "operation_id": "op_GET_/api/v1/orders/{orderId}",
                        "recommended": True,
                        "priority": 0,
                        "requires_seed": False,
                        "requires_auth": False,
                        "reason": "LLM wrong: no seed",
                    },
                ],
                "warnings": [],
            }
        )

    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/orders/{orderId}",
                method="GET",
                path_template="/api/v1/orders/{orderId}",
                path_params=["orderId"],
                successful_seed_request_ids=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    req = PlannerRequest.model_validate(
        {"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40, "enable_llm_candidate_advisor": True}
    )
    resp = PlannerService(advisor=LlmCandidateAdvisor(llm_complete=llm)).plan("cmp_plan", req)
    row = next(c for c in resp.candidates if c.kind.value == "data_exposure_validator")
    assert row.status.value == "blocked"
    assert row.command is None
    assert row.summary.get("llm_candidate_advisor_used") is True


def test_planner_data_exposure_advisor_fallback_when_llm_unavailable() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/a",
                method="GET",
                path_template="/api/a",
                path_params=[],
                resource_type="user",
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/b",
                method="GET",
                path_template="/api/b",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    req = PlannerRequest.model_validate(
        {"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40, "enable_llm_candidate_advisor": True}
    )
    resp = PlannerService(advisor=LlmCandidateAdvisor(llm_complete=None)).plan("cmp_plan", req)
    ready = [c for c in resp.candidates if c.kind.value == "data_exposure_validator" and c.status.value == "ready"]
    assert len(ready) == 2
    assert all(c.summary.get("llm_candidate_advisor_used") is False for c in ready)


def test_planner_data_exposure_advisor_summary_no_raw_leakage() -> None:
    _reset_store()
    _campaign()

    def llm(_sys: str, _user: str) -> str:
        return json.dumps(
            {
                "ranked_candidates": [
                    {
                        "operation_id": "op_GET_/api/v1/me",
                        "recommended": True,
                        "priority": 0,
                        "requires_seed": False,
                        "requires_auth": False,
                        "reason": "ok",
                    },
                ],
                "warnings": [],
            }
        )

    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    req = PlannerRequest.model_validate(
        {"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40, "enable_llm_candidate_advisor": True}
    )
    resp = PlannerService(advisor=LlmCandidateAdvisor(llm_complete=llm)).plan("cmp_plan", req)
    row = next(c for c in resp.candidates if c.kind.value == "data_exposure_validator")
    blob = json.dumps(row.summary, ensure_ascii=False).lower()
    for bad in ("bearer ", "authorization:", "set-cookie", "response_body", "request_body"):
        assert bad not in blob


def test_planner_data_exposure_validator_skipped_when_tool_run_exists() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/ping",
                method="GET",
                path_template="/api/v1/ping",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    memory_store.store_command(
        "cmd_dex_existing",
        "cmp_plan",
        {
            "command_id": "cmd_dex_existing",
            "campaign_id": "cmp_plan",
            "worker_class": "access_control",
            "strategy": "validate_response_field_exposure",
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/ping",
            "inputs": {
                "target_url": "http://target.local",
                "operation_id": "op_GET_/api/v1/ping",
                "path_template": "/api/v1/ping",
                "validation_mode": "response_field_inventory_check",
            },
        },
    )
    memory_store.store_tool_run(
        "toolrun_dex_existing",
        "cmp_plan",
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": "toolrun_dex_existing",
            "campaign_id": "cmp_plan",
            "tool_name": "data_exposure_validator",
            "status": "finished",
            "command_id": "cmd_dex_existing",
            "result_ready": True,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "data_exposure_validator"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_authenticated_data_exposure_candidate_ready_when_materialized_owner_exists() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={"token_field_path": "$.token"},
    )
    _store_raw_observation(
        observation_id="obs_test_authmat",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "attacker_auth_profile_id": "",
            "auth_profiles_created_count": 1,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and (c.command.inputs.get("auth_mode") if c.command else c.summary.get("auth_mode")) == "authenticated"
    ]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].summary.get("auth_profile_id") == profile.auth_profile_id
    assert rows[0].summary.get("role_hint") == "owner"


def test_planner_authenticated_data_exposure_retry_created_after_unauth_401() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_raw_observation(
        observation_id="obs_authmat_401",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "auth_profiles_created_count": 1,
        },
    )
    _store_raw_observation(
        observation_id="obs_unauth_401_probe",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_probe_result.value,
        details={
            "source": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "method": "GET",
            "status_code": 401,
            "content_type": "application/json",
            "result": "non_200_response",
            "field_count": 0,
            "sensitive_field_count": 0,
            "sensitive_categories": [],
            "reason_codes": ["non_200_response"],
            "auth_mode": "unauthenticated",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and (c.command.inputs.get("auth_mode") if c.command else c.summary.get("auth_mode")) == "authenticated"
    ]
    assert len(auth_rows) == 1
    assert auth_rows[0].summary.get("prior_unauth_status_code") == 401
    assert "retry_after_unauth_401" in (auth_rows[0].summary.get("reason_codes") or [])


def test_planner_authenticated_data_exposure_dedup_separate_from_unauthenticated() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_raw_observation(
        observation_id="obs_authmat_dedup_sep",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "auth_profiles_created_count": 1,
        },
    )
    _store_raw_observation(
        observation_id="obs_unauth_only_inventory",
        campaign_id="cmp_plan",
        observation_type=ObservationType.response_field_inventory.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "method": "GET",
            "field_count": 1,
            "sensitive_field_count": 0,
            "auth_mode": "unauthenticated",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and (c.command.inputs.get("auth_mode") if c.command else c.summary.get("auth_mode")) == "authenticated"
    ]
    assert len(auth_rows) == 1
    assert auth_rows[0].status.value == "ready"


def test_planner_existing_authenticated_probe_skips_authenticated_candidate() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_raw_observation(
        observation_id="obs_authmat_existing_auth_probe",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "auth_profiles_created_count": 1,
        },
    )
    _store_raw_observation(
        observation_id="obs_authenticated_probe_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.data_exposure_probe_result.value,
        details={
            "source": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "method": "GET",
            "status_code": 200,
            "content_type": "application/json",
            "result": "fields_extracted",
            "field_count": 2,
            "sensitive_field_count": 0,
            "sensitive_categories": [],
            "reason_codes": ["fields_extracted"],
            "auth_mode": "authenticated",
            "auth_profile_id": profile.auth_profile_id,
            "role_hint": "owner",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and c.summary.get("auth_mode") == "authenticated"
    ]
    assert len(auth_rows) == 1
    assert auth_rows[0].status.value == "skipped_existing"


def test_planner_no_authenticated_data_exposure_candidate_without_auth_profile() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and c.summary.get("auth_mode") == "authenticated"
    ]
    assert auth_rows == []


def test_planner_no_authenticated_data_exposure_candidate_when_owner_profile_missing_in_materialization() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    _store_raw_observation(
        observation_id="obs_authmat_missing_owner",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and c.summary.get("auth_mode") == "authenticated"
    ]
    assert auth_rows == []


def test_planner_authenticated_inventory_creates_resource_instance_extractor_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_rfi_resource_source",
        campaign_id="cmp_plan",
        observation_type=ObservationType.response_field_inventory.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "field_count": 13,
            "sensitive_field_count": 2,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_instance_extractor"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].summary.get("source_observation_id") == "obs_rfi_resource_source"
    assert rows[0].summary.get("auth_profile_id") == "authprof_owner_1"
    assert rows[0].summary.get("resource_instance_candidate_source") == "authenticated_inventory"
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "resource_instance_extractor"


def test_planner_successful_materialization_and_no_object_refs_creates_resource_seed_worker_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_seed_ready",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_seed_worker"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].summary.get("owner_auth_profile_id") == "authprof_owner_1"
    assert rows[0].summary.get("object_refs_count") == 0
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "resource_seed_worker"
    assert rows[0].command.inputs.get("validation_mode") == "resource_seed"
    assert rows[0].command.inputs.get("owner_auth_profile_id") == "authprof_owner_1"
    blob = json.dumps(rows[0].summary, sort_keys=True).lower()
    for bad in ("authorization", "cookie", "token", "password", "bearer"):
        assert bad not in blob


def test_planner_resource_seed_worker_dedups_existing_seeded_result() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_seeded_ok",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
        },
    )
    _store_raw_observation(
        observation_id="obs_seeded_done",
        campaign_id="cmp_plan",
        observation_type=ObservationType.resource_seed_result.value,
        details={
            "validation_mode": "resource_seed",
            "seed_status": "seeded",
            "owner_auth_profile_id": "authprof_owner_1",
            "object_refs_created_count": 1,
            "object_refs": [],
            "http_calls_count": 1,
            "reason_codes": ["resource_ids_extracted"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_seed_worker"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_missing_owner_auth_profile_id_means_no_seed_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_no_owner",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_seed_worker"]
    assert rows == []


def test_planner_materialized_profiles_and_resource_instances_create_bola_object_pair_builder_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_bola_pair_ready",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
        },
    )
    ResourceInstanceStore().create_resource_instance(
        campaign_id="cmp_plan",
        resource_type="vehicle",
        object_id_field="vehicleId",
        raw_object_id="veh-1",
        source_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        source_path="/api/v1/vehicles/{vehicleId}",
        source_auth_profile_id="authprof_owner_1",
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_object_pair_builder"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].command is not None
    assert rows[0].command.tool_name == "bola_object_pair_builder"
    assert rows[0].command.inputs.get("validation_mode") == "bola_object_pair_building"
    assert rows[0].summary.get("owner_auth_profile_id") == "authprof_owner_1"
    assert rows[0].summary.get("attacker_auth_profile_id") == "authprof_attacker_1"


def test_planner_missing_attacker_profile_blocks_bola_object_pair_builder_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_no_attacker",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "",
        },
    )
    ResourceInstanceStore().create_resource_instance(
        campaign_id="cmp_plan",
        resource_type="vehicle",
        object_id_field="vehicleId",
        raw_object_id="veh-1",
        source_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        source_path="/api/v1/vehicles/{vehicleId}",
        source_auth_profile_id="authprof_owner_1",
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_object_pair_builder"]
    assert len(rows) == 1
    assert rows[0].status.value == "blocked"


def test_planner_bola_object_pair_builder_dedups_existing_inventory_observation() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_bola_pair_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
        },
    )
    ResourceInstanceStore().create_resource_instance(
        campaign_id="cmp_plan",
        resource_type="vehicle",
        object_id_field="vehicleId",
        raw_object_id="veh-1",
        source_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        source_path="/api/v1/vehicles/{vehicleId}",
        source_auth_profile_id="authprof_owner_1",
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
    )
    _store_raw_observation(
        observation_id="obs_bola_pairs_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_object_pair_inventory.value,
        details={"validation_mode": "bola_object_pair_building", "object_pairs_count": 1, "object_pairs": []},
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_object_pair_builder"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_no_resource_instances_means_no_bola_object_pair_builder_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_bola_pair_no_resources",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_object_pair_builder"]
    assert rows == []


def test_planner_creates_bola_replay_probe_candidate_from_object_pair() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_authmat_replay_ready",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "auth_profiles_created_count": 2,
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
        },
    )
    memory_store.store_runtime_bola_object_pair(
        "objpair_1",
        "cmp_plan",
        {
            "object_pair_id": "objpair_1",
            "campaign_id": "cmp_plan",
            "resource_type": "post",
            "object_ref_id": "objref_1",
            "object_id_ref": "objidref_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
            "target_path_template": "/community/api/v2/community/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "confidence": "high",
            "created_by": "bola_object_pair_builder",
            "reason_codes": ["path_param_resource_match"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    assert len(rows) == 1
    assert rows[0].status.value == "ready"
    assert rows[0].command is not None
    assert rows[0].command.strategy == "replay_bola_object_pair"
    assert rows[0].command.inputs.get("object_pair_id") == "objpair_1"
    assert rows[0].command.inputs.get("validation_mode") == "bola_replay"


def test_planner_dedups_existing_bola_replay_result_by_object_pair_id() -> None:
    _reset_store()
    _campaign()
    memory_store.store_runtime_bola_object_pair(
        "objpair_1",
        "cmp_plan",
        {
            "object_pair_id": "objpair_1",
            "campaign_id": "cmp_plan",
            "resource_type": "post",
            "object_ref_id": "objref_1",
            "object_id_ref": "objidref_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
            "target_path_template": "/community/api/v2/community/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "confidence": "high",
            "created_by": "bola_object_pair_builder",
            "reason_codes": ["path_param_resource_match"],
        },
    )
    _store_raw_observation(
        observation_id="obs_bola_replay_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_1",
            "result": "attacker_access_granted",
            "access_granted": True,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_rotates_to_next_object_pair_when_first_invalid_object_pair() -> None:
    _reset_store()
    _campaign()
    _store_runtime_bola_pair(
        object_pair_id="objpair_a",
        target_operation_id="op_GET_/api/v1/posts/{postId}",
        target_path_template="/api/v1/posts/{postId}",
        path_param_name="postId",
        confidence="high",
    )
    _store_runtime_bola_pair(
        object_pair_id="objpair_b",
        target_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        target_path_template="/api/v1/vehicles/{vehicleId}",
        path_param_name="vehicleId",
        confidence="high",
    )
    _store_raw_observation(
        observation_id="obs_bola_invalid_a",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_a",
            "result": "invalid_object_pair",
            "access_granted": False,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    ready = [c for c in rows if c.status.value == "ready"]
    assert len(ready) == 1
    assert ready[0].command is not None
    assert ready[0].command.inputs.get("object_pair_id") == "objpair_b"
    assert "objpair_b" in (ready[0].dedup_key or "")


def test_planner_stops_replay_when_all_object_pairs_have_results() -> None:
    _reset_store()
    _campaign()
    _store_runtime_bola_pair(object_pair_id="objpair_a")
    _store_runtime_bola_pair(object_pair_id="objpair_b")
    _store_raw_observation(
        observation_id="obs_bola_a_done",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={"validation_mode": "bola_replay", "object_pair_id": "objpair_a", "result": "invalid_object_pair", "access_granted": False},
    )
    _store_raw_observation(
        observation_id="obs_bola_b_done",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={"validation_mode": "bola_replay", "object_pair_id": "objpair_b", "result": "attacker_access_denied", "access_granted": False},
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    assert rows
    assert all(c.status.value != "ready" for c in rows)


def test_planner_stops_replay_candidates_after_granted_result_exists() -> None:
    _reset_store()
    _campaign()
    _store_runtime_bola_pair(object_pair_id="objpair_a")
    _store_runtime_bola_pair(object_pair_id="objpair_b")
    _store_raw_observation(
        observation_id="obs_bola_granted_a",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={"validation_mode": "bola_replay", "object_pair_id": "objpair_a", "result": "attacker_access_granted", "access_granted": True},
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    assert rows
    assert all(c.status.value != "ready" for c in rows)


def test_planner_bola_replay_ordering_prefers_vehicle_high_over_post_medium() -> None:
    _reset_store()
    _campaign()
    _store_runtime_bola_pair(
        object_pair_id="objpair_post_medium",
        target_operation_id="op_GET_/api/v1/posts/{postId}",
        target_path_template="/api/v1/posts/{postId}",
        path_param_name="postId",
        confidence="medium",
        resource_type="post",
    )
    _store_runtime_bola_pair(
        object_pair_id="objpair_vehicle_high",
        target_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        target_path_template="/api/v1/vehicles/{vehicleId}",
        path_param_name="vehicleId",
        confidence="high",
        resource_type="vehicle",
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe" and c.status.value == "ready"]
    assert len(rows) == 1
    assert rows[0].command is not None
    assert rows[0].command.inputs.get("object_pair_id") == "objpair_vehicle_high"
    assert "objpair_vehicle_high" in (rows[0].dedup_key or "")


def test_planner_bola_pair_scoring_penalizes_previous_owner_400_invalid_pair() -> None:
    _reset_store()
    _campaign()
    memory_store.store_runtime_bola_object_pair(
        "objpair_post_high",
        "cmp_plan",
        {
            "object_pair_id": "objpair_post_high",
            "campaign_id": "cmp_plan",
            "resource_type": "post",
            "object_ref_id": "objref_post_1",
            "object_id_ref": "objidref_post_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/api/v1/posts/{postId}",
            "target_path_template": "/api/v1/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "confidence": "high",
            "created_by": "bola_object_pair_builder",
            "reason_codes": ["path_param_resource_match"],
            "metadata": {"baseline_probability_score": 92.0},
        },
    )
    memory_store.store_runtime_bola_object_pair(
        "objpair_vehicle_medium",
        "cmp_plan",
        {
            "object_pair_id": "objpair_vehicle_medium",
            "campaign_id": "cmp_plan",
            "resource_type": "vehicle",
            "object_ref_id": "objref_veh_1",
            "object_id_ref": "objidref_veh_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
            "target_path_template": "/api/v1/vehicles/{vehicleId}",
            "target_method": "GET",
            "path_param_name": "vehicleId",
            "confidence": "medium",
            "created_by": "bola_object_pair_builder",
            "reason_codes": ["path_param_resource_match"],
            "metadata": {"baseline_probability_score": 70.0},
        },
    )
    _store_raw_observation(
        observation_id="obs_bola_post_invalid",
        campaign_id="cmp_plan",
        observation_type=ObservationType.bola_replay_result.value,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_post_high",
            "target_operation_id": "op_GET_/api/v1/posts/{postId}",
            "resource_type": "post",
            "result": "invalid_object_pair",
            "owner_status_code": 400,
            "access_granted": False,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    ready = [c for c in resp.candidates if c.kind.value == "bola_replay_probe" and c.status.value == "ready"]
    assert len(ready) == 1
    assert ready[0].command is not None
    assert ready[0].command.inputs.get("object_pair_id") == "objpair_vehicle_medium"
    assert float(ready[0].summary.get("invalid_pair_penalty") or 0.0) <= 0.0


def test_planner_does_not_select_low_baseline_probability_bola_pair() -> None:
    _reset_store()
    _campaign()
    memory_store.store_runtime_bola_object_pair(
        "objpair_low_sem",
        "cmp_plan",
        {
            "object_pair_id": "objpair_low_sem",
            "campaign_id": "cmp_plan",
            "resource_type": "post",
            "object_ref_id": "objref_1",
            "object_id_ref": "objidref_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/api/posts/{postId}",
            "target_path_template": "/api/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "object_id_field": "authorid",
            "confidence": "medium",
            "created_by": "bola_object_pair_builder",
            "metadata": {
                "semantic_id_kind": "author_id",
                "source_reason_codes": ["creation_non_2xx", "blocked_required_object_ref"],
            },
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "bola_replay_probe"]
    assert rows
    assert all(c.status.value != "ready" for c in rows)
    assert any("semantic_id_mismatch" in (c.missing_inputs or []) or "low_baseline_probability" in (c.missing_inputs or []) for c in rows)
    sample = rows[0].summary or {}
    assert "semantic_id_kind" in sample
    assert "object_id_field" in sample
    assert "baseline_block_reasons" in sample
    assert "source_status_code" in sample


def test_planner_selects_semantic_match_pair_before_weak_pair() -> None:
    _reset_store()
    _campaign()
    memory_store.store_runtime_bola_object_pair(
        "objpair_post_blocked",
        "cmp_plan",
        {
            "object_pair_id": "objpair_post_blocked",
            "campaign_id": "cmp_plan",
            "resource_type": "post",
            "object_ref_id": "objref_weak",
            "object_id_ref": "objidref_weak",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/api/posts/{postId}",
            "target_path_template": "/api/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "object_id_field": "authorid",
            "confidence": "medium",
            "metadata": {
                "semantic_id_kind": "author_id",
                "baseline_block_reasons": ["object_id_field_semantic_mismatch"],
                "source_status_code": 400,
            },
        },
    )
    memory_store.store_runtime_bola_object_pair(
        "objpair_vehicle_ready",
        "cmp_plan",
        {
            "object_pair_id": "objpair_vehicle_ready",
            "campaign_id": "cmp_plan",
            "resource_type": "vehicle",
            "object_ref_id": "objref_ok",
            "object_id_ref": "objidref_ok",
            "owner_auth_profile_id": "authprof_owner_1",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "target_operation_id": "op_GET_/api/vehicles/{vehicleId}",
            "target_path_template": "/api/vehicles/{vehicleId}",
            "target_method": "GET",
            "path_param_name": "vehicleId",
            "object_id_field": "vehicleId",
            "confidence": "high",
            "metadata": {
                "semantic_id_kind": "vehicle_id",
                "baseline_probability_score": 95.0,
                "source_status_code": 200,
                "owner_evidence": True,
            },
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": True}, "max_candidates": 50}),
    )
    ready = [c for c in resp.candidates if c.kind.value == "bola_replay_probe" and c.status.value == "ready"]
    assert ready
    assert ready[0].command is not None
    assert ready[0].command.inputs.get("object_pair_id") == "objpair_vehicle_ready"


def test_planner_resource_instance_inventory_dedups_existing_source_observation() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_rfi_resource_source_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.response_field_inventory.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "field_count": 13,
            "sensitive_field_count": 1,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    _store_raw_observation(
        observation_id="obs_resource_inventory_existing",
        campaign_id="cmp_plan",
        observation_type=ObservationType.resource_instance_inventory.value,
        details={
            "source": "resource_instance_extractor",
            "validation_mode": "resource_instance_extraction",
            "source_observation_id": "obs_rfi_resource_source_existing",
            "source_operation_id": "op_GET_/api/v1/me",
            "source_path": "/api/v1/me",
            "source_auth_profile_id": "authprof_owner_1",
            "resource_instances_count": 1,
            "object_refs": [],
            "reason_codes": ["resource_ids_extracted"],
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_instance_extractor"]
    assert len(rows) == 1
    assert rows[0].status.value == "skipped_existing"


def test_planner_unauthenticated_inventory_does_not_create_resource_instance_candidate() -> None:
    _reset_store()
    _campaign()
    _store_raw_observation(
        observation_id="obs_rfi_resource_unauth",
        campaign_id="cmp_plan",
        observation_type=ObservationType.response_field_inventory.value,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "field_count": 13,
            "auth_mode": "unauthenticated",
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    rows = [c for c in resp.candidates if c.kind.value == "resource_instance_extractor"]
    assert rows == []


def test_planner_latest_successful_materialization_used_for_authenticated_followup() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                path_params=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_raw_observation(
        observation_id="obs_authmat_success_old",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "auth_profiles_created_count": 2,
        },
    )
    _store_raw_observation(
        observation_id="obs_authmat_latest_but_failed",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "failed",
            "auth_profiles_created_count": 0,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and (c.command.inputs.get("auth_mode") if c.command else c.summary.get("auth_mode")) == "authenticated"
    ]
    assert len(auth_rows) == 1
    assert auth_rows[0].status.value == "ready"
    assert auth_rows[0].summary.get("auth_profile_id") == profile.auth_profile_id


def test_planner_authenticated_data_exposure_path_params_blocked_without_seed() -> None:
    _reset_store()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_plan",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/users/{id}",
                method="GET",
                path_template="/api/v1/users/{id}",
                path_params=["id"],
                successful_seed_request_ids=[],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_plan", graph.model_dump(mode="json"))
    profile = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_plan",
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_raw_observation(
        observation_id="obs_authmat_for_path_block",
        campaign_id="cmp_plan",
        observation_type=ObservationType.test_account_materialization_result.value,
        details={
            "source": "test_account_materializer",
            "validation_mode": "test_account_materialization",
            "test_account_materialization_status": "materialized",
            "owner_auth_profile_id": profile.auth_profile_id,
            "auth_profiles_created_count": 2,
        },
    )
    resp = PlannerService().plan(
        "cmp_plan",
        PlannerRequest.model_validate({"zap": {"enabled": False}, "bola": {"enabled": False}, "max_candidates": 40}),
    )
    auth_rows = [
        c for c in resp.candidates
        if c.kind.value == "data_exposure_validator"
        and c.summary.get("auth_mode") == "authenticated"
    ]
    assert len(auth_rows) == 1
    assert auth_rows[0].status.value == "blocked"
    assert "path_params_without_seed" in (auth_rows[0].missing_inputs or [])
    assert auth_rows[0].summary.get("auth_profile_id") == profile.auth_profile_id
