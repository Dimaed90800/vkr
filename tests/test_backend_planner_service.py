"""Phase 12A — backend WorkerCommand planner tests."""
from __future__ import annotations

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
from backend.services.injection_scenario_parameter_candidates import INJECTION_COMPILER_PAYLOAD_FAMILIES
from backend.services.planner_service import PlannerService
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
        "observation_apply_meta",
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

    response = PlannerService().plan("cmp_plan", _request_with_bola())

    assert response.ready_count == 1
    candidate = response.candidates[0]
    assert candidate.kind == "bola_replay_probe"
    assert candidate.status == "ready"
    assert candidate.command is not None
    assert candidate.command.worker_class == "access_control"
    assert candidate.command.strategy == "prove_bola"
    assert candidate.command.inputs["object_id"] == "veh_123"


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

    response = PlannerService().plan("cmp_plan", _request_with_bola())
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
    request = PlannerRequest.model_validate({
        "zap": {"enabled": True},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
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
    client = TestClient(app)

    response = client.post(
        "/v1/planner/cmp_plan/candidates",
        json={
            "zap": {"enabled": False},
            "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["campaign_id"] == "cmp_plan"
    assert payload["ready_count"] == 1
    assert payload["candidates"][0]["command"]["tool_name"] == "bola_replay_probe"


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
    assert response.candidates[0].status == "ready"
    assert response.candidates[1].status == "skipped_existing"


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

    response = PlannerService().plan("cmp_plan", _request_with_bola())

    assert response.candidates[0].status == "ready"
    assert response.candidates[0].command is not None


def test_planner_cross_campaign_existing_signal_does_not_suppress_candidate():
    _reset_store()
    _campaign(campaign_id="cmp_plan")
    _campaign(campaign_id="cmp_other")
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

    response = PlannerService().plan("cmp_plan", _request_with_bola())

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
    _store_zap_alert_observation()
    request = PlannerRequest.model_validate({
        "zap": {"enabled": False},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
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
    _store_graph_vehicle_op()
    _store_zap_alert_observation()
    body = {
        "zap": {"enabled": True},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
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
    assert cmd.inputs.get("mutation_policy") == "diagnostic_only"
    assert cmd.inputs.get("diagnostic_only") is True
    assert cmd.inputs.get("max_mutations") == 1
    assert cmd.inputs.get("target_url") == "http://target.local"
    assert cmd.inputs.get("operation_id") == "op_PATCH_/api/v1/users/{userId}"
    assert "isAdmin" in (cmd.inputs.get("sensitive_fields") or [])
    assert "owner_id" in (cmd.inputs.get("sensitive_fields") or [])
    assert cmd.budget.max_requests == 0
    assert cmd.budget.timeout_sec == 30
    assert cmd.success_criteria == ["property_mutation_probe_completed"]
    assert CommandValidator().validate(cmd).valid


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
