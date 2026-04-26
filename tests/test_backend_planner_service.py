"""Phase 12A — backend WorkerCommand planner tests."""
from __future__ import annotations

from fastapi.testclient import TestClient

from backend.main import app
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation, ObservationType, SecurityRelevance
from backend.models.planner import PlannerRequest
from backend.models.tool_run import (
    ToolExecutionMode,
    ToolResult,
    ToolResultObservationLite,
    ToolRun,
    ToolRunStatus,
)
from backend.services.command_validator import CommandValidator
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
) -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://target.local",
        allowed_hosts=["target.local"] if allowed_hosts is None else allowed_hosts,
        roles_json=[
            {"name": "owner", "headers": {"X-Role": "owner"}},
            {"name": "attacker", "headers": {"X-Role": "attacker"}},
        ],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=max_duration_sec),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))
    return campaign


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
) -> None:
    memory_store.store_command(
        command_id,
        campaign_id,
        {
            "command_id": command_id,
            "campaign_id": campaign_id,
            "worker_class": "discovery_inventory",
            "strategy": "zap_discovery_passive",
            "tool_name": tool_name,
            "inputs": inputs,
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


def test_planner_orders_zap_before_bola():
    _reset_store()
    _campaign()
    request = PlannerRequest.model_validate({
        "zap": {"enabled": True},
        "bola": {"enabled": True, "object_pairs": [_bola_pair()]},
    })

    response = PlannerService().plan("cmp_plan", request)

    assert [candidate.kind.value for candidate in response.candidates[:2]] == [
        "zap_discovery_passive",
        "bola_replay_probe",
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
