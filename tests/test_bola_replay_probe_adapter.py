"""Phase 9A — strict BOLA replay probe adapter tests."""
from __future__ import annotations

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.evidence_pack_builder import EvidencePackBuilder
from backend.services.http.safe_http_client import SafeHttpClient
from backend.services.observation_normalizer import NormalizeError, ObservationNormalizer
from backend.services.observation_triage import ObservationTriage
from backend.services.tool_executor import ToolExecutor
from backend.storage.memory_store import memory_store


VEHICLE_PATH = "/api/v1/vehicles/{vehicleId}"
VEHICLE_COLLECTION_PATH = "/api/v1/vehicles"
OPERATION_ID = f"op_GET_{VEHICLE_PATH}"


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
        "evidence_packs_by_verification_plan",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()


def _campaign(campaign_id: str = "cmp_bola_replay") -> Campaign:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://crapi.local",
        allowed_hosts=["crapi.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
        roles_json=[
            {"name": "owner", "bearer_token": "owner-token"},
            {"name": "attacker", "bearer_token": "attacker-token"},
        ],
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _command(**input_overrides) -> WorkerCommand:
    inputs = {
        "operation_id": OPERATION_ID,
        "method": "GET",
        "object_url": "http://crapi.local/api/v1/vehicles/veh_123",
        "attacker_own_object_url": "http://crapi.local/api/v1/vehicles/veh_456",
        "collection_url": "http://crapi.local/api/v1/vehicles",
        "path_template": VEHICLE_PATH,
        "collection_path_template": VEHICLE_COLLECTION_PATH,
        "object_id": "veh_123",
        "attacker_own_object_id": "veh_456",
        "owner_role": "owner",
        "attacker_role": "attacker",
    }
    inputs.update(input_overrides)
    return WorkerCommand(
        campaign_id="cmp_bola_replay",
        worker_class="access_control",
        strategy="prove_bola",
        tool_name="bola_replay_probe",
        operation_id=OPERATION_ID,
        inputs=inputs,
        budget=CommandBudget(max_requests=5, timeout_sec=30),
    )


def _transport(
    *,
    attacker_blocked: bool = False,
    negative_control_missing: bool = False,
    owner_collection_missing: bool = False,
    attacker_collection_contains_owner: bool = False,
) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        auth = request.headers.get("authorization", "")
        path = request.url.path
        if path.endswith("/veh_123") and auth == "Bearer owner-token":
            return httpx.Response(200, json={"id": "veh_123", "owner": "owner", "secret": "hidden"})
        if path.endswith("/veh_123") and auth == "Bearer attacker-token":
            if attacker_blocked:
                return httpx.Response(403, json={"error": "forbidden"})
            return httpx.Response(200, json={"id": "veh_123", "owner": "owner"})
        if path.endswith("/veh_456") and auth == "Bearer attacker-token":
            if negative_control_missing:
                return httpx.Response(404, json={"error": "missing"})
            return httpx.Response(200, json={"id": "veh_456", "owner": "attacker"})
        if path == "/api/v1/vehicles" and auth == "Bearer owner-token":
            if owner_collection_missing:
                return httpx.Response(200, json={"id": "veh_456"})
            return httpx.Response(200, json={"id": "veh_123"})
        if path == "/api/v1/vehicles" and auth == "Bearer attacker-token":
            if attacker_collection_contains_owner:
                return httpx.Response(200, json={"id": "veh_123"})
            return httpx.Response(200, json={"id": "veh_456"})
        return httpx.Response(404, json={"error": "not found"})

    return httpx.MockTransport(handler)


def _execute_with_transport(transport: httpx.MockTransport):
    return ToolExecutor(
        http_client=SafeHttpClient(transport=transport)
    ).execute_sync(_command())


def test_bola_replay_probe_valid_proof_creates_cross_role_access_signal():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport())

    assert result.status == "finished"
    assert len(result.requests) == 5
    assert len(memory_store.list_corpus_by_campaign("cmp_bola_replay")) == 5
    signals = [o for o in result.observations if o.observation_type == "cross_role_access_signal"]
    assert len(signals) == 1
    details = signals[0].details
    assert details["object_id"] == "veh_123"
    assert details["owner_role"] == "owner"
    assert details["attacker_role"] == "attacker"
    assert details["owner_request_id"]
    assert details["attack_request_id"]
    assert details["attacker_own_request_id"]
    assert details["owner_collection_request_id"]
    assert details["attacker_collection_request_id"]


def test_bola_replay_probe_no_signal_when_attacker_blocked():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport(attacker_blocked=True))

    assert result.observations == []
    assert any(e.error_type == "bola_proof_incomplete" for e in result.errors)


def test_bola_replay_probe_requires_negative_control():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport(negative_control_missing=True))

    assert result.observations == []
    assert any(e.error_type == "bola_proof_incomplete" for e in result.errors)


def test_bola_replay_probe_requires_owner_collection_contains_object():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport(owner_collection_missing=True))

    assert result.observations == []
    assert any(e.error_type == "bola_proof_incomplete" for e in result.errors)


def test_bola_replay_probe_requires_attacker_collection_excludes_object():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport(attacker_collection_contains_owner=True))

    assert result.observations == []
    assert any(e.error_type == "bola_proof_incomplete" for e in result.errors)


def test_bola_replay_probe_stores_corpus_redacted():
    _reset_store()
    _campaign()

    result = _execute_with_transport(_transport())
    items = memory_store.list_corpus_by_campaign("cmp_bola_replay")

    assert len(items) == 5
    assert all(i["source"] == "tool:bola_replay_probe" for i in items)
    assert all(i["source_tool_run_id"] == result.tool_run_id for i in items)
    assert all(i["headers_redacted"].get("Authorization") == "<redacted>" for i in items)
    assert items[0]["response_body_redacted"]["secret"] == "<redacted>"


def test_bola_replay_probe_observation_normalizes_and_builds_ready_evidence():
    _reset_store()
    _campaign()
    result = _execute_with_transport(_transport())

    normalized = ObservationNormalizer().normalize(result.tool_run_id)
    assert not isinstance(normalized, NormalizeError)
    observations = [
        obs for obs in normalized
        if getattr(obs.type, "value", obs.type) == "cross_role_access_signal"
    ]
    assert len(observations) == 1
    observation: Observation = observations[0]

    _, plan, error = ObservationTriage().triage(observation.observation_id)
    assert error is None
    assert plan is not None

    pack, build_error, _ = EvidencePackBuilder().build_from_verification_plan(
        plan.verification_plan_id
    )
    assert build_error is None
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.missing_evidence == []


def test_bola_probe_id_matching_not_substring():
    _reset_store()
    _campaign()
    cmd = _command(object_id="veh_12")

    result = ToolExecutor(
        http_client=SafeHttpClient(transport=_transport())
    ).execute_sync(cmd)

    assert result.status == "finished"
    assert result.observations == []
    assert any(e.error_type == "bola_proof_incomplete" for e in result.errors)
