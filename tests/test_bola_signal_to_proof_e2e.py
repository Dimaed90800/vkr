"""Service-level BOLA signal-to-proof E2E.

This test module stitches together the Phase 1-7 services using synthetic
state only. It does not use FastAPI routes, real scanners, Dify, scheduler
logic, or network I/O.
"""
from __future__ import annotations

import json

from backend.models.campaign import CampaignLimits
from backend.models.evidence_pack import EvidencePack
from backend.models.judge import (
    FindingCandidatePayload,
    JudgeApplyRequest,
    JudgeVerdictKind,
    JudgeVerdictPayload,
)
from backend.models.observation import Observation, VerificationPlan
from backend.models.tool_run import ToolResult, ToolResultObservationLite
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.api_graph_service import ApiGraphService
from backend.services.campaign_service import CampaignService
from backend.services.evidence_pack_builder import EvidencePackBuilder
from backend.services.judge_apply_service import JudgeApplyService
from backend.services.observation_normalizer import NormalizeError, ObservationNormalizer
from backend.services.observation_triage import ObservationTriage
from backend.services.request_corpus_service import RequestCorpusService
from backend.services.tool_executor import ToolExecutor
from backend.storage.memory_store import memory_store


VEHICLE_OBJECT_ID = "veh_123"
ATTACKER_OWN_OBJECT_ID = "veh_456"
OWNER_ROLE = "owner"
ATTACKER_ROLE = "attacker"
VEHICLE_PATH = "/api/v1/vehicles/{vehicleId}"
VEHICLE_COLLECTION_PATH = "/api/v1/vehicles"
VEHICLE_OPERATION_ID = f"op_GET_{VEHICLE_PATH}"
VEHICLE_COLLECTION_OPERATION_ID = f"op_GET_{VEHICLE_COLLECTION_PATH}"


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


def create_campaign() -> str:
    campaign = CampaignService().create_campaign(
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        roles_json=[
            {"name": OWNER_ROLE, "kind": "authenticated"},
            {"name": ATTACKER_ROLE, "kind": "authenticated"},
        ],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    return campaign.campaign_id


def build_vehicle_graph(campaign_id: str) -> None:
    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Vehicle API", "version": "1.0.0"},
        "paths": {
            VEHICLE_COLLECTION_PATH: {
                "get": {
                    "summary": "List vehicles",
                    "responses": {
                        "200": {
                            "description": "Vehicle collection",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    },
                }
            },
            VEHICLE_PATH: {
                "get": {
                    "summary": "Get vehicle",
                    "parameters": [
                        {
                            "name": "vehicleId",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                    "responses": {
                        "200": {
                            "description": "Vehicle",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "owner": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
        },
    }
    graph = ApiGraphService().build_from_openapi(campaign_id, json.dumps(spec))
    assert any(op.operation_id == VEHICLE_OPERATION_ID for op in graph.operations)


def add_bola_corpus(campaign_id: str) -> dict[str, object]:
    corpus = RequestCorpusService()
    common_headers = {"Authorization": "Bearer top-secret-token"}

    owner_seed = corpus.add_exchange(
        campaign_id=campaign_id,
        method="GET",
        url=f"http://testapp.local/api/v1/vehicles/{VEHICLE_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        auth_profile=OWNER_ROLE,
        headers=common_headers,
        body={"password": "owner-secret"},
        status_code=200,
        response_body={"id": VEHICLE_OBJECT_ID, "owner": OWNER_ROLE},
        operation_id=VEHICLE_OPERATION_ID,
    )
    attacker_attack = corpus.add_exchange(
        campaign_id=campaign_id,
        method="GET",
        url=f"http://testapp.local/api/v1/vehicles/{VEHICLE_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        auth_profile=ATTACKER_ROLE,
        headers=common_headers,
        body={"access_token": "attacker-secret"},
        status_code=200,
        response_body={"id": VEHICLE_OBJECT_ID, "owner": OWNER_ROLE},
        operation_id=VEHICLE_OPERATION_ID,
    )
    attacker_self = corpus.add_exchange(
        campaign_id=campaign_id,
        method="GET",
        url=f"http://testapp.local/api/v1/vehicles/{ATTACKER_OWN_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        auth_profile=ATTACKER_ROLE,
        headers=common_headers,
        status_code=200,
        response_body={"id": ATTACKER_OWN_OBJECT_ID, "owner": ATTACKER_ROLE},
        operation_id=VEHICLE_OPERATION_ID,
    )
    owner_collection = corpus.add_exchange(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/v1/vehicles",
        path_template=VEHICLE_COLLECTION_PATH,
        auth_profile=OWNER_ROLE,
        headers=common_headers,
        status_code=200,
        response_body={"id": VEHICLE_OBJECT_ID},
        operation_id=VEHICLE_COLLECTION_OPERATION_ID,
    )
    attacker_collection = corpus.add_exchange(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/v1/vehicles",
        path_template=VEHICLE_COLLECTION_PATH,
        auth_profile=ATTACKER_ROLE,
        headers=common_headers,
        status_code=200,
        response_body={"id": ATTACKER_OWN_OBJECT_ID},
        operation_id=VEHICLE_COLLECTION_OPERATION_ID,
    )

    ApiGraphService().ingest_corpus(campaign_id)
    candidates = corpus.find_cross_role_candidates(campaign_id)
    assert any(VEHICLE_OBJECT_ID in c["overlapping_ids"] for c in candidates)

    return {
        "owner_seed": owner_seed,
        "attacker_attack": attacker_attack,
        "attacker_self": attacker_self,
        "owner_collection": owner_collection,
        "attacker_collection": attacker_collection,
    }


def run_tool_and_inject_bola_signal(campaign_id: str, attacker_request_id: str) -> ToolResult:
    command = WorkerCommand(
        campaign_id=campaign_id,
        task_id="task_bola_e2e",
        worker_class="access_control",
        strategy="prove_bola",
        tool_name="custom_request_executor",
        operation_id=VEHICLE_OPERATION_ID,
        seed_request_id=attacker_request_id,
        inputs={
            "url": f"http://testapp.local/api/v1/vehicles/{VEHICLE_OBJECT_ID}",
            "method": "GET",
            "path_template": VEHICLE_PATH,
            "owner_role": OWNER_ROLE,
            "attacker_role": ATTACKER_ROLE,
        },
        budget=CommandBudget(max_requests=5, timeout_sec=60),
        success_criteria=["cross_role_access_signal_recorded"],
    )
    result = ToolExecutor().execute_sync(command)
    assert result.status == "finished"
    assert result.tool_run_id

    stored = memory_store.get_tool_result(result.tool_run_id)
    assert stored is not None
    updated = ToolResult.model_validate(stored)
    updated.observations.append(
        ToolResultObservationLite(
            observation_type="cross_role_access_signal",
            confidence=0.9,
            details={
                "object_id": VEHICLE_OBJECT_ID,
                "owner_role": OWNER_ROLE,
                "attacker_role": ATTACKER_ROLE,
                "operation_id": VEHICLE_OPERATION_ID,
                "request_id": attacker_request_id,
                "auth_profile": ATTACKER_ROLE,
            },
        )
    )
    memory_store.store_tool_result(
        updated.tool_run_id,
        updated.model_dump(mode="json"),
    )
    return updated


def normalize_and_triage(tool_run_id: str) -> tuple[Observation, VerificationPlan]:
    normalized = ObservationNormalizer().normalize(tool_run_id)
    assert not isinstance(normalized, NormalizeError)

    observations = [
        obs for obs in normalized
        if str(obs.type) == "ObservationType.cross_role_access_signal"
        or getattr(obs.type, "value", obs.type) == "cross_role_access_signal"
    ]
    assert len(observations) == 1
    observation = observations[0]

    triaged, plan, error = ObservationTriage().triage(observation.observation_id)
    assert error is None
    assert triaged is not None
    assert plan is not None
    assert plan.goal == "prove_ownership"
    assert plan.strategy == "prove_ownership"
    return triaged, plan


def build_evidence(plan_id: str) -> EvidencePack:
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan(plan_id)
    assert error is None
    assert existing is False
    assert pack is not None
    return pack


def apply_confirmed(campaign_id: str, evidence_id: str):
    request = JudgeApplyRequest(
        campaign_id=campaign_id,
        evidence_id=evidence_id,
        task_id="task_bola_e2e",
        verdict=JudgeVerdictPayload(
            verdict=JudgeVerdictKind.confirmed,
            confidence=0.95,
            severity="",
            reason="Synthetic BOLA proof is complete.",
            finding_candidate=FindingCandidatePayload(
                title="BOLA allows attacker to access another user's vehicle",
                vulnerability_class="cross_role_access_signal",
                summary="Attacker role can read owner vehicle object.",
                extras={"scenario": "service_level_bola_e2e"},
            ),
            judge_source="synthetic",
            judge_model="unit-test",
        ),
    )
    result, error = JudgeApplyService().apply(request)
    assert error is None
    assert result is not None
    return result


def _run_full_bola_e2e() -> dict[str, object]:
    campaign_id = create_campaign()
    build_vehicle_graph(campaign_id)
    corpus = add_bola_corpus(campaign_id)
    attack_request_id = corpus["attacker_attack"].request_id
    tool_result = run_tool_and_inject_bola_signal(campaign_id, attack_request_id)
    observation, plan = normalize_and_triage(tool_result.tool_run_id)
    pack = build_evidence(plan.verification_plan_id)
    result = apply_confirmed(campaign_id, pack.evidence_id)
    return {
        "campaign_id": campaign_id,
        "corpus": corpus,
        "tool_result": tool_result,
        "observation": observation,
        "plan": plan,
        "pack": pack,
        "result": result,
    }


def test_bola_signal_to_proof_e2e_creates_confirmed_finding():
    _reset_store()

    ctx = _run_full_bola_e2e()
    campaign_id = ctx["campaign_id"]
    pack = ctx["pack"]
    result = ctx["result"]

    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.missing_evidence == []
    assert pack.baseline is not None
    assert pack.attack is not None
    assert pack.ownership_proof is not None
    assert pack.controls
    assert pack.diff is not None
    assert pack.replay_steps

    assert result.finding is not None
    assert result.finding.evidence_id == pack.evidence_id
    assert result.finding.campaign_id == campaign_id
    assert result.finding.observation_id == pack.observation_id
    assert len(memory_store.confirmed_findings_by_campaign[campaign_id]) == 1


def test_bola_e2e_repeated_judge_apply_does_not_duplicate_finding():
    _reset_store()

    ctx = _run_full_bola_e2e()
    campaign_id = ctx["campaign_id"]
    first = ctx["result"]
    second = apply_confirmed(campaign_id, ctx["pack"].evidence_id)

    assert len(memory_store.list_confirmed_findings_by_campaign(campaign_id)) == 1
    assert second.finding_id == first.finding_id
    assert second.duplicate_of_finding_id == first.finding_id


def test_bola_e2e_does_not_inline_raw_bodies_or_headers():
    _reset_store()

    ctx = _run_full_bola_e2e()
    pack_json = json.dumps(ctx["pack"].model_dump(mode="json"))
    finding_json = json.dumps(ctx["result"].finding.model_dump(mode="json"))
    combined = f"{pack_json}\n{finding_json}"

    for forbidden in ["Authorization", "Bearer", "secret", "access_token", "password"]:
        assert forbidden not in combined
    assert "request_id" in pack_json
    assert "body_redacted" not in pack_json
    assert "headers_redacted" not in pack_json


def test_bola_e2e_campaign_isolation():
    _reset_store()

    first = _run_full_bola_e2e()
    second = _run_full_bola_e2e()

    first_campaign = first["campaign_id"]
    second_campaign = second["campaign_id"]
    first_finding = first["result"].finding
    second_finding = second["result"].finding

    assert first_campaign != second_campaign
    assert first_finding.finding_id != second_finding.finding_id
    assert first_finding.fingerprint != second_finding.fingerprint
    assert len(memory_store.list_confirmed_findings_by_campaign(first_campaign)) == 1
    assert len(memory_store.list_confirmed_findings_by_campaign(second_campaign)) == 1


def test_bola_e2e_does_not_write_legacy_findings_or_evidence_records():
    _reset_store()

    _run_full_bola_e2e()

    assert memory_store.findings == []
    assert memory_store.evidence_records == []
    assert dict(memory_store.findings_by_session) == {}
    assert dict(memory_store.evidence_by_session) == {}
