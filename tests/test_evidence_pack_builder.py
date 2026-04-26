"""Phase 6 — EvidencePackBuilder tests.

Covers builder behavior per observation type, idempotency, route surface,
isolation guarantees, and a regression guard for the legacy
``EvidenceBuilderService.from_wrapper_result`` (JudgeReadyEvidence) path.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import (
    Observation,
    ObservationType,
    VerificationPlan,
    VerificationPlanStatus,
)
from backend.models.tool_run import ToolArtifactRef, ToolRun, ToolRunStatus
from backend.services.evidence_pack_builder import (
    EvidencePackBuildError,
    EvidencePackBuilder,
)
from backend.services.request_corpus_service import RequestCorpusService
from backend.storage.memory_store import memory_store


# ─── Test helpers ─────────────────────────────────────────────────


def _reset_store() -> None:
    memory_store.campaigns.clear()
    memory_store.campaign_by_run_id.clear()
    memory_store.campaign_by_session_id.clear()
    memory_store.corpus_items.clear()
    memory_store.corpus_by_campaign.clear()
    memory_store.resource_instances.clear()
    memory_store.resources_by_campaign.clear()
    memory_store.graphs_by_campaign.clear()
    memory_store.commands.clear()
    memory_store.commands_by_campaign.clear()
    memory_store.command_fingerprints.clear()
    memory_store.tool_runs.clear()
    memory_store.tool_runs_by_campaign.clear()
    memory_store.tool_results.clear()
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()
    memory_store.observations.clear()
    memory_store.observations_by_campaign.clear()
    memory_store.observations_by_tool_run.clear()
    memory_store.verification_plans.clear()
    memory_store.verification_plans_by_campaign.clear()
    memory_store.evidence_packs.clear()
    memory_store.evidence_packs_by_campaign.clear()
    memory_store.evidence_packs_by_observation.clear()
    memory_store.evidence_packs_by_verification_plan.clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _create_campaign(campaign_id: str = "cmp_evp1") -> None:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))


def _store_observation(obs: Observation) -> None:
    memory_store.store_observation(
        obs.observation_id, obs.campaign_id, obs.tool_run_id,
        obs.model_dump(mode="json"),
    )


def _store_plan(plan: VerificationPlan) -> None:
    memory_store.store_verification_plan(
        plan.verification_plan_id, plan.campaign_id,
        plan.model_dump(mode="json"),
    )


def _store_finished_run(
    tool_run_id: str = "toolrun_evp",
    campaign_id: str = "cmp_evp1",
    tool_name: str = "custom_request_executor",
) -> None:
    run = ToolRun(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name=tool_name,
        status=ToolRunStatus.finished,
        result_ready=True,
    )
    memory_store.store_tool_run(tool_run_id, campaign_id, run.model_dump(mode="json"))


def _add_corpus(
    *,
    campaign_id: str = "cmp_evp1",
    method: str = "GET",
    url: str,
    path_template: str = "",
    role: str = "",
    status_code: int = 200,
    operation_id: str = "",
    response_body=None,
    headers=None,
):
    return RequestCorpusService().add_exchange(
        campaign_id=campaign_id,
        method=method,
        url=url,
        path_template=path_template,
        auth_profile=role,
        status_code=status_code,
        operation_id=operation_id,
        response_body=response_body,
        headers=headers,
    )


def _make_obs(
    obs_type: str,
    *,
    observation_id: str = "obs_evp_test",
    campaign_id: str = "cmp_evp1",
    tool_run_id: str = "toolrun_evp",
    operation_id: str = "",
    request_id: str = "",
    auth_profile: str = "",
    status_code: int = 0,
    confidence: float = 0.0,
    details: dict | None = None,
    artifact_refs: list[str] | None = None,
) -> Observation:
    obs = Observation(
        observation_id=observation_id,
        campaign_id=campaign_id,
        tool_run_id=tool_run_id,
        type=obs_type,
        operation_id=operation_id,
        request_id=request_id,
        auth_profile=auth_profile,
        status_code=status_code,
        confidence=confidence,
        details=details or {},
        artifact_refs=artifact_refs or [],
    )
    _store_observation(obs)
    return obs


def _make_plan(
    obs: Observation,
    goal: str,
    required_evidence: list[str],
    plan_id: str = "vplan_evp",
) -> VerificationPlan:
    plan = VerificationPlan(
        verification_plan_id=plan_id,
        campaign_id=obs.campaign_id,
        parent_observation_id=obs.observation_id,
        parent_task_id=obs.task_id,
        goal=goal,
        worker_class="",
        strategy=goal,
        required_evidence=required_evidence,
        status=VerificationPlanStatus.pending,
    )
    _store_plan(plan)
    return plan


def _store_api_graph_with_op(
    *,
    campaign_id: str = "cmp_evp1",
    operation_id: str,
    method: str,
    path_template: str,
    owasp_candidates: list[str] | None = None,
) -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id=operation_id,
                method=method,
                path_template=path_template,
                owasp_candidates=owasp_candidates or [],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


def _setup_complete_bola_corpus(campaign_id: str = "cmp_evp1") -> dict:
    """Returns a dict with object_id, owner_role, attacker_role, op_id and corpus refs."""
    op_id = "op_GET_/api/users/{userId}"
    coll_op_id = "op_GET_/api/users/me/posts"

    owner_seed = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/users/123",
        path_template="/api/users/{userId}",
        role="user_a",
        status_code=200,
        operation_id=op_id,
    )
    attacker_attack = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/users/123",
        path_template="/api/users/{userId}",
        role="user_b",
        status_code=200,
        operation_id=op_id,
    )
    attacker_self = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/users/456",
        path_template="/api/users/{userId}",
        role="user_b",
        status_code=200,
        operation_id=op_id,
    )
    owner_collection = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/users/me/posts",
        path_template="/api/users/me/posts",
        role="user_a",
        status_code=200,
        operation_id=coll_op_id,
        response_body={"id": "123"},
    )
    attacker_collection = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/users/me/posts",
        path_template="/api/users/me/posts",
        role="user_b",
        status_code=200,
        operation_id=coll_op_id,
        response_body={"id": "456"},
    )
    return {
        "object_id": "123",
        "owner_role": "user_a",
        "attacker_role": "user_b",
        "op_id": op_id,
        "owner_seed": owner_seed,
        "attacker_attack": attacker_attack,
        "attacker_self": attacker_self,
        "owner_collection": owner_collection,
        "attacker_collection": attacker_collection,
    }


def _setup_complete_bola_uuid_corpus(campaign_id: str = "cmp_evp1") -> dict:
    op_id = "op_GET_/api/vehicles/{vehicleId}"
    coll_op_id = "op_GET_/api/vehicles"
    uuid_val = "8e00713c-fe1b-457c-9f73-6be4099f6e8c"

    owner_seed = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url=f"http://testapp.local/api/vehicles/{uuid_val}",
        path_template="/api/vehicles/{vehicleId}",
        role="owner",
        status_code=200,
        operation_id=op_id,
        response_body={"carId": uuid_val, "owner": "owner"},
    )
    attacker_attack = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url=f"http://testapp.local/api/vehicles/{uuid_val}",
        path_template="/api/vehicles/{vehicleId}",
        role="attacker",
        status_code=200,
        operation_id=op_id,
        response_body={"carId": uuid_val, "owner": "owner"},
    )
    attacker_self = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/vehicles/attacker-own",
        path_template="/api/vehicles/{vehicleId}",
        role="attacker",
        status_code=200,
        operation_id=op_id,
        response_body={"carId": "attacker-own"},
    )
    owner_collection = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/vehicles",
        path_template="/api/vehicles",
        role="owner",
        status_code=200,
        operation_id=coll_op_id,
        response_body={"items": [{"id": 168, "uuid": uuid_val}]},
    )
    attacker_collection = _add_corpus(
        campaign_id=campaign_id,
        method="GET",
        url="http://testapp.local/api/vehicles",
        path_template="/api/vehicles",
        role="attacker",
        status_code=200,
        operation_id=coll_op_id,
        response_body={"items": [{"id": 169, "uuid": "other-uuid"}]},
    )
    return {
        "object_id": uuid_val,
        "owner_role": "owner",
        "attacker_role": "attacker",
        "op_id": op_id,
        "owner_seed": owner_seed,
        "attacker_attack": attacker_attack,
        "attacker_self": attacker_self,
        "owner_collection": owner_collection,
        "attacker_collection": attacker_collection,
    }


# ─── BOLA / cross_role_access_signal tests ────────────────────────


def test_build_bola_evidence_missing_ownership_proof():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/users/{userId}"
    _add_corpus(
        url="http://testapp.local/api/users/123",
        path_template="/api/users/{userId}",
        role="user_a", status_code=200, operation_id=op_id,
    )
    _add_corpus(
        url="http://testapp.local/api/users/123",
        path_template="/api/users/{userId}",
        role="user_b", status_code=200, operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=op_id,
        confidence=0.9,
        details={"object_id": "123", "owner_role": "user_a", "attacker_role": "user_b"},
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False

    missing_codes = {item.code for item in pack.missing_evidence}
    assert "ownership_proof_missing" in missing_codes


def test_build_bola_evidence_complete_with_ownership_proof():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()

    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        confidence=0.9,
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.baseline is not None and pack.baseline.request_ref is not None
    assert pack.attack is not None and pack.attack.request_ref is not None
    assert pack.ownership_proof is not None
    assert pack.ownership_proof.owner_collection_request_ref is not None
    assert pack.ownership_proof.attacker_collection_request_ref is not None
    assert pack.controls
    assert pack.diff is not None
    assert pack.replay_steps
    assert pack.missing_evidence == []
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True


def test_build_bola_evidence_complete_with_uuid_ownership_proof():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_uuid_corpus()

    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        confidence=0.9,
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.ownership_proof is not None
    assert pack.ownership_proof.owner_collection_request_ref is not None
    assert pack.ownership_proof.attacker_collection_request_ref is not None
    assert pack.missing_evidence == []


def test_build_bola_evidence_uses_observation_collection_request_ids_for_ownership_proof():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_uuid_corpus()

    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        confidence=0.9,
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
            "owner_collection_request_id": ctx["owner_collection"].request_id,
            "attacker_collection_request_id": ctx["attacker_collection"].request_id,
        },
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.ownership_proof is not None
    assert pack.ownership_proof.owner_collection_request_ref is not None
    assert pack.ownership_proof.attacker_collection_request_ref is not None
    assert (
        pack.ownership_proof.owner_collection_request_ref.request_id
        == ctx["owner_collection"].request_id
    )
    assert (
        pack.ownership_proof.attacker_collection_request_ref.request_id
        == ctx["attacker_collection"].request_id
    )
    assert pack.status == "ready_for_judge"
    assert pack.missing_evidence == []


def test_build_bola_evidence_uses_request_ids_not_raw_bodies():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()

    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None

    raw = pack.model_dump(mode="json")

    assert pack.baseline.request_ref.request_id == ctx["owner_seed"].request_id
    assert pack.attack.request_ref.request_id == ctx["attacker_attack"].request_id
    assert pack.ownership_proof.owner_collection_request_ref.request_id == ctx["owner_collection"].request_id
    assert pack.ownership_proof.attacker_collection_request_ref.request_id == ctx["attacker_collection"].request_id

    serialized_blob = str(raw)
    assert "response_body" not in serialized_blob
    assert "headers_redacted" not in serialized_blob


# ─── unexpected_500 tests ─────────────────────────────────────────


def test_build_unexpected_500_evidence_missing_reproduction():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_POST_/api/orders"
    item = _add_corpus(
        method="POST",
        url="http://testapp.local/api/orders",
        path_template="/api/orders",
        role="user_a",
        status_code=500,
        operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.unexpected_500.value,
        operation_id=op_id,
        request_id=item.request_id,
        status_code=500,
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.judge_ready is False
    assert pack.status == "incomplete"

    missing_codes = {m.code for m in pack.missing_evidence}
    assert "reproduced_500" in missing_codes
    assert "minimized_request" in missing_codes


def test_build_unexpected_500_evidence_with_minimized_replay():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_POST_/api/orders"

    original = _add_corpus(
        method="POST",
        url="http://testapp.local/api/orders",
        path_template="/api/orders",
        role="user_a",
        status_code=500,
        operation_id=op_id,
    )
    repeated = _add_corpus(
        method="POST",
        url="http://testapp.local/api/orders",
        path_template="/api/orders",
        role="user_a",
        status_code=500,
        operation_id=op_id,
    )
    minimized = _add_corpus(
        method="POST",
        url="http://testapp.local/api/orders",
        path_template="/api/orders",
        role="user_a",
        status_code=500,
        operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.unexpected_500.value,
        operation_id=op_id,
        request_id=original.request_id,
        status_code=500,
        details={"minimized_request_id": minimized.request_id},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.attack is not None
    assert pack.attack.request_ref.request_id == original.request_id

    minimized_steps = [
        s for s in pack.replay_steps
        if s.request_ref and s.request_ref.request_id == minimized.request_id
    ]
    assert len(minimized_steps) == 1
    assert any(c.name == "minimized_request" for c in pack.controls)

    repeated_refs = [
        s.request_ref for s in pack.replay_steps
        if s.request_ref and s.request_ref.request_id == repeated.request_id
    ]
    assert repeated_refs

    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True


# ─── store-only / not_judge_ready types ───────────────────────────


def test_build_unsupported_tool_signal_returns_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.unsupported_tool_signal.value)

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False
    assert pack.missing_evidence


def test_build_timeout_signal_returns_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False


# ─── ZAP / nuclei / discovered_endpoint ──────────────────────────


def test_build_zap_alert_missing_replay_validation():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/anything"
    item = _add_corpus(
        url="http://testapp.local/api/anything",
        path_template="/api/anything",
        role="user_a", status_code=200, operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.zap_alert.value,
        operation_id=op_id,
        request_id=item.request_id,
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "replay_validation_missing" in missing_codes
    assert pack.status == "incomplete"
    assert pack.judge_ready is False


def test_build_nuclei_match_missing_reproduction():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/anything"
    item = _add_corpus(
        url="http://testapp.local/api/anything",
        path_template="/api/anything",
        role="user_a", status_code=200, operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.nuclei_match.value,
        operation_id=op_id,
        request_id=item.request_id,
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "reproduction_missing" in missing_codes
    assert pack.status == "incomplete"
    assert pack.judge_ready is False


def test_build_discovered_endpoint_missing_auth_check():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/secret"
    item = _add_corpus(
        url="http://testapp.local/api/secret",
        path_template="/api/secret",
        role="user_a", status_code=200, operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.discovered_endpoint.value,
        operation_id=op_id,
        request_id=item.request_id,
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.owasp_category == "API9_IMPROPER_INVENTORY_MANAGEMENT"
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "auth_required_confirmed" in missing_codes
    assert "no_auth_access_result" in missing_codes
    assert pack.status == "incomplete"


# ─── auth_anomaly ────────────────────────────────────────────────


def test_build_auth_anomaly_pack_uses_baseline_and_attack_request_ids():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/me"
    baseline = _add_corpus(
        url="http://testapp.local/api/me",
        path_template="/api/me",
        role="user_a", status_code=200, operation_id=op_id,
    )
    attack = _add_corpus(
        url="http://testapp.local/api/me",
        path_template="/api/me",
        role="anonymous", status_code=200, operation_id=op_id,
    )

    obs = _make_obs(
        ObservationType.auth_anomaly.value,
        operation_id=op_id,
        request_id=attack.request_id,
        auth_profile="anonymous",
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.owasp_category == "API2_AUTH"
    assert pack.baseline is not None
    assert pack.baseline.request_ref is not None
    assert pack.baseline.request_ref.request_id == baseline.request_id
    assert pack.attack is not None
    assert pack.attack.request_ref.request_id == attack.request_id


# ─── Cross-cutting structural assertions ─────────────────────────


def test_evidence_pack_has_artifact_refs_not_raw_output():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    memory_store.store_artifact(
        "art_1", "toolrun_evp",
        {
            "artifact_id": "art_1",
            "artifact_type": "stdout",
            "path": "/tmp/run/toolrun_evp/stdout.log",
            "size_bytes": 1234,
        },
    )
    ctx = _setup_complete_bola_corpus()
    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.artifact_refs
    art = pack.artifact_refs[0]
    assert art.artifact_id == "art_1"
    assert art.path == "/tmp/run/toolrun_evp/stdout.log"
    assert art.size_bytes == 1234

    serialized = str(pack.model_dump(mode="json"))
    assert "stdout_payload" not in serialized
    assert "raw_output" not in serialized


def test_evidence_pack_preserves_redaction():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/me"
    _add_corpus(
        url="http://testapp.local/api/me",
        path_template="/api/me",
        role="user_a", status_code=200, operation_id=op_id,
        headers={"Authorization": "Bearer SECRET-TOKEN"},
        response_body={"password": "topsecret", "id": "u1"},
    )
    item_a = list(memory_store.list_corpus_by_campaign("cmp_evp1"))[0]
    assert item_a["headers_redacted"]["Authorization"] == "<redacted>"
    assert item_a["response_body_redacted"]["password"] == "<redacted>"

    obs = _make_obs(
        ObservationType.auth_anomaly.value,
        operation_id=op_id,
        request_id=item_a["request_id"],
        auth_profile="user_a",
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    blob = str(pack.model_dump(mode="json"))
    assert "SECRET-TOKEN" not in blob
    assert "topsecret" not in blob


def test_evidence_pack_contains_replay_steps():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()
    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert len(pack.replay_steps) >= 2
    orders = [s.order for s in pack.replay_steps]
    assert orders == sorted(orders)


def test_evidence_pack_uses_apigraph_metadata():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    op_id = "op_GET_/api/users/{userId}"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/users/{userId}",
        owasp_candidates=["API1_BOLA"],
    )
    ctx = _setup_complete_bola_corpus()
    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.endpoint == "/api/users/{userId}"
    assert pack.method == "GET"
    assert pack.operation_id == op_id


def test_evidence_pack_owasp_category_set_for_bola_observation():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id="op_GET_/api/orders/{orderId}",
        details={"object_id": "1", "owner_role": "a", "attacker_role": "b"},
    )
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.owasp_category == "API1_BOLA"


# ─── Regression guards: no Judge / no Finding ────────────────────


def test_no_finding_is_created():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()
    obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=ctx["op_id"],
        details={
            "object_id": ctx["object_id"],
            "owner_role": ctx["owner_role"],
            "attacker_role": ctx["attacker_role"],
        },
    )
    EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert memory_store.findings == []
    assert dict(memory_store.findings_by_session) == {}


def test_no_judge_is_called():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(
        ObservationType.unexpected_500.value,
        operation_id="op_POST_/api/orders",
        request_id="",
        status_code=500,
    )
    EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert memory_store.evidence_records == []
    assert dict(memory_store.evidence_by_session) == {}


# ─── Storage / isolation ─────────────────────────────────────────


def test_evidence_pack_isolation_per_campaign():
    _reset_store()
    _create_campaign("cmp_a")
    _create_campaign("cmp_b")
    _store_finished_run("toolrun_a", "cmp_a")
    _store_finished_run("toolrun_b", "cmp_b")

    obs_a = _make_obs(
        ObservationType.timeout_signal.value,
        observation_id="obs_a", campaign_id="cmp_a", tool_run_id="toolrun_a",
    )
    obs_b = _make_obs(
        ObservationType.timeout_signal.value,
        observation_id="obs_b", campaign_id="cmp_b", tool_run_id="toolrun_b",
    )

    EvidencePackBuilder().build_from_observation(obs_a.observation_id)
    EvidencePackBuilder().build_from_observation(obs_b.observation_id)

    assert len(memory_store.list_evidence_packs_by_campaign("cmp_a")) == 1
    assert len(memory_store.list_evidence_packs_by_campaign("cmp_b")) == 1
    a_pack = memory_store.list_evidence_packs_by_campaign("cmp_a")[0]
    b_pack = memory_store.list_evidence_packs_by_campaign("cmp_b")[0]
    assert a_pack["campaign_id"] == "cmp_a"
    assert b_pack["campaign_id"] == "cmp_b"
    assert a_pack["evidence_id"] != b_pack["evidence_id"]


def test_evidence_pack_indexed_by_observation_id():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None

    listed = memory_store.list_evidence_packs_by_observation(obs.observation_id)
    assert len(listed) == 1
    assert listed[0]["evidence_id"] == pack.evidence_id


def test_evidence_pack_indexed_by_verification_plan_id():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.unexpected_500.value, status_code=500)
    plan = _make_plan(obs, goal="replay_minimized_payload",
                       required_evidence=["minimized_request", "reproduced_500"])

    pack, _, _ = EvidencePackBuilder().build_from_verification_plan(plan.verification_plan_id)
    assert pack is not None

    listed = memory_store.list_evidence_packs_by_verification_plan(plan.verification_plan_id)
    assert len(listed) == 1
    assert listed[0]["evidence_id"] == pack.evidence_id


def test_evidence_build_is_idempotent_for_same_observation_and_plan():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)

    pack1, _, existing1 = EvidencePackBuilder().build_from_observation(obs.observation_id)
    pack2, _, existing2 = EvidencePackBuilder().build_from_observation(obs.observation_id)

    assert pack1 is not None
    assert pack2 is not None
    assert existing1 is False
    assert existing2 is True
    assert pack1.evidence_id == pack2.evidence_id

    listed = memory_store.list_evidence_packs_by_observation(obs.observation_id)
    assert len(listed) == 1


def test_find_active_plan_ignores_completed_cancelled():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.unexpected_500.value, status_code=500)

    _store_plan(
        VerificationPlan(
            verification_plan_id="vplan_completed",
            campaign_id=obs.campaign_id,
            parent_observation_id=obs.observation_id,
            goal="old_completed",
            strategy="old_completed",
            required_evidence=[],
            status=VerificationPlanStatus.completed,
        )
    )
    _store_plan(
        VerificationPlan(
            verification_plan_id="vplan_cancelled",
            campaign_id=obs.campaign_id,
            parent_observation_id=obs.observation_id,
            goal="old_cancelled",
            strategy="old_cancelled",
            required_evidence=[],
            status=VerificationPlanStatus.cancelled,
        )
    )
    pending = VerificationPlan(
        verification_plan_id="vplan_pending",
        campaign_id=obs.campaign_id,
        parent_observation_id=obs.observation_id,
        goal="active_pending",
        strategy="active_pending",
        required_evidence=[],
        status=VerificationPlanStatus.pending,
    )
    _store_plan(pending)

    pack, error, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert pack is not None
    assert pack.verification_plan_id == pending.verification_plan_id

    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs2 = _make_obs(
        ObservationType.unexpected_500.value,
        observation_id="obs_only_done",
        status_code=500,
    )
    _store_plan(
        VerificationPlan(
            verification_plan_id="vplan_only_completed",
            campaign_id=obs2.campaign_id,
            parent_observation_id=obs2.observation_id,
            goal="only_completed",
            strategy="only_completed",
            required_evidence=[],
            status=VerificationPlanStatus.completed,
        )
    )
    pack2, error2, _ = EvidencePackBuilder().build_from_observation(obs2.observation_id)
    assert error2 is None
    assert pack2 is not None
    assert pack2.verification_plan_id == ""


# ─── Route-level tests ────────────────────────────────────────────


def _get_test_client():
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


def test_build_from_observation_route_returns_200():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)

    client = _get_test_client()
    resp = client.post(f"/v1/evidence/build/{obs.observation_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert "evidence_pack" in body
    assert body["existing"] is False
    assert body["evidence_pack"]["observation_id"] == obs.observation_id


def test_build_from_observation_route_404_for_missing_observation():
    _reset_store()
    client = _get_test_client()
    resp = client.post("/v1/evidence/build/obs_missing_xyz")
    assert resp.status_code == 404
    assert resp.json()["error"] == "observation_not_found"


def test_build_from_observation_rejects_missing_campaign():
    _reset_store()
    obs = _make_obs(
        ObservationType.timeout_signal.value,
        campaign_id="cmp_missing_campaign",
    )
    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is None
    assert existing is False
    assert isinstance(error, EvidencePackBuildError)
    assert error.code == "campaign_not_found"
    assert memory_store.evidence_packs == {}


def test_build_from_verification_plan_route_returns_200():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)
    plan = _make_plan(obs, goal="store_only", required_evidence=[])

    client = _get_test_client()
    resp = client.post(f"/v1/evidence/build-from-plan/{plan.verification_plan_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["evidence_pack"]["verification_plan_id"] == plan.verification_plan_id


def test_build_from_verification_plan_route_404_for_missing_plan():
    _reset_store()
    client = _get_test_client()
    resp = client.post("/v1/evidence/build-from-plan/vplan_missing_xyz")
    assert resp.status_code == 404
    assert resp.json()["error"] == "verification_plan_not_found"


def test_builder_does_not_attach_artifacts_from_other_campaign():
    _reset_store()
    _create_campaign("cmp_a")
    _create_campaign("cmp_b")
    _store_finished_run(tool_run_id="toolrun_b", campaign_id="cmp_b")
    memory_store.store_artifact(
        "art_cross",
        "toolrun_b",
        {
            "artifact_id": "art_cross",
            "artifact_type": "stdout",
            "path": "/tmp/cross.log",
            "size_bytes": 42,
            "campaign_id": "cmp_b",
            "tool_run_id": "toolrun_b",
            "content": "secret",
        },
    )
    obs = _make_obs(
        ObservationType.timeout_signal.value,
        campaign_id="cmp_a",
        tool_run_id="toolrun_b",
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is None
    assert existing is False
    assert isinstance(error, EvidencePackBuildError)
    assert error.code == "tool_run_campaign_mismatch"
    assert memory_store.evidence_packs == {}


def test_get_evidence_pack_route_returns_pack():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None

    client = _get_test_client()
    resp = client.get(f"/v1/evidence/packs/{pack.evidence_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["evidence_id"] == pack.evidence_id


def test_get_evidence_pack_route_404_for_missing_pack():
    _reset_store()
    client = _get_test_client()
    resp = client.get("/v1/evidence/packs/evp_missing_xyz")
    assert resp.status_code == 404
    assert resp.json()["error"] == "evidence_pack_not_found"


def test_list_evidence_packs_by_campaign_route_returns_list():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(ObservationType.timeout_signal.value)
    EvidencePackBuilder().build_from_observation(obs.observation_id)

    client = _get_test_client()
    resp = client.get("/v1/evidence/campaign/cmp_evp1")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) == 1
    assert body[0]["campaign_id"] == "cmp_evp1"


def test_list_evidence_packs_by_campaign_route_404_for_missing_campaign():
    _reset_store()
    client = _get_test_client()
    resp = client.get("/v1/evidence/campaign/cmp_missing")
    assert resp.status_code == 404
    assert resp.json()["error"] == "campaign_not_found"


# ─── Legacy regression guard ─────────────────────────────────────


def test_existing_judge_ready_evidence_path_still_works():
    _reset_store()

    from backend.models.tool_wrappers import (
        ToolArtifacts,
        ToolBudget,
        ToolReproduction,
        ToolWrapperResult,
    )
    from backend.services.evidence_builder_service import EvidenceBuilderService

    tool_result = ToolWrapperResult(
        tool_name="custom_request_executor",
        status="ok",
        signals=["schema_violation"],
        candidate_findings=[],
        reproduction=ToolReproduction(method="GET", url="http://testapp.local/x"),
        artifacts=ToolArtifacts(),
        budget=ToolBudget(),
        termination_reason="ok",
        auth_context_name="user_a",
        source_task_id="t_legacy",
    )

    svc = EvidenceBuilderService()
    legacy = svc.from_wrapper_result(
        task=None,
        worker_role="contract_fuzzing",
        tool_result=tool_result,
        run_id="run_legacy",
        notes=["legacy path"],
    )

    assert legacy is not None
    assert legacy.tool_name == "custom_request_executor"
    assert legacy.signals == ["schema_violation"]
    assert "legacy path" in legacy.notes
    assert memory_store.evidence_packs == {}
    assert memory_store.findings == []
