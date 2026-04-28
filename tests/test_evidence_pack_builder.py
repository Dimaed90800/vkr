"""Phase 6 — EvidencePackBuilder tests.

Covers builder behavior per observation type, idempotency, route surface,
isolation guarantees, and a regression guard for the legacy
``EvidenceBuilderService.from_wrapper_result`` (JudgeReadyEvidence) path.
"""
from __future__ import annotations

import json
import os
import re
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
    memory_store.runtime_response_json_secrets.clear()
    memory_store.runtime_object_id_secrets.clear()
    memory_store.runtime_resource_instances.clear()
    memory_store.runtime_resource_instances_by_campaign.clear()
    memory_store.runtime_bola_object_pairs.clear()
    memory_store.runtime_bola_object_pairs_by_campaign.clear()


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
    *,
    worker_class: str = "",
    strategy: str | None = None,
) -> VerificationPlan:
    plan = VerificationPlan(
        verification_plan_id=plan_id,
        campaign_id=obs.campaign_id,
        parent_observation_id=obs.observation_id,
        parent_task_id=obs.task_id,
        goal=goal,
        worker_class=worker_class,
        strategy=strategy if strategy is not None else goal,
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
    auth_required: bool = False,
    resource_type: str = "",
    risk_hints: list[str] | None = None,
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
                auth_required=auth_required,
                resource_type=resource_type,
                risk_hints=risk_hints or [],
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


def test_build_bola_replay_result_evidence_ready_when_access_granted() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run()
    replay = _add_corpus(
        url="http://testapp.local/community/api/v2/community/posts/post-123",
        path_template="/community/api/v2/community/posts/{postId}",
        role="authprof_attacker_1",
        status_code=200,
        operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        response_body={"id": "post-123", "title": "owned"},
    )
    obs = _make_obs(
        ObservationType.bola_replay_result.value,
        operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        request_id=replay.request_id,
        auth_profile="authprof_attacker_1",
        status_code=200,
        confidence=0.95,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_1",
            "resource_type": "post",
            "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
            "target_path_template": "/community/api/v2/community/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "request_id": replay.request_id,
            "result": "attacker_access_granted",
            "access_granted": True,
            "evidence_strength": "high",
            "reason_codes": ["owner_baseline_valid", "attacker_access_granted"],
            "owner_baseline_valid": True,
            "owner_status_code": 200,
            "owner_result": "attacker_access_granted",
            "attacker_status_code": 200,
            "attacker_result": "attacker_access_granted",
            "replay_classification": "possible_bola",
        },
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.vulnerability_class == "bola"
    assert pack.owasp_category == "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION"
    assert pack.attack is not None and pack.attack.request_ref is not None
    assert pack.attack.request_ref.request_id == replay.request_id
    blob = json.dumps(pack.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("post-123", "bearer ", "set-cookie", "cookie:", "password", "response_body"):
        assert bad not in blob


def test_build_bola_replay_result_evidence_not_ready_when_denied() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run()
    replay = _add_corpus(
        url="http://testapp.local/community/api/v2/community/posts/post-404",
        path_template="/community/api/v2/community/posts/{postId}",
        role="authprof_attacker_1",
        status_code=403,
        operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        response_body={"error": "forbidden"},
    )
    obs = _make_obs(
        ObservationType.bola_replay_result.value,
        operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        request_id=replay.request_id,
        auth_profile="authprof_attacker_1",
        status_code=403,
        confidence=0.5,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_2",
            "resource_type": "post",
            "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
            "target_path_template": "/community/api/v2/community/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "request_id": replay.request_id,
            "result": "attacker_access_denied",
            "access_granted": False,
            "evidence_strength": "low",
            "reason_codes": ["owner_baseline_valid", "attacker_denied"],
            "owner_baseline_valid": True,
            "owner_status_code": 200,
            "owner_result": "attacker_access_granted",
            "attacker_status_code": 403,
            "attacker_result": "attacker_access_denied",
            "replay_classification": "access_denied",
        },
    )

    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.judge_ready is False
    assert pack.status == "incomplete"


def test_build_bola_replay_result_evidence_not_ready_when_invalid_object_pair() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run()
    obs = _make_obs(
        ObservationType.bola_replay_result.value,
        operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        request_id="",
        auth_profile="authprof_attacker_1",
        status_code=400,
        confidence=0.2,
        details={
            "validation_mode": "bola_replay",
            "object_pair_id": "objpair_3",
            "resource_type": "post",
            "target_operation_id": "op_GET_/community/api/v2/community/posts/{postId}",
            "target_path_template": "/community/api/v2/community/posts/{postId}",
            "target_method": "GET",
            "path_param_name": "postId",
            "attacker_auth_profile_id": "authprof_attacker_1",
            "owner_auth_profile_id": "authprof_owner_1",
            "result": "invalid_object_pair",
            "access_granted": False,
            "evidence_strength": "low",
            "reason_codes": ["owner_baseline_failed"],
            "owner_baseline_valid": False,
            "owner_status_code": 400,
            "owner_result": "non_2xx",
            "attacker_status_code": 0,
            "attacker_result": "skipped",
            "replay_classification": "invalid_object_pair",
        },
    )
    pack, error, existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.judge_ready is False


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


def test_build_undocumented_endpoint_signal_ready_for_judge():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="undocumented_endpoint_validator")
    obs = _make_obs(
        ObservationType.undocumented_endpoint_signal.value,
        operation_id="",
        details={
            "method": "GET",
            "path": "/api/hidden",
            "url_sanitized": "http://testapp.local/api/hidden",
            "status_code": 200,
            "source": "zap_discovery_passive",
            "source_observation_id": "obs_disc_1",
            "openapi_match": False,
            "matched_operation_id": "",
            "is_static_asset": False,
            "validation_mode": "one_shot_undocumented_endpoint_check",
        },
    )
    _make_plan(
        obs,
        goal="validate_undocumented_endpoint_inventory",
        required_evidence=["discovered_endpoint", "openapi_absence", "runtime_observed_status"],
        plan_id="vplan_undoc_ready",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_undoc_ready")
    assert pack is not None
    assert pack.owasp_category == "API9_IMPROPER_INVENTORY_MANAGEMENT"
    assert pack.vulnerability_class == "undocumented_api_endpoint"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert "undocumented_endpoint_signal" in pack.derived_signals
    blob = json.dumps(pack.model_dump(mode="json")).lower()
    for bad in ("authorization", "cookie", "set-cookie", "request_body", "response_body", "raw_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_build_undocumented_endpoint_signal_missing_status_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="undocumented_endpoint_validator")
    obs = _make_obs(
        ObservationType.undocumented_endpoint_signal.value,
        details={
            "method": "GET",
            "path": "/api/hidden",
            "url_sanitized": "http://testapp.local/api/hidden",
            "openapi_match": False,
            "is_static_asset": False,
        },
    )
    _make_plan(
        obs,
        goal="validate_undocumented_endpoint_inventory",
        required_evidence=["discovered_endpoint", "openapi_absence", "runtime_observed_status"],
        plan_id="vplan_undoc_missing",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_undoc_missing")
    assert pack is not None
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "runtime_status_missing" in missing_codes
    assert pack.judge_ready is False


def test_build_ssrf_candidate_signal_maps_to_api7_and_stays_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="ssrf_candidate_detector")
    obs = _make_obs(
        ObservationType.ssrf_candidate_signal.value,
        operation_id="op_POST_/api/v1/hooks",
        details={
            "operation_id": "op_POST_/api/v1/hooks",
            "method": "POST",
            "path": "/api/v1/hooks",
            "field_name": "callback_url",
            "field_path": "$.callback_url",
            "schema_type": "string",
            "schema_format": "uri",
            "confidence": "high",
            "reason_codes": ["url_like_field_name", "schema_format_uri"],
            "validation_mode": "ssrf_candidate_detection",
        },
    )
    _make_plan(
        obs,
        goal="validate_ssrf_candidate_safely",
        required_evidence=["openapi_schema_url_like_field", "operation_context"],
        plan_id="vplan_ssrf_diag",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_ssrf_diag")
    assert pack is not None
    assert pack.owasp_category == "API7_SERVER_SIDE_REQUEST_FORGERY"
    assert pack.vulnerability_class == "ssrf_candidate"
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False
    assert "ssrf_candidate_signal" in pack.derived_signals
    blob = json.dumps(pack.model_dump(mode="json")).lower()
    for bad in ("authorization", "cookie", "set-cookie", "request_body", "response_body", "raw_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_build_auth_flow_signal_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="auth_flow_detector")
    obs = _make_obs(
        ObservationType.auth_flow_signal.value,
        observation_id="obs_auth_flow_evp",
        details={
            "source": "auth_flow_detector",
            "validation_mode": "auth_flow_detection",
            "auth_flow_detected": True,
            "signup_candidates": [],
            "login_candidates": [],
            "token_response_candidates": [],
            "profile_candidates": [{"operation_id": "op_GET_/me", "method": "GET", "path": "/me", "confidence": "low", "reason_codes": ["path_profile_me_user_account"]}],
            "missing_prerequisites": [],
            "reason_codes": [],
        },
    )
    pack, error, _existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert pack is not None
    assert pack.owasp_category == "API2_AUTH"
    assert pack.vulnerability_class == "auth_flow_diagnostic"
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False


def test_build_resource_instance_inventory_not_judge_ready() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="resource_instance_extractor")
    obs = _make_obs(
        ObservationType.resource_instance_inventory.value,
        observation_id="obs_resource_inventory_evp",
        details={
            "source": "resource_instance_extractor",
            "validation_mode": "resource_instance_extraction",
            "source_observation_id": "obs_rfi_source",
            "source_operation_id": "op_GET_/api/v1/me",
            "source_path": "/api/v1/me",
            "source_auth_profile_id": "authprof_owner_1",
            "source_role_hint": "owner",
            "resource_instances_count": 1,
            "resource_types": ["vehicle"],
            "object_refs": [{
                "object_ref_id": "objref_1",
                "resource_type": "vehicle",
                "object_id_field": "vehicleid",
                "object_id_ref": "objidref_1",
                "confidence": "high",
            }],
            "reason_codes": ["resource_ids_extracted"],
        },
    )
    pack, error, _existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert pack is not None
    assert pack.owasp_category == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False
    blob = json.dumps(pack.model_dump(mode="json")).lower()
    assert "veh-123" not in blob


def test_build_resource_seed_result_not_judge_ready() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="resource_seed_worker")
    obs = _make_obs(
        ObservationType.resource_seed_result.value,
        observation_id="obs_resource_seed_evp",
        details={
            "validation_mode": "resource_seed",
            "seed_status": "seeded",
            "resource_type": "order",
            "owner_auth_profile_id": "authprof_owner_1",
            "seed_operation_id": "op_POST_/api/orders",
            "seed_method": "POST",
            "seed_path": "/api/orders",
            "followup_operation_id": "",
            "object_refs_created_count": 1,
            "object_refs": [{
                "object_ref_id": "objref_1",
                "object_id_ref": "objidref_1",
                "object_id_field": "order_id",
                "resource_type": "order",
                "confidence": "high",
            }],
            "http_calls_count": 1,
            "reason_codes": ["resource_ids_extracted"],
        },
    )
    pack, error, _existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert pack is not None
    assert pack.owasp_category == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False


def test_build_bola_object_pair_inventory_not_judge_ready() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="bola_object_pair_builder")
    obs = _make_obs(
        ObservationType.bola_object_pair_inventory.value,
        observation_id="obs_bola_pair_inventory_evp",
        details={
            "validation_mode": "bola_object_pair_building",
            "object_pairs_count": 1,
            "resource_types": ["vehicle"],
            "object_pairs": [{
                "object_pair_id": "objpair_1",
                "resource_type": "vehicle",
                "object_ref_id": "objref_1",
                "object_id_ref": "objidref_1",
                "owner_auth_profile_id": "authprof_owner_1",
                "attacker_auth_profile_id": "authprof_attacker_1",
                "target_operation_id": "op_GET_/api/v1/vehicles/{vehicleId}",
                "target_path_template": "/api/v1/vehicles/{vehicleId}",
                "target_method": "GET",
                "path_param_name": "vehicleId",
                "confidence": "high",
                "reason_codes": ["path_param_resource_match"],
            }],
            "reason_codes": ["object_pairs_built"],
        },
    )
    pack, error, _existing = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert error is None
    assert pack is not None
    assert pack.owasp_category == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
    assert pack.status == "not_judge_ready"
    assert pack.judge_ready is False


def test_schema_mismatch_schemathesis_strong_signals_ready_for_judge():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    _store_api_graph_with_op(
        operation_id="op_GET_/api/v1/items/{id}",
        method="GET",
        path_template="/api/v1/items/{id}",
        owasp_candidates=[],
    )
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "exit_code": 1,
            "signal_count": 3,
            "signal_types": ["5xx", "schema_violation", "unexpected_2xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_ok",
    )

    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_ok")
    assert pack is not None
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    assert pack.vulnerability_class == "api_schema_contract_violation"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.missing_evidence == []
    assert "schema_mismatch" in pack.derived_signals
    assert "tool_name:schemathesis_negative_test" in pack.derived_signals
    assert "operation_id:op_GET_/api/v1/items/{id}" in pack.derived_signals
    assert "signal_count:3" in pack.derived_signals
    assert "exit_code:1" in pack.derived_signals
    assert "signal:5xx" in pack.derived_signals
    assert "signal:schema_violation" in pack.derived_signals
    assert "strong_signal_count:3" in pack.derived_signals
    assert "signal_interpretation:server_error_on_negative_contract_test" in pack.derived_signals
    assert "signal_interpretation:unexpected_success_on_invalid_input" in pack.derived_signals
    assert "signal_interpretation:response_schema_contract_violation" in pack.derived_signals
    assert any(s.startswith("impact_summary:") for s in pack.derived_signals)
    assert pack.replay_steps
    assert pack.replay_steps[0].description.startswith("Schemathesis negative testing")


def test_schema_mismatch_required_evidence_canonical_codes_satisfied():
    """Phase 16E-fix: canonical triage codes merge to ready_for_judge."""
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=[
            "schemathesis_signal",
            "operation_context",
            "impact_classification",
        ],
        plan_id="vplan_schema_canonical_only",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_canonical_only")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.missing_evidence == []


def test_schema_mismatch_legacy_operation_id_required_evidence_is_satisfied_when_matches():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    op = "op_GET_/api/v1/items/{id}"
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id=op,
        details={
            "operation_id": op,
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=[
            "schemathesis_signal",
            "operation_context",
            "impact_classification",
            f"operation_id:{op}",
        ],
        plan_id="vplan_schema_legacy_op_ok",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_legacy_op_ok")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert not any(m.code.startswith("operation_id:") for m in pack.missing_evidence)


def test_schema_mismatch_legacy_operation_id_required_evidence_missing_when_mismatch():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=[
            "schemathesis_signal",
            "operation_context",
            "impact_classification",
            "operation_id:op_OTHER_not_matching",
        ],
        plan_id="vplan_schema_legacy_op_bad",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_legacy_op_bad")
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "operation_id:op_OTHER_not_matching" in missing_codes


def test_phase16e_fix_regression_bola_and_security_header_evidence_unchanged():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()
    bola_obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        observation_id="obs_bola_fix",
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
    pack_b, _, _ = EvidencePackBuilder().build_from_observation(bola_obs.observation_id)
    assert pack_b is not None
    assert pack_b.status == "ready_for_judge"
    assert pack_b.judge_ready is True

    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    hdr_obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        observation_id="obs_hdr_fix",
        operation_id="",
        details={
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
            "actual_state": "missing",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_header_fix",
            "url": "http://testapp.local/frame",
        },
    )
    pack_h, _, _ = EvidencePackBuilder().build_from_observation(hdr_obs.observation_id)
    assert pack_h is not None
    assert pack_h.status == "ready_for_judge"
    assert pack_h.judge_ready is True


def _inj_obs_details(**kwargs: object) -> dict:
    base: dict = {
        "operation_id": "op_GET_/api/v1/items/{id}",
        "tool_name": "injection_test",
        "parameter_name": "q",
        "parameter_location": "query",
        "payload_family": "sql_like",
        "payload_label": "sql_quote_single",
        "signal_types": ["server_error_on_payload"],
        "baseline_status": 200,
        "attack_status": 500,
        "response_delta_class": "new_5xx",
        "marker_reflected": False,
        "error_pattern_class": "none",
    }
    base.update(kwargs)
    return base


def test_injection_signal_strong_ready_for_judge() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    op_id = "op_GET_/api/v1/items/{id}"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/v1/items/{id}",
        owasp_candidates=[],
    )
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_ready",
        operation_id=op_id,
        details=_inj_obs_details(),
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_ready",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_ready")
    assert pack is not None
    assert pack.vulnerability_class == "potential_injection"
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.missing_evidence == []
    assert "Injection probe reported strong signals for operation" in (pack.hypothesis or "")
    assert op_id in (pack.hypothesis or "")
    assert "injection_signal" in pack.derived_signals
    assert "strong_signal:server_error_on_payload" in pack.derived_signals
    assert "parameter_name:q" in pack.derived_signals


def test_injection_signal_missing_parameter_context_incomplete() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    d = _inj_obs_details()
    d["parameter_name"] = ""
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_noparam",
        operation_id="op_GET_/api/v1/items/{id}",
        details=d,
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_noparam",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_noparam")
    codes = {m.code for m in pack.missing_evidence}
    assert "injection_parameter_context_missing" in codes
    assert pack.status == "incomplete"
    assert pack.judge_ready is False


def test_injection_signal_missing_baseline_attack_delta_incomplete() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    d = _inj_obs_details()
    del d["baseline_status"]
    del d["attack_status"]
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_nodelta",
        operation_id="op_GET_/api/v1/items/{id}",
        details=d,
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_nodelta",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_nodelta")
    codes = {m.code for m in pack.missing_evidence}
    assert "baseline_attack_delta_missing" in codes


def test_injection_signal_weak_only_incomplete() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_weak",
        operation_id="op_GET_/api/v1/items/{id}",
        details=_inj_obs_details(
            signal_types=["status_changed", "response_size_changed"],
            baseline_status=200,
            attack_status=200,
            response_delta_class="unchanged",
        ),
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_weak",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_weak")
    codes = {m.code for m in pack.missing_evidence}
    assert "impact_classification_missing" in codes
    assert "impact_classification" in codes
    assert pack.status == "incomplete"


def test_injection_signal_wrong_tool_name_incomplete() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_badtool",
        operation_id="op_GET_/api/v1/items/{id}",
        details=_inj_obs_details(tool_name="cats_fuzz_test"),
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_badtool",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_badtool")
    assert any(m.code == "tool_name_mismatch" for m in pack.missing_evidence)
    assert pack.status == "incomplete"


def test_injection_signal_replay_steps_no_raw_payload_body_headers() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    op_id = "op_GET_/api/v1/items/{id}"
    _store_api_graph_with_op(operation_id=op_id, method="GET", path_template="/api/v1/items/{id}")
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_replay",
        operation_id=op_id,
        details=_inj_obs_details(),
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_replay",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_replay")
    assert pack.replay_steps
    step = pack.replay_steps[0]
    assert "Injection probe compared baseline" in step.description
    blob = str(pack.model_dump(mode="json")).lower()
    for bad in ("response_body", "request_body", "authorization:", "bearer "):
        assert bad not in blob


def test_injection_required_evidence_codes_satisfied() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="injection_test")
    op_id = "op_GET_/api/v1/items/{id}"
    _store_api_graph_with_op(operation_id=op_id, method="GET", path_template="/api/v1/items/{id}")
    obs = _make_obs(
        ObservationType.injection_signal.value,
        observation_id="obs_inj_sat",
        operation_id=op_id,
        details=_inj_obs_details(),
    )
    _make_plan(
        obs,
        goal="validate_injection_impact",
        required_evidence=[
            "injection_signal",
            "parameter_context",
            "baseline_attack_delta",
            "impact_classification",
        ],
        plan_id="vplan_inj_sat",
        worker_class="contract_fuzzing",
        strategy="validate_injection_impact",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_inj_sat")
    assert EvidencePackBuilder._is_required_code_satisfied("injection_signal", pack)
    assert EvidencePackBuilder._is_required_code_satisfied("parameter_context", pack)
    assert EvidencePackBuilder._is_required_code_satisfied("baseline_attack_delta", pack)
    assert EvidencePackBuilder._is_required_code_satisfied("impact_classification", pack)


def test_regression_phase17b2_bola_evidence_unchanged() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run()
    ctx = _setup_complete_bola_corpus()
    bola_obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        observation_id="obs_bola_17b2",
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
    pack_b, _, _ = EvidencePackBuilder().build_from_observation(bola_obs.observation_id)
    assert pack_b.status == "ready_for_judge"
    assert pack_b.judge_ready is True


def test_regression_phase17b2_security_header_evidence_unchanged() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    hdr_obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        observation_id="obs_hdr_17b2",
        operation_id="",
        details={
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
            "actual_state": "missing",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_1",
            "url": "http://testapp.local/frame",
        },
    )
    pack_h, _, _ = EvidencePackBuilder().build_from_observation(hdr_obs.observation_id)
    assert pack_h.vulnerability_class == "security_header_misconfiguration"
    assert pack_h.status == "ready_for_judge"
    assert pack_h.judge_ready is True


def test_regression_phase17b2_schema_mismatch_evidence_unchanged() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        observation_id="obs_schema_17b2",
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_17b2",
    )
    pack_s, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_17b2")
    assert pack_s.vulnerability_class == "api_schema_contract_violation"
    assert pack_s.status == "ready_for_judge"
    assert pack_s.judge_ready is True


def test_schema_mismatch_strong_signals_include_interpretation_and_impact_summary():
    """Phase 16E-A: interpretation lines and impact_summary on strong Schemathesis signals."""
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_interp",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_interp")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert "signal_interpretation:server_error_on_negative_contract_test" in pack.derived_signals
    assert "strong_signal_count:1" in pack.derived_signals
    imp = next(s for s in pack.derived_signals if s.startswith("impact_summary:"))
    assert "server error" in imp.lower()


def test_schema_mismatch_multiple_strong_signals_combines_impact_summary_compactly():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx", "unexpected_2xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_multi",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_multi")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert "signal_interpretation:server_error_on_negative_contract_test" in pack.derived_signals
    assert "signal_interpretation:unexpected_success_on_invalid_input" in pack.derived_signals
    imp = next(s for s in pack.derived_signals if s.startswith("impact_summary:"))
    assert "server error" in imp.lower() and "invalid" in imp.lower()


def test_schema_mismatch_graph_context_added_when_operation_exists():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    op_id = "op_GET_/api/v1/items/{id}"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/v1/items/{id}",
        owasp_candidates=["API1_BOLA", "API8_MISCONFIG"],
        auth_required=True,
        resource_type="Item",
        risk_hints=["pii", "authz", "extra_hint"],
    )
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id=op_id,
        details={
            "operation_id": op_id,
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["schema_violation"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_graph",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_graph")
    assert pack is not None
    assert "method:GET" in pack.derived_signals
    assert "path_template:/api/v1/items/{id}" in pack.derived_signals
    assert "auth_required:true" in pack.derived_signals
    assert "resource_type:Item" in pack.derived_signals
    assert "risk_hint:pii" in pack.derived_signals
    assert "risk_hint:authz" in pack.derived_signals
    assert "risk_hint:extra_hint" in pack.derived_signals
    assert "owasp_candidate:API1_BOLA" in pack.derived_signals
    assert "owasp_candidate:API8_MISCONFIG" in pack.derived_signals


def test_schema_mismatch_graph_context_missing_does_not_block_ready_if_required_fields_present():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_UNKNOWN_not_in_graph",
        details={
            "operation_id": "op_UNKNOWN_not_in_graph",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_nograph",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_nograph")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert not any(s.startswith("method:") for s in pack.derived_signals)
    assert not any(s.startswith("path_template:") for s in pack.derived_signals)


def test_schema_mismatch_does_not_add_raw_body_headers_or_url_query():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    op_id = "op_GET_/api/v1/items/{id}"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/v1/items/{id}?token=secret&sig=abc",
        owasp_candidates=[],
    )
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id=op_id,
        details={
            "operation_id": op_id,
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["5xx"],
            "malicious_note": "Authorization: Bearer X",
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_safe",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_safe")
    blob = "\n".join(pack.derived_signals)
    assert "?" not in blob
    assert "Bearer" not in blob
    assert "Authorization" not in blob
    assert "token=secret" not in blob


def test_phase16e_regression_security_header_evidence_unchanged():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        operation_id="",
        details={
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
            "actual_state": "missing",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_header_1",
            "url": "http://testapp.local/frame",
        },
    )
    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)
    assert pack is not None
    assert pack.vulnerability_class == "security_header_misconfiguration"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert "validated_security_header_issue" in pack.derived_signals
    assert "impact_summary:" not in "\n".join(pack.derived_signals)


def test_phase16e_regression_bola_cross_role_evidence_unchanged():
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
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert "impact_summary:" not in "\n".join(pack.derived_signals)


def test_schema_mismatch_missing_signal_types_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": [],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_missing_signals",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_missing_signals")
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "schemathesis_signal_missing" in missing_codes


def test_schema_mismatch_weak_signals_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["warning", "unknown"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_weak",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_weak")
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "impact_classification_missing" in missing_codes


def test_schema_mismatch_wrong_tool_name_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="custom_request_executor")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "custom_request_executor",
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_wrong_tool",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_wrong_tool")
    assert pack is not None
    assert pack.status == "incomplete"
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "tool_name_mismatch" in missing_codes


def test_schema_mismatch_missing_operation_id_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="",
        details={
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["schema_violation"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_missing_op",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_missing_op")
    assert pack is not None
    assert pack.status == "incomplete"
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "operation_context_missing" in missing_codes


def test_schema_mismatch_wrong_verification_goal_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_types": ["schema_violation"],
        },
    )
    _make_plan(
        obs,
        goal="impact_validation",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_wrong_goal",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_wrong_goal")
    assert pack is not None
    assert pack.status == "incomplete"
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "verification_goal_mismatch" in missing_codes


def test_schema_mismatch_exit_code_missing_does_not_block_if_strong_signals_present():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_count": 1,
            "signal_types": ["5xx"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_no_exit",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_no_exit")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert all(not s.startswith("exit_code:") for s in pack.derived_signals)


def test_schema_mismatch_non_numeric_signal_count_does_not_fail_and_uses_fallback():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="schemathesis_negative_test")
    obs = _make_obs(
        ObservationType.schema_mismatch.value,
        operation_id="op_GET_/api/v1/items/{id}",
        details={
            "operation_id": "op_GET_/api/v1/items/{id}",
            "tool_name": "schemathesis_negative_test",
            "signal_count": "N/A",
            "signal_types": ["5xx", "schema_violation"],
        },
    )
    _make_plan(
        obs,
        goal="validate_schema_mismatch_impact",
        required_evidence=["schemathesis_signal", "operation_context", "impact_classification"],
        plan_id="vplan_schema_bad_count",
    )
    pack, _, _ = EvidencePackBuilder().build_from_verification_plan("vplan_schema_bad_count")
    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert "signal_count:2" in pack.derived_signals


def test_build_security_header_evidence_ready_from_complete_validated_issue():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        operation_id="",
        details={
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
            "actual_state": "missing",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_header_1",
            "url": "http://testapp.local/frame",
        },
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)

    assert pack is not None
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    assert pack.vulnerability_class == "security_header_misconfiguration"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    assert pack.method == "GET"
    assert pack.replay_steps
    assert pack.replay_steps[0].description == "Validated security header misconfiguration"
    assert "validated_security_header_issue" in pack.derived_signals
    assert "header_name:X-Frame-Options" in pack.derived_signals
    assert not pack.missing_evidence


def test_build_security_header_evidence_missing_required_fields_incomplete():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        details={},
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)

    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "header_name_missing" in missing_codes
    assert "alert_name_missing" in missing_codes
    assert "actual_state_missing" in missing_codes
    assert "validation_mode_missing" in missing_codes
    assert "source_observation_id_missing" in missing_codes
    assert "target_location_missing" in missing_codes


def test_build_security_header_evidence_unsafe_value_requires_actual_value():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="security_header_validator")
    obs = _make_obs(
        ObservationType.validated_security_header_issue.value,
        details={
            "header_name": "X-Content-Type-Options",
            "alert_name": "X-Content-Type-Options Header Missing",
            "actual_state": "unsafe_value",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_header_2",
            "path": "/api/content",
        },
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(obs.observation_id)

    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    missing_codes = {m.code for m in pack.missing_evidence}
    assert "actual_value_missing_for_unsafe_value" in missing_codes


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


def test_build_security_header_evidence_missing_state_does_not_affect_bola_readiness():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    setup = _setup_complete_bola_corpus()
    bola_obs = _make_obs(
        ObservationType.cross_role_access_signal.value,
        operation_id=setup["op_id"],
        request_id=setup["attacker_attack"].request_id,
        confidence=0.9,
        details={
            "object_id": setup["object_id"],
            "owner_role": setup["owner_role"],
            "attacker_role": setup["attacker_role"],
            "owner_collection_request_id": setup["owner_collection"].request_id,
            "attacker_collection_request_id": setup["attacker_collection"].request_id,
        },
    )
    _make_obs(
        ObservationType.validated_security_header_issue.value,
        observation_id="obs_header_incomplete",
        details={
            "header_name": "X-Frame-Options",
            "alert_name": "X-Frame-Options Header Not Set",
            "validation_mode": "single_replay_header_check",
            "source_observation_id": "obs_zap_header_3",
            "url": "http://testapp.local/frame",
        },
    )

    pack, _, _ = EvidencePackBuilder().build_from_observation(bola_obs.observation_id)

    assert pack is not None
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True


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


def test_build_mass_assignment_signal_pack_with_diagnostic_context_ready_for_judge():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="property_mutation_test")
    op_id = "op_PATCH_/users/{id}"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="PATCH",
        path_template="/users/{id}",
        owasp_candidates=[],
    )
    seed = _add_corpus(
        method="PATCH",
        url="http://testapp.local/users/123",
        path_template="/users/{id}",
        role="user_a",
        status_code=200,
        operation_id=op_id,
    )
    obs = _make_obs(
        ObservationType.mass_assignment_signal.value,
        observation_id="obs_mass_assignment_ready",
        operation_id=op_id,
        details={
            "tool_name": "property_mutation_test",
            "operation_id": op_id,
            "signal_types": [
                "candidate_sensitive_writable_fields",
                "seed_context_present",
                "diagnostic_probe_ready",
            ],
            "mutation_policy": "diagnostic_only",
            "diagnostic_only": True,
            "runtime_effect_proven": False,
            "fields_selected": ["isAdmin"],
            "fields_considered_count": 3,
            "fields_skipped_count": 1,
            "seed_request_id": seed.request_id,
            "seed_request_id_present": True,
            "proof_scope": "diagnostic_signal_only",
        },
    )
    _make_plan(
        obs,
        goal="validate_mass_assignment_impact",
        required_evidence=[
            "mass_assignment_signal",
            "seed_reference",
            "field_selection_context",
            "runtime_effect_assessment",
        ],
        plan_id="vplan_mass_assignment_ready",
        worker_class="access_control",
        strategy="validate_mass_assignment_impact",
    )

    pack, error, existing = EvidencePackBuilder().build_from_verification_plan(
        "vplan_mass_assignment_ready"
    )
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.vulnerability_class == "potential_mass_assignment"
    assert pack.owasp_category == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
    assert "runtime_effect_proven:false" in pack.derived_signals
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    blob = json.dumps(pack.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("request_body", "response_body", "raw_body", "headers", "bearer ", "token=", "set-cookie"):
        assert bad not in blob
    assert re.search(r"[\"']authorization[\"']\\s*:", blob) is None
    assert re.search(r"[\"']cookie[\"']\\s*:", blob) is None


def test_build_data_exposure_signal_pack_api3_sensitive_property_exposure_judge_ready() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="data_exposure_validator")
    _store_api_graph_with_op(
        operation_id="op_GET_/api/profile",
        method="GET",
        path_template="/api/profile",
        owasp_candidates=["API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"],
    )
    obs = _make_obs(
        ObservationType.data_exposure_signal.value,
        observation_id="obs_dex_evp_1",
        operation_id="op_GET_/api/profile",
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/profile",
            "path": "/api/profile",
            "method": "GET",
            "status_code": 200,
            "sensitive_field_count": 1,
            "sensitive_categories": ["identity"],
            "sensitive_fields": [{"field_name": "email", "field_path": "$.email", "category": "identity"}],
        },
    )
    _make_plan(
        obs,
        goal="prove_sensitive_property_exposure",
        required_evidence=[
            "response_field_inventory",
            "sensitive_field_names",
            "operation_context",
        ],
        plan_id="vplan_dex_evp",
        worker_class="access_control",
        strategy="validate_response_field_exposure",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_dex_evp")
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.owasp_category == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION"
    assert pack.vulnerability_class == "sensitive_property_exposure"
    assert pack.judge_ready is True
    assert pack.status == "ready_for_judge"
    blob = json.dumps(pack.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("request_body", "response_body", "raw_body", "set-cookie", "bearer ", "token="):
        assert bad not in blob


def test_build_data_exposure_signal_wrong_tool_not_judge_ready() -> None:
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="data_exposure_validator")
    obs = _make_obs(
        ObservationType.data_exposure_signal.value,
        observation_id="obs_dex_evp_badtool",
        operation_id="op_GET_/api/profile",
        details={
            "tool_name": "other_tool",
            "operation_id": "op_GET_/api/profile",
            "path": "/api/profile",
            "method": "GET",
            "status_code": 200,
            "sensitive_field_count": 1,
            "sensitive_categories": ["identity"],
            "sensitive_fields": [{"field_name": "email", "field_path": "$.email", "category": "identity"}],
        },
    )
    _make_plan(
        obs,
        goal="prove_sensitive_property_exposure",
        required_evidence=["operation_context"],
        plan_id="vplan_dex_bad",
        worker_class="access_control",
        strategy="validate_response_field_exposure",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_dex_bad")
    assert error is None
    assert pack is not None
    assert pack.judge_ready is False


def test_build_mass_assignment_signal_pack_missing_seed_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="property_mutation_test")
    op_id = "op_PATCH_/users/{id}"
    obs = _make_obs(
        ObservationType.mass_assignment_signal.value,
        observation_id="obs_mass_assignment_missing_seed",
        operation_id=op_id,
        details={
            "tool_name": "property_mutation_test",
            "operation_id": op_id,
            "mutation_policy": "diagnostic_only",
            "diagnostic_only": True,
            "runtime_effect_proven": False,
            "fields_selected": ["isAdmin"],
            "seed_request_id_present": False,
        },
    )
    _make_plan(
        obs,
        goal="validate_mass_assignment_impact",
        required_evidence=[
            "mass_assignment_signal",
            "seed_reference",
            "field_selection_context",
            "runtime_effect_assessment",
        ],
        plan_id="vplan_mass_assignment_missing_seed",
        worker_class="access_control",
        strategy="validate_mass_assignment_impact",
    )

    pack, error, existing = EvidencePackBuilder().build_from_verification_plan(
        "vplan_mass_assignment_missing_seed"
    )
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    assert "runtime_effect_proven:false" in pack.derived_signals
    assert any(m.code == "seed_reference_missing" for m in pack.missing_evidence)


def test_get_evidence_pack_route_404_for_missing_pack():
    _reset_store()
    client = _get_test_client()
    resp = client.get("/v1/evidence/packs/evp_missing_xyz")
    assert resp.status_code == 404
    assert resp.json()["error"] == "evidence_pack_not_found"


def test_build_validated_cors_issue_pack_strong_case_ready_for_judge():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="cors_validator")
    op_id = "op_GET_/api/v1/users"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/v1/users",
        owasp_candidates=[],
    )
    obs = _make_obs(
        ObservationType.validated_cors_issue.value,
        observation_id="obs_cors_ready",
        operation_id=op_id,
        details={
            "tool_name": "cors_validator",
            "operation_id": op_id,
            "path_template": "/api/v1/users",
            "request_url": "http://testapp.local/api/v1/users",
            "origin_probe_label": "evil_example_invalid",
            "acao_state": "wildcard",
            "acac_present": True,
            "vary_origin_present": False,
            "origin_reflection_detected": False,
            "issue_codes": ["cors_wildcard_with_credentials"],
            "validation_mode": "single_replay_cors_check",
            "request_count": 1,
            "status_code": 200,
        },
    )
    _make_plan(
        obs,
        goal="prove_cors_misconfiguration",
        required_evidence=[
            "validated_cors_issue",
            "cors_policy_state",
            "origin_probe_context",
        ],
        plan_id="vplan_cors_ready",
        worker_class="misconfiguration",
        strategy="prove_cors_misconfiguration",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_cors_ready")
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.vulnerability_class == "cors_misconfiguration"
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    blob = json.dumps(pack.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("authorization", "cookie", "set-cookie", "request_body", "response_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_build_validated_cors_issue_pack_weak_case_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="cors_validator")
    obs = _make_obs(
        ObservationType.validated_cors_issue.value,
        observation_id="obs_cors_weak",
        operation_id="op_GET_/api/v1/users",
        details={
            "tool_name": "cors_validator",
            "operation_id": "op_GET_/api/v1/users",
            "path_template": "/api/v1/users",
            "request_url": "http://testapp.local/api/v1/users",
            "origin_probe_label": "evil_example_invalid",
            "acao_state": "reflective",
            "acac_present": False,
            "vary_origin_present": False,
            "origin_reflection_detected": True,
            "issue_codes": ["cors_missing_vary_origin_when_reflecting"],
            "validation_mode": "single_replay_cors_check",
        },
    )
    _make_plan(
        obs,
        goal="prove_cors_misconfiguration",
        required_evidence=[
            "validated_cors_issue",
            "cors_policy_state",
            "origin_probe_context",
        ],
        plan_id="vplan_cors_weak",
        worker_class="misconfiguration",
        strategy="prove_cors_misconfiguration",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_cors_weak")
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    assert any(m.code == "strong_cors_issue_missing" for m in pack.missing_evidence)


def test_build_validated_cookie_flag_issue_pack_strong_case_ready_for_judge():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="cookie_flag_validator")
    op_id = "op_GET_/api/v1/session"
    _store_api_graph_with_op(
        operation_id=op_id,
        method="GET",
        path_template="/api/v1/session",
        owasp_candidates=[],
    )
    obs = _make_obs(
        ObservationType.validated_cookie_flag_issue.value,
        observation_id="obs_cookie_ready",
        operation_id=op_id,
        details={
            "tool_name": "cookie_flag_validator",
            "operation_id": op_id,
            "path_template": "/api/v1/session",
            "request_url": "https://testapp.local/api/v1/session",
            "validation_mode": "baseline_cookie_flag_check",
            "cookie_name_hash": "deadbeefcafefeed",
            "issue_codes": ["missing_httponly"],
            "has_httponly": False,
            "has_secure": True,
            "samesite_state": "lax",
            "is_https": True,
            "status_code": 200,
        },
    )
    _make_plan(
        obs,
        goal="prove_cookie_flag_misconfiguration",
        required_evidence=[
            "validated_cookie_flag_issue",
            "cookie_flag_context",
            "endpoint_context",
        ],
        plan_id="vplan_cookie_ready",
        worker_class="misconfiguration",
        strategy="prove_cookie_flag_misconfiguration",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_cookie_ready")
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.vulnerability_class == "cookie_flag_misconfiguration"
    assert pack.owasp_category == "API8_SECURITY_MISCONFIGURATION"
    assert pack.status == "ready_for_judge"
    assert pack.judge_ready is True
    blob = json.dumps(pack.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("set-cookie", "sessionid", "abc123", "response_body", "request_body", "headers", "bearer ", "token="):
        assert bad not in blob


def test_build_validated_cookie_flag_issue_pack_missing_hash_not_judge_ready():
    _reset_store()
    _create_campaign()
    _store_finished_run(tool_name="cookie_flag_validator")
    obs = _make_obs(
        ObservationType.validated_cookie_flag_issue.value,
        observation_id="obs_cookie_weak",
        operation_id="op_GET_/api/v1/session",
        details={
            "tool_name": "cookie_flag_validator",
            "operation_id": "op_GET_/api/v1/session",
            "path_template": "/api/v1/session",
            "request_url": "https://testapp.local/api/v1/session",
            "validation_mode": "baseline_cookie_flag_check",
            "issue_codes": ["missing_httponly"],
            "has_httponly": False,
            "has_secure": True,
            "samesite_state": "lax",
            "is_https": True,
        },
    )
    _make_plan(
        obs,
        goal="prove_cookie_flag_misconfiguration",
        required_evidence=[
            "validated_cookie_flag_issue",
            "cookie_flag_context",
            "endpoint_context",
        ],
        plan_id="vplan_cookie_weak",
        worker_class="misconfiguration",
        strategy="prove_cookie_flag_misconfiguration",
    )
    pack, error, existing = EvidencePackBuilder().build_from_verification_plan("vplan_cookie_weak")
    assert error is None
    assert existing is False
    assert pack is not None
    assert pack.status == "incomplete"
    assert pack.judge_ready is False
    assert any(m.code == "cookie_name_hash_missing" for m in pack.missing_evidence)


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
