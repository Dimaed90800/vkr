from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.bola_replay_probe_adapter import BolaReplayProbeAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.bola_object_pair_store import BolaObjectPairStore
from backend.services.http.safe_http_client import SafeHttpClient
from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns",
        "auth_profiles",
        "auth_profiles_by_campaign",
        "runtime_token_secrets",
        "runtime_object_id_secrets",
        "runtime_resource_instances",
        "runtime_resource_instances_by_campaign",
        "runtime_bola_object_pairs",
        "runtime_bola_object_pairs_by_campaign",
        "corpus_items",
        "corpus_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_bola_replay",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _setup_pair(*, method: str = "GET", raw_object_id: str = "post/123") -> tuple[str, str, str]:
    owner = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_bola_replay",
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )
    attacker = AuthProfileStore().create_auth_profile(
        campaign_id="cmp_bola_replay",
        role_hint="attacker",
        user_label="attacker",
        auth_type="bearer",
        raw_token="attacker-token",
        created_by="test",
    )
    instance = ResourceInstanceStore().create_resource_instance(
        campaign_id="cmp_bola_replay",
        resource_type="post",
        object_id_field="postId",
        raw_object_id=raw_object_id,
        source_operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        source_path="/community/api/v2/community/posts/{postId}",
        source_auth_profile_id=owner.auth_profile_id,
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
    )
    pair = BolaObjectPairStore().create_bola_object_pair(
        campaign_id="cmp_bola_replay",
        resource_type="post",
        object_ref_id=instance.object_ref_id,
        object_id_ref=instance.object_id_ref,
        owner_auth_profile_id=owner.auth_profile_id,
        attacker_auth_profile_id=attacker.auth_profile_id,
        target_operation_id="op_GET_/community/api/v2/community/posts/{postId}",
        target_path_template="/community/api/v2/community/posts/{postId}",
        target_method=method,
        path_param_name="postId",
        confidence="high",
        created_by="bola_object_pair_builder",
        reason_codes=["path_param_resource_match"],
        metadata={"baseline_probability_score": 73.0, "baseline_probability_reasons": ["method_get_preferred"]},
    )
    return pair.object_pair_id, owner.auth_profile_id, attacker.auth_profile_id


def _cmd(object_pair_id: str) -> WorkerCommand:
    return WorkerCommand(
        campaign_id="cmp_bola_replay",
        worker_class="access_control",
        strategy="replay_bola_object_pair",
        tool_name="bola_replay_probe",
        inputs={
            "validation_mode": "bola_replay",
            "object_pair_id": object_pair_id,
            "max_requests": 2,
        },
        budget=CommandBudget(max_requests=2, timeout_sec=15),
    )


def test_owner_baseline_200_then_attacker_200_emits_possible_bola_without_raw_leakage() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, attacker = _setup_pair()

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("authorization") or "")
        if len(calls) == 1:
            assert request.headers.get("authorization") == "Bearer owner-token"
            assert str(request.url).endswith("/post%2F123")
            return httpx.Response(200, json={"id": "post/123", "title": "hello"})
        assert request.headers.get("authorization") == "Bearer attacker-token"
        assert str(request.url).endswith("/post%2F123")
        return httpx.Response(200, json={"id": "post/123", "title": "hello"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_1")
    assert result.status == "finished"
    assert result.observations[0].observation_type == "bola_replay_result"
    det = result.observations[0].details
    assert det["result"] == "attacker_access_granted"
    assert det["replay_classification"] == "possible_bola"
    assert det["owner_baseline_valid"] is True
    assert det["owner_status_code"] == 200
    assert det["attacker_status_code"] == 200
    assert det["access_granted"] is True
    assert det["evidence_strength"] == "high"
    assert len(calls) == 2
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("post/123", "post%2f123", "owner-token", "attacker-token", "authorization", "cookie", "password", "response_body"):
        assert bad not in blob


def test_owner_200_then_attacker_403_marks_attacker_access_denied() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="abc")

    calls: list[str] = []

    def handler(_: httpx.Request) -> httpx.Response:
        calls.append("x")
        if len(calls) == 1:
            return httpx.Response(200, json={"id": "abc"})
        return httpx.Response(403, json={"error": "forbidden"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_2")
    det = result.observations[0].details
    assert det["result"] == "attacker_access_denied"
    assert det["access_granted"] is False
    assert det["owner_baseline_valid"] is True
    assert det["replay_classification"] == "access_denied"
    assert len(calls) == 2


def test_owner_200_then_attacker_404_marks_access_denied_or_not_found() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="abc")

    calls: list[str] = []

    def handler(_: httpx.Request) -> httpx.Response:
        calls.append("x")
        if len(calls) == 1:
            return httpx.Response(200, json={"id": "abc"})
        return httpx.Response(404, json={"error": "missing"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_2b")
    det = result.observations[0].details
    assert det["result"] == "attacker_access_denied_or_not_found"
    assert det["access_granted"] is False
    assert det["owner_baseline_valid"] is True
    assert det["replay_classification"] == "access_denied_or_not_found"
    assert len(calls) == 2


def test_owner_non_2xx_marks_invalid_object_pair_and_skips_attacker() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="abc")

    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.headers.get("authorization") or "")
        return httpx.Response(400, json={"error": "bad"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_2c")
    det = result.observations[0].details
    assert det["result"] == "invalid_object_pair"
    assert det["replay_classification"] == "invalid_object_pair"
    assert det["owner_baseline_valid"] is False
    assert det["attacker_result"] == "skipped"
    assert len(calls) == 1


def test_missing_raw_object_id_returns_finished_diagnostic() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="gone")
    pair = memory_store.get_runtime_bola_object_pair(object_pair_id)
    assert pair is not None
    memory_store.runtime_object_id_secrets.clear()

    result = BolaReplayProbeAdapter().execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_3")
    assert result.status == "finished"
    det = result.observations[0].details
    assert det["result"] == "error"
    assert "raw_object_id_unavailable" in det["reason_codes"]


def test_non_get_pair_returns_finished_diagnostic_for_mvp() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(method="DELETE")
    result = BolaReplayProbeAdapter().execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_4")
    det = result.observations[0].details
    assert det["result"] == "error"
    assert "target_method_not_supported_mvp" in det["reason_codes"]


def test_path_substitution_url_encodes_id_and_observation_does_not_expose_raw_id() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="a/b c")

    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(404, json={"error": "missing"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_5")
    assert captured["url"].endswith("/a%2Fb%20c")
    blob = json.dumps(result.observations[0].details, sort_keys=True).lower()
    assert "a/b c" not in blob


def test_bola_replay_result_carries_baseline_probability_metadata() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="abc")

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "bad"})

    result = BolaReplayProbeAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    ).execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_meta")
    det = result.observations[0].details
    assert float(det.get("baseline_probability_score") or 0) == 73.0
    assert "method_get_preferred" in (det.get("baseline_probability_reasons") or [])


def test_blocked_pair_returns_blocked_before_replay() -> None:
    _reset_store()
    campaign = _campaign()
    object_pair_id, _owner, _attacker = _setup_pair(raw_object_id="abc")
    pair = memory_store.get_runtime_bola_object_pair(object_pair_id)
    assert isinstance(pair, dict)
    md = pair.get("metadata") if isinstance(pair.get("metadata"), dict) else {}
    md["baseline_block_reasons"] = ["object_id_field_semantic_mismatch", "path_param_semantic_mismatch"]
    pair["metadata"] = md
    memory_store.store_runtime_bola_object_pair(object_pair_id, "cmp_bola_replay", pair)

    result = BolaReplayProbeAdapter().execute(_cmd(object_pair_id), campaign, "toolrun_bola_replay_blocked")
    det = result.observations[0].details
    assert det["result"] == "blocked_before_replay"
    assert det["replay_classification"] == "blocked_pair"
    assert det["owner_status_code"] == 0
    assert det["attacker_status_code"] == 0
