from __future__ import annotations

import json

import httpx

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.targeted_object_harvester_adapter import TargetedObjectHarvesterAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.http.safe_http_client import SafeHttpClient
from backend.storage.memory_store import memory_store


def _reset() -> None:
    for name in [
        "campaigns",
        "graphs_by_campaign",
        "auth_profiles",
        "auth_profiles_by_campaign",
        "runtime_token_secrets",
        "runtime_resource_instances",
        "runtime_resource_instances_by_campaign",
        "runtime_object_id_secrets",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    c = Campaign(
        campaign_id="cmp_toh",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=120),
    )
    memory_store.store_campaign(c.campaign_id, c.model_dump(mode="json"))
    return c


def _cmd(auth_profile_id: str = "authprof_owner") -> WorkerCommand:
    return WorkerCommand(
        campaign_id="cmp_toh",
        worker_class="access_control",
        strategy="targeted_object_harvest",
        tool_name="targeted_object_harvester",
        inputs={
            "validation_mode": "targeted_object_harvest",
            "target_url": "http://target.local",
            "auth_profile_id": auth_profile_id,
            "role_hint": "owner",
            "max_requests": 10,
            "harvest_policy": "safe_get_only",
            "candidate_resource_types": ["post", "vehicle", "video", "order"],
        },
        budget=CommandBudget(max_requests=10, timeout_sec=20),
    )


def _store_graph(ops: list[Operation]) -> None:
    memory_store.store_graph_for_campaign("cmp_toh", ApiGraph(campaign_id="cmp_toh", operations=ops).model_dump(mode="json"))


def _owner_profile(campaign: Campaign) -> str:
    p = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test",
    )
    return p.auth_profile_id


def test_extracts_post_id_from_posts_array() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/posts/recent", method="GET", path_template="/posts/recent", auth_required=True)])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"posts": [{"id": "post-1"}]})

    res = TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_1")
    det = res.observations[0].details
    assert det["object_refs_created_count"] >= 1
    assert det["targeted_post_id_count"] >= 1


def test_extracts_vehicle_id_from_posts_author_vehicleid() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/posts/recent", method="GET", path_template="/posts/recent", auth_required=True)])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"posts": [{"author": {"vehicleid": "veh-1"}}]})

    res = TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_2")
    det = res.observations[0].details
    assert det["targeted_vehicle_id_count"] >= 1


def test_does_not_treat_author_id_as_post_id() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/posts/recent", method="GET", path_template="/posts/recent", auth_required=True)])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"posts": [{"author": {"id": "user-1"}}]})

    res = TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_3")
    det = res.observations[0].details
    assert det["targeted_post_id_count"] == 0


def test_emits_safe_object_refs_without_raw_ids() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/orders/all", method="GET", path_template="/orders/all", auth_required=True)])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"orders": [{"id": "ord-raw-1"}]})

    res = TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_4")
    blob = json.dumps(res.model_dump(mode="json"), sort_keys=True).lower()
    assert "ord-raw-1" not in blob


def test_only_safe_get_operations_used() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([
        Operation(operation_id="op_POST_/orders", method="POST", path_template="/orders", auth_required=True),
        Operation(operation_id="op_GET_/orders/all", method="GET", path_template="/orders/all", auth_required=True),
    ])
    calls: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(req.method.upper())
        return httpx.Response(200, json={"orders": [{"id": "ord-1"}]})

    TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_5")
    assert calls and all(m == "GET" for m in calls)


def test_returns_no_refs_when_no_safe_json_list_endpoint() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/health", method="GET", path_template="/health", auth_required=False)])
    res = TargetedObjectHarvesterAdapter().execute(_cmd(auth_id), c, "toolrun_toh_6")
    det = res.observations[0].details
    assert det["object_refs_created_count"] == 0
    assert "no_safe_get_operations" in (det.get("reason_codes") or []) or "no_typed_object_refs_found" in (det.get("reason_codes") or [])


def test_owner_evidence_true_for_owner_2xx() -> None:
    _reset()
    c = _campaign()
    auth_id = _owner_profile(c)
    _store_graph([Operation(operation_id="op_GET_/videos", method="GET", path_template="/videos", auth_required=True)])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"videos": [{"video_id": "v-1"}]})

    res = TargetedObjectHarvesterAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler))).execute(_cmd(auth_id), c, "toolrun_toh_7")
    det = res.observations[0].details
    assert det["object_refs_created_count"] >= 1
    row = det["object_refs"][0]
    assert row["owner_evidence"] is True
    assert row["source_status_code"] == 200

