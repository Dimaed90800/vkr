from __future__ import annotations

import json

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.bola_object_pair_builder_adapter import BolaObjectPairBuilderAdapter
from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns",
        "graphs_by_campaign",
        "runtime_object_id_secrets",
        "runtime_resource_instances",
        "runtime_resource_instances_by_campaign",
        "runtime_bola_object_pairs",
        "runtime_bola_object_pairs_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_bola_pair",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _store_graph(ops: list[Operation]) -> None:
    graph = ApiGraph(campaign_id="cmp_bola_pair", operations=ops)
    memory_store.store_graph_for_campaign("cmp_bola_pair", graph.model_dump(mode="json"))


def _cmd(**overrides) -> WorkerCommand:
    inputs = {
        "validation_mode": "bola_object_pair_building",
        "owner_auth_profile_id": "authprof_owner_1",
        "attacker_auth_profile_id": "authprof_attacker_1",
        "max_object_pairs": 10,
    }
    inputs.update(overrides)
    return WorkerCommand(
        campaign_id="cmp_bola_pair",
        worker_class="access_control",
        strategy="build_bola_object_pairs",
        tool_name="bola_object_pair_builder",
        inputs=inputs,
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )


def _add_resource(resource_type: str, field: str, raw: str) -> None:
    ResourceInstanceStore().create_resource_instance(
        campaign_id="cmp_bola_pair",
        resource_type=resource_type,
        object_id_field=field,
        raw_object_id=raw,
        source_operation_id="op_GET_/seed",
        source_path="/seed",
        source_auth_profile_id="authprof_owner_1",
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
    )


def test_vehicle_ref_and_vehicle_id_path_builds_high_confidence_pair() -> None:
    _reset_store()
    campaign = _campaign()
    _add_resource("vehicle", "vehicleId", "veh-1")
    _store_graph([
        Operation(
            operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
            method="GET",
            path_template="/api/v1/vehicles/{vehicleId}",
            path_params=["vehicleId"],
            auth_required=True,
            resource_type="vehicle",
            tags=["vehicles"],
        )
    ])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_1")
    assert res.status == "finished"
    det = res.observations[0].details
    assert det["object_pairs_count"] == 1
    assert det["object_pairs"][0]["confidence"] == "high"
    blob = json.dumps(res.model_dump(mode="json"), sort_keys=True).lower()
    assert "veh-1" not in blob


def test_post_ref_and_postid_path_builds_pair() -> None:
    _reset_store()
    campaign = _campaign()
    _add_resource("post", "postId", "post-1")
    _store_graph([
        Operation(
            operation_id="op_GET_/api/v1/posts/{postId}",
            method="GET",
            path_template="/api/v1/posts/{postId}",
            path_params=["postId"],
            auth_required=True,
            resource_type="post",
            tags=["posts"],
        )
    ])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_2")
    assert res.observations[0].details["object_pairs_count"] == 1
    assert res.observations[0].details["object_pairs"][0]["resource_type"] == "post"


def test_generic_id_with_matching_alias_produces_medium_pair() -> None:
    _reset_store()
    campaign = _campaign()
    _add_resource("vehicle", "vehicleId", "veh-2")
    _store_graph([
        Operation(
            operation_id="op_GET_/api/cars/{id}",
            method="GET",
            path_template="/api/cars/{id}",
            path_params=["id"],
            auth_required=True,
            resource_type="",
            tags=["cars"],
        )
    ])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_3")
    det = res.observations[0].details
    assert det["object_pairs_count"] == 1
    assert det["object_pairs"][0]["confidence"] in {"medium", "high"}


def test_no_matching_operation_returns_reason_code() -> None:
    _reset_store()
    campaign = _campaign()
    _add_resource("vehicle", "vehicleId", "veh-3")
    _store_graph([
        Operation(
            operation_id="op_POST_/api/v1/vehicles",
            method="POST",
            path_template="/api/v1/vehicles",
            path_params=[],
            auth_required=True,
            resource_type="vehicle",
            tags=["vehicles"],
        )
    ])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_4")
    det = res.observations[0].details
    assert det["object_pairs_count"] == 0
    assert "no_matching_path_param_operation" in det["reason_codes"]


def test_no_resource_refs_returns_no_resource_instances_available() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph([])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_5")
    det = res.observations[0].details
    assert det["object_pairs_count"] == 0
    assert "no_resource_instances_available" in det["reason_codes"]


def test_adapter_output_has_no_raw_secret_leakage() -> None:
    _reset_store()
    campaign = _campaign()
    _add_resource("vehicle", "vehicleId", "veh-raw-secret")
    _store_graph([
        Operation(
            operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
            method="GET",
            path_template="/api/v1/vehicles/{vehicleId}",
            path_params=["vehicleId"],
            auth_required=True,
            resource_type="vehicle",
            tags=["vehicles"],
        )
    ])
    res = BolaObjectPairBuilderAdapter().execute(_cmd(), campaign, "toolrun_bola_pair_6")
    blob = json.dumps(res.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("veh-raw-secret", "authorization", "cookie", "password", "token", "raw_body"):
        assert bad not in blob
