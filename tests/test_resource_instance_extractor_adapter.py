from __future__ import annotations

import json

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation, ObservationType
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.resource_instance_extractor_adapter import (
    ResourceInstanceExtractorAdapter,
)
from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "artifacts", "artifacts_by_run", "observations", "observations_by_campaign",
        "observations_by_tool_run", "runtime_response_json_secrets",
        "runtime_object_id_secrets", "runtime_resource_instances",
        "runtime_resource_instances_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_resource",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def test_resource_instance_extractor_creates_object_refs_from_authenticated_json() -> None:
    _reset_store()
    campaign = _campaign()
    memory_store.store_runtime_response_json_secret(
        "toolrun_dex_auth_1",
        {"vehicleid": "veh-123", "profile": {"userId": 7}, "items": [{"order_id": "ord-9"}]},
    )
    obs = Observation(
        observation_id="obs_source_inventory",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_dex_auth_1",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "field_count": 13,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        operation_id="op_GET_/api/v1/me",
        inputs={
            "source_observation_id": obs.observation_id,
            "source_operation_id": "op_GET_/api/v1/me",
            "source_path": "/api/v1/me",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
            "validation_mode": "resource_instance_extraction",
            "max_instances": 10,
        },
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_resource_1")
    assert result.status == "finished"
    assert [o.observation_type for o in result.observations] == ["resource_instance_inventory"]
    det = result.observations[0].details
    assert det["resource_instances_count"] >= 3
    assert "vehicle" in det["resource_types"]
    assert any(row["object_id_field"] == "vehicleid" for row in det["object_refs"])
    store_rows = ResourceInstanceStore().list_resource_instances(campaign.campaign_id)
    assert len(store_rows) >= 3
    blob = json.dumps({"observation": det, "store": store_rows}, sort_keys=True).lower()
    for bad in ("veh-123", "ord-9", "\"7\"", "authorization", "cookie", "set-cookie", "token="):
        assert bad not in blob


def test_resource_instance_extractor_rejects_count_aggregate_field() -> None:
    _reset_store()
    campaign = _campaign()
    memory_store.store_runtime_response_json_secret(
        "toolrun_orders_count",
        {"count": 42},
    )
    obs = Observation(
        observation_id="obs_orders_count",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_orders_count",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/workshop/api/shop/orders/all",
            "path": "/workshop/api/shop/orders/all",
            "field_count": 1,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        operation_id=obs.details["operation_id"],
        inputs={"source_observation_id": obs.observation_id, "validation_mode": "resource_instance_extraction"},
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_resource_count")
    assert result.status == "finished"
    det = result.observations[0].details
    assert det["resource_instances_count"] == 0
    assert "aggregate_field_filtered" in det["reason_codes"]
    assert "no_resource_ids_found" in det["reason_codes"]
    assert det["aggregate_fields_filtered_count"] >= 1
    assert det["candidate_fields_count"] == 0
    assert ResourceInstanceStore().list_resource_instances(campaign.campaign_id) == []
    blob = json.dumps(det, sort_keys=True).lower()
    assert "42" not in blob


def test_resource_instance_extractor_order_id_camel_case_high() -> None:
    _reset_store()
    campaign = _campaign()
    memory_store.store_runtime_response_json_secret("toolrun_oid_camel", {"orderId": "o-camel-1"})
    obs = Observation(
        observation_id="obs_oid_camel",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_oid_camel",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/orders",
            "path": "/api/orders",
            "field_count": 1,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        operation_id="op_GET_/orders",
        inputs={"source_observation_id": obs.observation_id, "validation_mode": "resource_instance_extraction"},
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_res_camel")
    det = result.observations[0].details
    assert det["resource_instances_count"] == 1
    assert det["object_refs"][0]["object_id_field"] == "orderId"
    assert det["object_refs"][0]["confidence"] == "high"
    assert "o-camel-1" not in json.dumps(det, sort_keys=True).lower()


def test_resource_instance_extractor_order_id_high_and_generic_id_medium_in_orders_list() -> None:
    _reset_store()
    campaign = _campaign()
    memory_store.store_runtime_response_json_secret(
        "toolrun_orders_mixed",
        {"items": [{"order_id": "ord-high-1", "id": "gen-mid-1"}]},
    )
    obs = Observation(
        observation_id="obs_orders_mixed",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_orders_mixed",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/workshop/api/shop/orders/all",
            "path": "/workshop/api/shop/orders/all",
            "field_count": 2,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        operation_id=obs.details["operation_id"],
        inputs={"source_observation_id": obs.observation_id, "validation_mode": "resource_instance_extraction", "max_instances": 10},
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_resource_orders")
    assert result.status == "finished"
    det = result.observations[0].details
    assert det["resource_instances_count"] == 2
    fields = {r["object_id_field"]: r["confidence"] for r in det["object_refs"]}
    assert fields.get("order_id") == "high"
    assert fields.get("id") == "medium"
    assert "resource_ids_extracted" in det["reason_codes"]
    blob = json.dumps(det, sort_keys=True).lower()
    for bad in ("ord-high-1", "gen-mid-1", "authorization", "cookie"):
        assert bad not in blob


def test_resource_instance_extractor_denylist_amount_quantity_price_status() -> None:
    _reset_store()
    campaign = _campaign()
    memory_store.store_runtime_response_json_secret(
        "toolrun_shop_agg",
        {"amount": 10, "quantity": 2, "price": 99, "status": "ok", "order_id": "ord-only"},
    )
    obs = Observation(
        observation_id="obs_shop_agg",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_shop_agg",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/shop/item",
            "path": "/shop/item",
            "field_count": 5,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        operation_id=obs.details["operation_id"],
        inputs={"source_observation_id": obs.observation_id, "validation_mode": "resource_instance_extraction"},
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_resource_agg")
    det = result.observations[0].details
    assert det["resource_instances_count"] == 1
    assert det["object_refs"][0]["object_id_field"] == "order_id"
    assert det["aggregate_fields_filtered_count"] >= 4
    blob = json.dumps(det, sort_keys=True).lower()
    assert "ord-only" not in blob


def test_resource_instance_extractor_returns_safe_diagnostic_when_no_raw_values_available() -> None:
    _reset_store()
    campaign = _campaign()
    obs = Observation(
        observation_id="obs_source_inventory_no_raw",
        campaign_id=campaign.campaign_id,
        tool_run_id="toolrun_missing_secret",
        type=ObservationType.response_field_inventory,
        details={
            "tool_name": "data_exposure_validator",
            "operation_id": "op_GET_/api/v1/me",
            "path": "/api/v1/me",
            "field_count": 2,
            "auth_mode": "authenticated",
            "auth_profile_id": "authprof_owner_1",
            "role_hint": "owner",
        },
    )
    memory_store.store_observation(obs.observation_id, obs.campaign_id, obs.tool_run_id, obs.model_dump(mode="json"))
    cmd = WorkerCommand(
        campaign_id=campaign.campaign_id,
        worker_class="auth_context",
        strategy="extract_resource_instances",
        tool_name="resource_instance_extractor",
        inputs={
            "source_observation_id": obs.observation_id,
            "auth_profile_id": "authprof_owner_1",
            "validation_mode": "resource_instance_extraction",
        },
        budget=CommandBudget(max_requests=0, timeout_sec=15),
    )
    result = ResourceInstanceExtractorAdapter().execute(cmd, campaign, "toolrun_resource_2")
    det = result.observations[0].details
    assert det["resource_instances_count"] == 0
    assert det["reason_codes"] == ["no_raw_values_available"]
