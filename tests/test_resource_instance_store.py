from __future__ import annotations

import json

from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.runtime_object_id_secrets.clear()
    memory_store.runtime_resource_instances.clear()
    memory_store.runtime_resource_instances_by_campaign.clear()


def test_resource_instance_store_keeps_raw_id_internal_and_sanitizes_public_output() -> None:
    _reset_store()
    store = ResourceInstanceStore()
    instance = store.create_resource_instance(
        campaign_id="cmp_store",
        resource_type="vehicle",
        object_id_field="vehicleid",
        raw_object_id="veh-12345",
        source_operation_id="op_GET_/vehicles",
        source_path="/api/vehicles",
        source_auth_profile_id="authprof_owner_1",
        source_role_hint="owner",
        confidence="high",
        created_by="resource_instance_extractor",
        metadata={"source_observation_id": "obs_1", "note": "safe"},
    )
    assert store.get_raw_object_id(instance.object_id_ref) == "veh-12345"
    rows = store.list_resource_instances("cmp_store")
    assert len(rows) == 1
    assert rows[0]["object_ref_id"] == instance.object_ref_id
    assert rows[0]["object_id_ref"] == instance.object_id_ref
    blob = json.dumps(rows[0], sort_keys=True).lower()
    assert "veh-12345" not in blob
    for bad in ("authorization", "cookie", "set-cookie", "token=", "bearer "):
        assert bad not in blob
