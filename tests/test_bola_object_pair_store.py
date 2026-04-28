from __future__ import annotations

import json

from backend.services.bola_object_pair_store import BolaObjectPairStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.runtime_bola_object_pairs.clear()
    memory_store.runtime_bola_object_pairs_by_campaign.clear()


def test_bola_object_pair_store_creates_sanitized_pair_without_raw_object_id() -> None:
    _reset_store()
    store = BolaObjectPairStore()
    pair = store.create_bola_object_pair(
        campaign_id="cmp_bola_store",
        resource_type="vehicle",
        object_ref_id="objref_1",
        object_id_ref="objidref_1",
        owner_auth_profile_id="authprof_owner_1",
        attacker_auth_profile_id="authprof_attacker_1",
        target_operation_id="op_GET_/api/v1/vehicles/{vehicleId}",
        target_path_template="/api/v1/vehicles/{vehicleId}",
        target_method="GET",
        path_param_name="vehicleId",
        confidence="high",
        created_by="bola_object_pair_builder",
        reason_codes=["path_param_resource_match"],
        metadata={"raw_object_id": "veh-123", "Authorization": "Bearer secret"},
    )
    rows = store.list_bola_object_pairs("cmp_bola_store")
    assert len(rows) == 1
    assert rows[0]["object_pair_id"] == pair.object_pair_id
    assert rows[0]["object_id_ref"] == "objidref_1"
    blob = json.dumps(rows[0], sort_keys=True).lower()
    for bad in ("veh-123", "authorization", "cookie", "set-cookie", "password", "token", "raw_object_id"):
        assert bad not in blob
