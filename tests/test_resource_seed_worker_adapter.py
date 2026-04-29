from __future__ import annotations

import json

import httpx

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.resource_seed_worker_adapter import ResourceSeedWorkerAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.http.safe_http_client import SafeHttpClient
from backend.services.resource_instance_store import ResourceInstanceStore
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    for name in [
        "graphs_by_campaign",
        "campaigns",
        "auth_profiles",
        "auth_profiles_by_campaign",
        "runtime_token_secrets",
        "runtime_credential_secrets",
        "artifacts",
        "artifacts_by_run",
        "runtime_object_id_secrets",
        "runtime_resource_instances",
        "runtime_resource_instances_by_campaign",
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_seed",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _store_graph(ops: list[Operation]) -> None:
    graph = ApiGraph(campaign_id="cmp_seed", operations=ops)
    memory_store.store_graph_for_campaign("cmp_seed", graph.model_dump(mode="json"))


def _cmd(owner_auth_profile_id: str, **overrides) -> WorkerCommand:
    inputs = {
        "validation_mode": "resource_seed",
        "owner_auth_profile_id": owner_auth_profile_id,
        "max_seed_attempts": 1,
        "max_followup_requests": 1,
    }
    inputs.update(overrides)
    return WorkerCommand(
        campaign_id="cmp_seed",
        worker_class="auth_context",
        strategy="seed_resource_instance",
        tool_name="resource_seed_worker",
        operation_id="",
        inputs=inputs,
        budget=CommandBudget(max_requests=2, timeout_sec=15),
    )


def test_seed_worker_2xx_with_order_id_creates_resource_instance_ref() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        raw_credentials={"email": "o1@e.io"},
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/orders",
            method="POST",
            path_template="/api/orders",
            body_fields=["name"],
            response_fields=["order_id"],
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_POST_/identity/api/auth/login",
            method="POST",
            path_template="/identity/api/auth/login",
            body_fields=["email", "password"],
            auth_required=False,
            sources=["openapi"],
        ),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/orders":
            return httpx.Response(201, json={"order_id": "ord-1"})
        raise AssertionError("unexpected request")

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id), campaign, "toolrun_seed_1")
    assert result.status == "finished"
    det = result.observations[0].details
    assert det["seed_status"] == "seeded"
    assert det["object_refs_created_count"] == 1
    assert det["object_refs"][0]["resource_type"] == "order"
    assert det["object_refs"][0]["object_id_field"] in {"order_id", "orderId", "orderID"}
    store_rows = ResourceInstanceStore().list_resource_instances(campaign.campaign_id)
    assert len(store_rows) == 1
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("ord-1", "owner-token", "authorization", "cookie", "set-cookie", "password", "request_body", "response_body"):
        assert bad not in blob


def test_seed_worker_followup_get_list_extracts_generic_id_in_list_item_medium() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/orders",
            method="POST",
            path_template="/api/orders",
            body_fields=["name"],
            response_fields=[],
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_GET_/api/orders",
            method="GET",
            path_template="/api/orders",
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/orders" and request.method == "POST":
            return httpx.Response(201, json={"status": "ok"})
        if request.url.path == "/api/orders" and request.method == "GET":
            return httpx.Response(200, json={"items": [{"id": "ord-2"}]})
        raise AssertionError("unexpected request")

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id), campaign, "toolrun_seed_2")
    det = result.observations[0].details
    assert det["seed_status"] == "seeded"
    assert det["followup_operation_id"] == "op_GET_/api/orders"
    assert det["object_refs_created_count"] == 1
    assert det["object_refs"][0]["confidence"] in {"medium", "high"}
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    assert "ord-2" not in blob


def test_seed_worker_non_2xx_is_finished_creation_non_2xx_not_failed() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/orders",
            method="POST",
            path_template="/api/orders",
            body_fields=["name"],
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
    ])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(409, json={"error": "conflict", "token": "should-not-leak"})

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id), campaign, "toolrun_seed_3")
    assert result.status == "finished"
    det = result.observations[0].details
    assert det["seed_status"] == "creation_non_2xx"
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("should-not-leak", "authorization", "cookie", "set-cookie"):
        assert bad not in blob


def test_seed_worker_no_id_returns_no_object_id_found() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/orders",
            method="POST",
            path_template="/api/orders",
            body_fields=["name"],
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
    ])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"status": "created"})

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id, max_followup_requests=0), campaign, "toolrun_seed_4")
    det = result.observations[0].details
    assert det["seed_status"] == "no_object_id_found"
    assert det["object_refs_created_count"] == 0


def test_resource_seed_authorid_not_typed_as_post_id() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/posts",
            method="POST",
            path_template="/api/posts",
            body_fields=["title"],
            auth_required=True,
            resource_type="post",
            sources=["openapi"],
        ),
    ])

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"authorid": "user-123"})

    adapter = ResourceSeedWorkerAdapter(http_client=SafeHttpClient(transport=httpx.MockTransport(handler)))
    result = adapter.execute(_cmd(profile.auth_profile_id), campaign, "toolrun_seed_author")
    det = result.observations[0].details
    assert det["seed_status"] == "seeded"
    assert det["object_refs_created_count"] == 1
    assert det["object_refs"][0]["semantic_id_kind"] == "author_id"
    assert det["object_refs"][0]["resource_type"] != "post"


def test_seed_worker_excludes_auth_admin_upload_payment_and_urlish_body_fields() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/identity/api/auth/login",
            method="POST",
            path_template="/identity/api/auth/login",
            body_fields=["email", "password"],
            auth_required=False,
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_POST_/api/admin/create",
            method="POST",
            path_template="/api/admin/create",
            body_fields=["name"],
            auth_required=True,
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_POST_/api/upload",
            method="POST",
            path_template="/api/upload",
            body_fields=["file"],
            auth_required=True,
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_POST_/api/orders",
            method="POST",
            path_template="/api/orders",
            body_fields=["callback_url"],
            auth_required=True,
            resource_type="order",
            sources=["openapi"],
        ),
    ])

    def handler(_: httpx.Request) -> httpx.Response:
        raise AssertionError("should not call HTTP when no seedable operation")

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id), campaign, "toolrun_seed_5")
    det = result.observations[0].details
    assert det["seed_status"] == "no_seedable_operation"


def test_seed_worker_multiple_attempts_bounded_and_can_seed_second_operation() -> None:
    _reset_store()
    campaign = _campaign()
    profile = AuthProfileStore().create_auth_profile(
        campaign_id=campaign.campaign_id,
        role_hint="owner",
        user_label="owner_user",
        auth_type="bearer",
        raw_token="owner-token",
        created_by="test_account_materializer",
        metadata={},
    )
    _store_graph([
        Operation(
            operation_id="op_POST_/api/posts",
            method="POST",
            path_template="/api/posts",
            body_fields=["title"],
            auth_required=True,
            resource_type="post",
            sources=["openapi"],
        ),
        Operation(
            operation_id="op_POST_/identity/api/v2/vehicle/add",
            method="POST",
            path_template="/identity/api/v2/vehicle/add",
            body_fields=["name"],
            auth_required=True,
            resource_type="vehicle",
            response_fields=["vehicleId"],
            sources=["openapi"],
        ),
    ])

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/posts":
            return httpx.Response(400, json={"error": "bad request"})
        if request.url.path == "/identity/api/v2/vehicle/add":
            return httpx.Response(201, json={"vehicleId": "veh-42"})
        raise AssertionError("unexpected request")

    adapter = ResourceSeedWorkerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_cmd(profile.auth_profile_id, max_seed_attempts=3), campaign, "toolrun_seed_6")
    det = result.observations[0].details
    assert det["seed_status"] == "seeded"
    assert det["resource_seed_attempts_count"] >= 2
    assert det["resource_seed_failed_count"] >= 1
    assert 1 <= det["http_calls_count"] <= 3
    assert det["object_refs_created_count"] >= 1
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    assert "veh-42" not in blob
