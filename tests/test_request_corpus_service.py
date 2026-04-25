"""Phase 2 — Request Corpus Service tests.

Validates RequestCorpusService: add/find/redact/extract/classify,
ResourceInstance creation, cross-role candidate search,
and integration with CampaignSummary counts.
"""
from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.campaign_service import CampaignService
from backend.services.request_corpus_service import RequestCorpusService
from backend.storage.memory_store import memory_store


def _reset_memory_store() -> None:
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()
    memory_store.campaigns.clear()
    memory_store.campaign_by_run_id.clear()
    memory_store.campaign_by_session_id.clear()
    memory_store.corpus_items.clear()
    memory_store.corpus_by_campaign.clear()
    memory_store.resource_instances.clear()
    memory_store.resources_by_campaign.clear()


def _create_campaign(target_url: str = "http://localhost:8888") -> str:
    _reset_memory_store()
    svc = CampaignService()
    campaign = svc.create_campaign(target_url=target_url)
    return campaign.campaign_id


def test_corpus_stores_successful_2xx_request() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        headers={"Content-Type": "application/json"},
        status_code=200,
        response_body={"id": 123, "make": "Toyota"},
        auth_profile="user_a",
        source="openapi_smoke",
    )
    assert item.request_id.startswith("req_")
    assert item.campaign_id == cid
    assert item.classification.value == "successful_seed"
    assert item.method == "GET"
    assert item.status_code == 200

    fetched = svc.get_request(item.request_id)
    assert fetched is not None
    assert fetched.request_id == item.request_id


def test_corpus_stores_403_as_auth_baseline() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/admin/users",
        status_code=403,
        auth_profile="user_a",
    )
    assert item.classification.value == "auth_baseline"


def test_corpus_redacts_authorization_header() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="POST",
        url="http://localhost:8888/api/login",
        headers={
            "Authorization": "Bearer secret-token-12345",
            "Content-Type": "application/json",
            "X-Api-Key": "my-key",
        },
        body={"username": "admin", "password": "supersecret"},
        status_code=200,
    )
    assert item.headers_redacted["Authorization"] == "<redacted>"
    assert item.headers_redacted["Content-Type"] == "application/json"
    assert item.headers_redacted["X-Api-Key"] == "<redacted>"
    assert item.body_redacted["password"] == "<redacted>"
    assert item.body_redacted["username"] == "admin"
    assert "Authorization" in item.sensitive_fields
    assert "password" in item.sensitive_fields


def test_corpus_extracts_object_ids() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        response_body={"id": 456, "vin": "ABC"},
    )
    assert "vehicleId" in item.extracted_ids
    assert "123" in item.extracted_ids["vehicleId"]
    assert "responseId" in item.extracted_ids
    assert "456" in item.extracted_ids["responseId"]


def test_corpus_finds_cross_role_candidates() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()

    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
        operation_id="getVehicle",
    )
    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
        operation_id="getVehicle",
    )

    candidates = svc.find_cross_role_candidates(cid)
    assert len(candidates) >= 1
    c = candidates[0]
    assert set([c["role_a"], c["role_b"]]) == {"user_a", "user_b"}
    assert c["confidence"] >= 0.9
    assert "123" in c["overlapping_ids"]


def test_cross_role_candidates_require_overlapping_ids() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()

    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
        operation_id="getVehicle",
    )
    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/456",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
        operation_id="getVehicle",
    )
    assert svc.find_cross_role_candidates(cid) == []

    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
        operation_id="getVehicle",
    )
    candidates = svc.find_cross_role_candidates(cid)
    assert candidates
    assert "123" in candidates[0]["overlapping_ids"]


def test_corpus_stores_5xx_as_server_error_candidate() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="POST",
        url="http://localhost:8888/api/crash",
        status_code=500,
    )
    assert item.classification.value == "server_error_candidate"


def test_corpus_add_from_manual_request_round_trip() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_from_manual_request(
        campaign_id=cid,
        method="PUT",
        url="http://localhost:8888/api/v2/order/42",
        path_template="/api/v2/order/{orderId}",
        headers={"Content-Type": "application/json"},
        body={"quantity": 5},
        status_code=200,
        response_body={"id": 42, "status": "updated"},
        auth_profile="user_a",
        source="manual",
    )
    assert item.request_id.startswith("req_")

    fetched = svc.get_request(item.request_id)
    assert fetched is not None
    assert fetched.method == "PUT"
    assert fetched.url == "http://localhost:8888/api/v2/order/42"
    assert fetched.auth_profile == "user_a"


def test_corpus_list_by_campaign_returns_only_campaign_items() -> None:
    _reset_memory_store()
    csvc = CampaignService()
    c1 = csvc.create_campaign(target_url="http://host1:8888")
    c2 = csvc.create_campaign(target_url="http://host2:9999")
    cid1, cid2 = c1.campaign_id, c2.campaign_id

    svc = RequestCorpusService()
    svc.add_exchange(campaign_id=cid1, method="GET", url="http://host1:8888/a", status_code=200)
    svc.add_exchange(campaign_id=cid1, method="GET", url="http://host1:8888/b", status_code=200)
    svc.add_exchange(campaign_id=cid2, method="GET", url="http://host2:9999/c", status_code=200)

    items1 = svc.list_by_campaign(cid1)
    items2 = svc.list_by_campaign(cid2)
    assert len(items1) == 2
    assert len(items2) == 1
    assert all(i.campaign_id == cid1 for i in items1)
    assert all(i.campaign_id == cid2 for i in items2)


def test_corpus_find_replay_seed_returns_best_match() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()

    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    svc.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicle/456",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
    )
    svc.add_exchange(
        campaign_id=cid,
        method="POST",
        url="http://localhost:8888/api/v2/vehicle",
        path_template="/api/v2/vehicle",
        status_code=201,
        auth_profile="user_a",
    )

    seed = svc.find_replay_seed(cid, "GET", "/api/v2/vehicle/{vehicleId}", "user_a")
    assert seed is not None
    assert seed.auth_profile == "user_a"
    assert seed.method == "GET"

    seed_b = svc.find_replay_seed(cid, "GET", "/api/v2/vehicle/{vehicleId}", "user_b")
    assert seed_b is not None
    assert seed_b.auth_profile == "user_b"

    seed_any = svc.find_replay_seed(cid, "GET", "/api/v2/vehicle/{vehicleId}")
    assert seed_any is not None

    no_seed = svc.find_replay_seed(cid, "DELETE", "/api/v2/vehicle/{vehicleId}")
    assert no_seed is None


def test_corpus_campaign_summary_includes_corpus_count() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()

    svc.add_exchange(campaign_id=cid, method="GET", url="http://localhost:8888/a", status_code=200)
    svc.add_exchange(campaign_id=cid, method="GET", url="http://localhost:8888/b", status_code=200)
    svc.add_exchange(campaign_id=cid, method="GET", url="http://localhost:8888/c", status_code=403)

    csvc = CampaignService()
    summary = csvc.get_summary(cid)
    assert summary is not None
    assert summary.counts.corpus_items == 3


def test_resource_instances_are_campaign_scoped() -> None:
    _reset_memory_store()
    csvc = CampaignService()
    cid1 = csvc.create_campaign(target_url="http://host1:8888").campaign_id
    cid2 = csvc.create_campaign(target_url="http://host2:9999").campaign_id
    svc = RequestCorpusService()

    svc.add_exchange(
        campaign_id=cid1,
        method="GET",
        url="http://host1:8888/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    svc.add_exchange(
        campaign_id=cid2,
        method="GET",
        url="http://host2:9999/api/v2/vehicle/123",
        path_template="/api/v2/vehicle/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
    )

    resources_c1 = memory_store.list_resources_by_campaign(cid1)
    resources_c2 = memory_store.list_resources_by_campaign(cid2)
    assert len(resources_c1) == 1
    assert len(resources_c2) == 1
    assert resources_c1[0]["resource_instance_id"] != resources_c2[0]["resource_instance_id"]
    assert resources_c1[0]["observed_by_roles"] == ["user_a"]
    assert resources_c2[0]["observed_by_roles"] == ["user_b"]


def test_classification_matrix_404_409_422_429() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()

    i404 = svc.add_exchange(campaign_id=cid, method="GET", url="http://localhost:8888/r/1", status_code=404)
    i409 = svc.add_exchange(campaign_id=cid, method="POST", url="http://localhost:8888/r", status_code=409)
    i422 = svc.add_exchange(campaign_id=cid, method="POST", url="http://localhost:8888/r", status_code=422)
    i429 = svc.add_exchange(campaign_id=cid, method="GET", url="http://localhost:8888/r", status_code=429)

    assert i404.classification.value == "negative_object"
    assert i409.classification.value == "validation_signal"
    assert i422.classification.value == "validation_signal"
    assert i429.classification.value == "rate_limit_signal"


def test_recursive_redaction_for_list_and_response_body() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    item = svc.add_exchange(
        campaign_id=cid,
        method="POST",
        url="http://localhost:8888/api/v2/auth",
        status_code=200,
        body={
            "items": [
                {"token": "t1"},
                {"nested": {"password": "p1", "ok": "v"}},
            ],
            "secret": "s1",
        },
        response_body={
            "users": [
                {"access_token": "a1"},
                {"nested": {"client_secret": "c1", "safe": True}},
            ]
        },
    )

    assert item.body_redacted["items"][0]["token"] == "<redacted>"
    assert item.body_redacted["items"][1]["nested"]["password"] == "<redacted>"
    assert item.body_redacted["items"][1]["nested"]["ok"] == "v"
    assert item.body_redacted["secret"] == "<redacted>"
    assert item.response_body_redacted["users"][0]["access_token"] == "<redacted>"
    assert item.response_body_redacted["users"][1]["nested"]["client_secret"] == "<redacted>"
    assert item.response_body_redacted["users"][1]["nested"]["safe"] is True


def test_corpus_routes_add_items_seeds_cross_role_candidates() -> None:
    _reset_memory_store()
    campaign_id = CampaignService().create_campaign(target_url="http://localhost:8888").campaign_id
    client = TestClient(app)

    add_a = client.post(
        "/v1/corpus/add",
        json={
            "campaign_id": campaign_id,
            "method": "GET",
            "url": "http://localhost:8888/api/v2/vehicle/123",
            "path_template": "/api/v2/vehicle/{vehicleId}",
            "auth_profile": "user_a",
            "operation_id": "getVehicle",
            "status_code": 200,
        },
    )
    add_b = client.post(
        "/v1/corpus/add",
        json={
            "campaign_id": campaign_id,
            "method": "GET",
            "url": "http://localhost:8888/api/v2/vehicle/123",
            "path_template": "/api/v2/vehicle/{vehicleId}",
            "auth_profile": "user_b",
            "operation_id": "getVehicle",
            "status_code": 200,
        },
    )

    assert add_a.status_code == 201
    assert add_b.status_code == 201

    items = client.get(f"/v1/corpus/{campaign_id}/items")
    seeds = client.get(f"/v1/corpus/{campaign_id}/seeds")
    cross = client.get(f"/v1/corpus/{campaign_id}/cross-role-candidates")

    assert items.status_code == 200
    assert seeds.status_code == 200
    assert cross.status_code == 200
    assert len(items.json()) == 2
    assert len(seeds.json()) == 2
    assert cross.json()


def test_add_from_tool_result_skips_statusless_reproduction() -> None:
    cid = _create_campaign()
    svc = RequestCorpusService()
    tool_result = SimpleNamespace(
        tool_name="custom_request_executor",
        tool_run_id="toolrun_123",
        reproduction=SimpleNamespace(
            method="GET",
            url="http://localhost:8888/api/v2/vehicle/123",
            headers={"Authorization": "Bearer X"},
            body={"token": "x"},
        ),
    )

    added = svc.add_from_tool_result(cid, tool_result, role="user_a")
    assert added == []
    assert svc.list_by_campaign(cid) == []
