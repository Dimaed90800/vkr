"""Phase 3 — API Graph / Dependency Graph service tests.

Validates ApiGraphService:
- build_from_openapi (operations, params, edges, OWASP candidates)
- ingest_corpus (observed_*, examples, cross-role, runtime-only ops)
- dependency edge confidence upgrade from corpus seeds
- summary_for_planner shape
- campaign isolation
- HTTP routes

Phase 3 explicitly does not create confirmed findings, observations,
or evidence packs. Tests assert that, too.
"""
from __future__ import annotations

import json

from fastapi.testclient import TestClient

from backend.main import app
from backend.services.api_graph_service import ApiGraphService
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
    memory_store.graphs_by_campaign.clear()


def _create_campaign(target_url: str = "http://localhost:8888") -> str:
    svc = CampaignService()
    campaign = svc.create_campaign(target_url=target_url)
    return campaign.campaign_id


def _fresh_client() -> TestClient:
    _reset_memory_store()
    return TestClient(app)


SAMPLE_SPEC = {
    "openapi": "3.0.0",
    "info": {"title": "Test API", "version": "1.0.0"},
    "paths": {
        "/api/v2/vehicles": {
            "get": {
                "operationId": "listVehicles",
                "tags": ["vehicle"],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "array",
                                    "items": {"$ref": "#/components/schemas/Vehicle"},
                                }
                            }
                        },
                    }
                },
            },
            "post": {
                "operationId": "createVehicle",
                "tags": ["vehicle"],
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Vehicle"}
                        }
                    }
                },
                "responses": {
                    "200": {
                        "description": "created",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Vehicle"}
                            }
                        },
                    }
                },
            },
        },
        "/api/v2/vehicles/{vehicleId}": {
            "get": {
                "operationId": "getVehicle",
                "tags": ["vehicle"],
                "security": [{"bearerAuth": []}],
                "parameters": [
                    {
                        "name": "vehicleId",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {
                    "200": {
                        "description": "ok",
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Vehicle"}
                            }
                        },
                    }
                },
            }
        },
    },
    "components": {
        "schemas": {
            "Vehicle": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "vin": {"type": "string"},
                },
            }
        },
        "securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}},
    },
}

SAMPLE_SPEC_TEXT = json.dumps(SAMPLE_SPEC)


# ---------------------------------------------------------------------
# OpenAPI build tests
# ---------------------------------------------------------------------


def test_graph_build_creates_operation_per_openapi_path() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    op_ids = sorted(op.operation_id for op in graph.operations)
    assert op_ids == sorted(
        [
            "op_GET_/api/v2/vehicles",
            "op_POST_/api/v2/vehicles",
            "op_GET_/api/v2/vehicles/{vehicleId}",
        ]
    )


def test_graph_build_infers_resource_type_from_path() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    by_id = {op.operation_id: op for op in graph.operations}
    assert by_id["op_GET_/api/v2/vehicles/{vehicleId}"].resource_type == "vehicle"
    assert by_id["op_POST_/api/v2/vehicles"].resource_type == "vehicle"


def test_graph_build_marks_auth_required_from_security() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    by_id = {op.operation_id: op for op in graph.operations}
    assert by_id["op_GET_/api/v2/vehicles/{vehicleId}"].auth_required is True
    assert "bearerAuth" in by_id["op_GET_/api/v2/vehicles/{vehicleId}"].security
    assert by_id["op_GET_/api/v2/vehicles"].auth_required is False


def test_graph_build_creates_has_param_edges() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    has_param_edges = [e for e in graph.edges if e.type == "HAS_PARAM"]
    targets = {e.to_node for e in has_param_edges}
    assert "param:op_GET_/api/v2/vehicles/{vehicleId}:path:vehicleId" in targets
    assert "param:op_POST_/api/v2/vehicles:body:id" in targets
    assert "param:op_POST_/api/v2/vehicles:body:vin" in targets


def test_graph_build_infers_consumes_for_object_id_path_params() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    consumes = [
        e for e in graph.edges
        if e.type == "CONSUMES"
        and e.from_node == "op_GET_/api/v2/vehicles/{vehicleId}"
    ]
    assert any(e.to_node == "restype:vehicle" for e in consumes)


def test_graph_build_infers_produces_for_post_returning_id() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    produces = [
        e for e in graph.edges
        if e.type == "PRODUCES" and e.from_node == "op_POST_/api/v2/vehicles"
    ]
    assert any(e.to_node == "restype:vehicle" for e in produces)


def test_graph_build_marks_owasp_bola_candidate_for_auth_required_object_id() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    by_id = {op.operation_id: op for op in graph.operations}
    target = by_id["op_GET_/api/v2/vehicles/{vehicleId}"]
    assert "object_id_in_path" in target.risk_hints
    assert "API1_BOLA" in target.owasp_candidates


def test_graph_build_is_idempotent_on_repeat_call() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    svc = ApiGraphService()
    g1 = svc.build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    g2 = svc.build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    assert len(g1.operations) == len(g2.operations) == 3
    assert {op.operation_id for op in g1.operations} == {
        op.operation_id for op in g2.operations
    }
    e1_types = sorted(e.type for e in g1.edges)
    e2_types = sorted(e.type for e in g2.edges)
    assert e1_types == e2_types


# ---------------------------------------------------------------------
# Corpus enrichment tests
# ---------------------------------------------------------------------


def test_graph_ingest_corpus_appends_observed_status_codes_and_roles() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
        response_body={"id": "123", "vin": "ABC"},
    )
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    target = next(
        op for op in graph.operations
        if op.operation_id == "op_GET_/api/v2/vehicles/{vehicleId}"
    )
    assert 200 in target.observed_status_codes
    assert "user_a" in target.observed_roles


def test_graph_ingest_corpus_creates_request_and_response_examples() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    item = corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
        response_body={"id": "123", "vin": "ABC"},
    )
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    request_examples = [
        rex for rex in graph.request_examples if rex.request_id == item.request_id
    ]
    response_examples = [
        rex for rex in graph.response_examples if rex.request_id == item.request_id
    ]
    assert len(request_examples) == 1
    assert len(response_examples) == 1
    assert request_examples[0].auth_profile == "user_a"
    assert "id" in response_examples[0].response_fields_seen


def test_graph_ingest_corpus_marks_cross_role_signal_when_two_roles_overlap_object_id() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
    )
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    target = next(
        op for op in graph.operations
        if op.operation_id == "op_GET_/api/v2/vehicles/{vehicleId}"
    )
    assert "cross_role_signal" in target.risk_hints
    summary = ApiGraphService().summary_for_planner(cid)
    assert "op_GET_/api/v2/vehicles/{vehicleId}" in summary.cross_role_signal_operations


def test_graph_ingest_corpus_creates_runtime_only_operation_when_spec_misses_path() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    svc = ApiGraphService()
    svc.build_from_openapi(cid, SAMPLE_SPEC_TEXT)

    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/internal/admin/secrets",
        path_template="/api/internal/admin/secrets",
        status_code=200,
        auth_profile="admin",
    )
    graph = svc.ingest_corpus(cid)
    runtime_only = [op for op in graph.operations if op.sources == ["corpus_only"]]
    assert any(
        op.path_template == "/api/internal/admin/secrets" for op in runtime_only
    )


def test_graph_ingest_corpus_does_not_create_confirmed_findings() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_b",
    )
    ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    assert memory_store.findings == []
    assert memory_store.findings_by_session.get(cid, []) == []
    assert memory_store.evidence_records == []
    assert memory_store.evidence_by_session.get(cid, []) == []


def test_graph_dependency_corpus_upgrade_raises_confidence() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="POST",
        url="http://localhost:8888/api/v2/vehicles",
        path_template="/api/v2/vehicles",
        status_code=201,
        auth_profile="user_a",
        response_body={"id": "123", "vin": "ABC"},
    )
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    graph = ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    upgraded = [
        e for e in graph.edges
        if e.type in {"PRODUCES", "CONSUMES"}
        and e.to_node == "restype:vehicle"
    ]
    assert upgraded, "expected PRODUCES/CONSUMES edges for vehicle"
    assert any(
        e.confidence >= 0.95 and "corpus" in e.sources for e in upgraded
    )


# ---------------------------------------------------------------------
# Summary / isolation / campaign counts
# ---------------------------------------------------------------------


def test_graph_summary_for_planner_lists_high_risk_and_seeded_operations() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    summary = ApiGraphService().summary_for_planner(cid)
    assert summary.campaign_id == cid
    assert summary.operations_total == 3
    assert summary.operations_with_seed >= 1
    assert summary.operations_auth_required >= 1
    assert "op_GET_/api/v2/vehicles/{vehicleId}" in summary.bola_candidates
    assert "op_GET_/api/v2/vehicles/{vehicleId}" in summary.object_id_operations
    assert "vehicle" in summary.resource_types
    assert "user_a" in summary.seeded_operations_by_role
    assert (
        "op_GET_/api/v2/vehicles/{vehicleId}"
        in summary.seeded_operations_by_role["user_a"]
    )


def test_graph_isolation_per_campaign() -> None:
    _reset_memory_store()
    c1 = _create_campaign(target_url="http://host1:8888")
    c2 = _create_campaign(target_url="http://host2:9999")
    svc = ApiGraphService()
    svc.build_from_openapi(c1, SAMPLE_SPEC_TEXT)
    svc.build_from_openapi(c2, SAMPLE_SPEC_TEXT)
    ops_1 = svc.list_operations(c1)
    ops_2 = svc.list_operations(c2)
    assert len(ops_1) == 3
    assert len(ops_2) == 3
    assert all(op.operation_id for op in ops_1)
    g1 = svc.get_graph(c1)
    g2 = svc.get_graph(c2)
    assert g1 is not None and g2 is not None
    assert g1.campaign_id == c1
    assert g2.campaign_id == c2


def test_campaign_summary_counts_operations_after_build() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    summary_before = CampaignService().get_summary(cid)
    assert summary_before is not None
    assert summary_before.counts.operations == 0

    ApiGraphService().build_from_openapi(cid, SAMPLE_SPEC_TEXT)
    summary_after = CampaignService().get_summary(cid)
    assert summary_after is not None
    assert summary_after.counts.operations == 3


# ---------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------


def test_routes_graph_build_returns_201_and_summary_returns_200() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns", json={"target_url": "http://localhost:8888"}
    )
    cid = create_response.json()["campaign_id"]

    build_response = client.post(
        f"/v1/graph/{cid}/build",
        json={"openapi_spec_text": SAMPLE_SPEC_TEXT},
    )
    assert build_response.status_code == 201
    payload = build_response.json()
    assert payload["status"] == "built"
    assert payload["campaign_id"] == cid
    assert payload["operations_count"] == 3
    assert payload["edges_count"] >= 1
    assert "openapi" in payload["sources_used"]

    summary_response = client.get(f"/v1/graph/{cid}/summary")
    assert summary_response.status_code == 200
    summary = summary_response.json()
    assert summary["campaign_id"] == cid
    assert summary["operations_total"] == 3
    assert "op_GET_/api/v2/vehicles/{vehicleId}" in summary["bola_candidates"]

    operations_response = client.get(f"/v1/graph/{cid}/operations")
    assert operations_response.status_code == 200
    ops_payload = operations_response.json()
    assert isinstance(ops_payload, list)
    assert len(ops_payload) == 3


def test_routes_graph_build_400_when_openapi_spec_text_missing() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns", json={"target_url": "http://localhost:8888"}
    )
    cid = create_response.json()["campaign_id"]

    response = client.post(f"/v1/graph/{cid}/build", json={})
    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["error"] == "invalid_graph_build_request"

    response_blank = client.post(
        f"/v1/graph/{cid}/build", json={"openapi_spec_text": "   "}
    )
    assert response_blank.status_code == 400


def test_routes_graph_build_returns_400_for_invalid_openapi_spec() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns", json={"target_url": "http://localhost:8888"}
    )
    cid = create_response.json()["campaign_id"]

    response = client.post(
        f"/v1/graph/{cid}/build",
        json={"openapi_spec_text": "not-json: [:::]"},
    )
    assert response.status_code == 400
    body = response.json()
    assert body["detail"]["error"] == "invalid_openapi_spec"
    assert "traceback" not in str(body).lower()


def test_routes_graph_build_404_for_missing_campaign() -> None:
    client = _fresh_client()
    response = client.post(
        "/v1/graph/cmp_does_not_exist/build",
        json={"openapi_spec_text": SAMPLE_SPEC_TEXT},
    )
    assert response.status_code == 404
    body = response.json()
    assert body["detail"]["error"] == "campaign_not_found"


def test_graph_summary_returns_empty_summary_when_graph_not_built() -> None:
    client = _fresh_client()
    create_response = client.post(
        "/v1/campaigns", json={"target_url": "http://localhost:8888"}
    )
    cid = create_response.json()["campaign_id"]
    response = client.get(f"/v1/graph/{cid}/summary")
    assert response.status_code == 200
    summary = response.json()
    assert summary["campaign_id"] == cid
    assert summary["operations_total"] == 0
    assert summary["bola_candidates"] == []
    assert summary["resource_types"] == []
    assert summary["seeded_operations_by_role"] == {}

    missing_response = client.get("/v1/graph/cmp_missing/summary")
    assert missing_response.status_code == 404


def test_graph_summary_seeded_operations_by_role_excludes_auth_baseline_only_roles() -> None:
    _reset_memory_store()
    cid = _create_campaign()
    spec_service = ApiGraphService()
    spec_service.build_from_openapi(cid, SAMPLE_SPEC_TEXT)

    corpus = RequestCorpusService()
    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=403,
        auth_profile="user_a",
    )
    graph = spec_service.ingest_corpus(cid)
    summary = spec_service.summary_for_planner(cid)
    assert graph is not None
    assert "user_a" not in summary.seeded_operations_by_role
    assert summary.operations_with_seed == 0

    corpus.add_exchange(
        campaign_id=cid,
        method="GET",
        url="http://localhost:8888/api/v2/vehicles/123",
        path_template="/api/v2/vehicles/{vehicleId}",
        status_code=200,
        auth_profile="user_a",
    )
    spec_service.ingest_corpus(cid)
    summary_seeded = spec_service.summary_for_planner(cid)
    assert "user_a" in summary_seeded.seeded_operations_by_role
    assert summary_seeded.operations_with_seed >= 1
