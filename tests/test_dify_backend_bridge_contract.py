"""Phase 8 — Dify backend bridge contract tests."""
from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from backend.main import app
from backend.storage.memory_store import memory_store


ROOT = Path(__file__).resolve().parents[1]
NEW_WORKFLOW = ROOT / "dify" / "wf-backend-bridge-smoke.yml"
LEGACY_WORKFLOW = ROOT / "dify" / "wf-multiagent-dast-multiworker.yml"

VEHICLE_OBJECT_ID = "veh_123"
ATTACKER_OWN_OBJECT_ID = "veh_456"
OWNER_ROLE = "owner"
ATTACKER_ROLE = "attacker"
VEHICLE_PATH = "/api/v1/vehicles/{vehicleId}"
VEHICLE_COLLECTION_PATH = "/api/v1/vehicles"
VEHICLE_OPERATION_ID = f"op_GET_{VEHICLE_PATH}"
VEHICLE_COLLECTION_OPERATION_ID = f"op_GET_{VEHICLE_COLLECTION_PATH}"


def _reset_store() -> None:
    for name in [
        "campaigns", "campaign_by_run_id", "campaign_by_session_id",
        "corpus_items", "corpus_by_campaign", "resource_instances",
        "resources_by_campaign", "graphs_by_campaign", "commands",
        "commands_by_campaign", "command_fingerprints", "tool_runs",
        "tool_runs_by_campaign", "tool_results", "artifacts",
        "artifacts_by_run", "observations", "observations_by_campaign",
        "observations_by_tool_run", "verification_plans",
        "verification_plans_by_campaign", "evidence_packs",
        "evidence_packs_by_campaign", "evidence_packs_by_observation",
        "evidence_packs_by_verification_plan", "judge_decisions",
        "judge_decisions_by_campaign", "judge_decisions_by_evidence",
        "confirmed_findings", "confirmed_findings_by_campaign",
        "findings_by_fingerprint", "evidence_pack_apply_meta",
        "observation_apply_meta",
    ]:
        getattr(memory_store, name).clear()
    memory_store.evidence_records.clear()
    memory_store.findings.clear()
    memory_store.evidence_by_session.clear()
    memory_store.findings_by_session.clear()


def _client() -> TestClient:
    return TestClient(app)


def _vehicle_openapi() -> str:
    return json.dumps({
        "openapi": "3.0.3",
        "info": {"title": "Vehicle API", "version": "1.0.0"},
        "paths": {
            VEHICLE_COLLECTION_PATH: {
                "get": {
                    "responses": {
                        "200": {
                            "description": "Vehicle collection",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"id": {"type": "string"}},
                                    }
                                }
                            },
                        }
                    }
                }
            },
            VEHICLE_PATH: {
                "get": {
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
                            "description": "Vehicle",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "id": {"type": "string"},
                                            "owner": {"type": "string"},
                                        },
                                    }
                                }
                            },
                        }
                    },
                }
            },
        },
    })


def _create_campaign(client: TestClient) -> str:
    response = client.post("/v1/campaigns", json={
        "target_url": "http://testapp.local",
        "allowed_hosts": ["testapp.local"],
        "roles_json": [
            {"name": OWNER_ROLE, "kind": "authenticated"},
            {"name": ATTACKER_ROLE, "kind": "authenticated"},
        ],
    })
    assert response.status_code == 201
    return response.json()["campaign_id"]


def _build_graph(client: TestClient, campaign_id: str) -> None:
    response = client.post(
        f"/v1/graph/{campaign_id}/build",
        json={"openapi_spec_text": _vehicle_openapi()},
    )
    assert response.status_code == 201
    assert response.json()["operations_count"] >= 2


def _add_corpus(
    client: TestClient,
    campaign_id: str,
    *,
    role: str,
    url: str,
    path_template: str,
    operation_id: str,
    response_body: dict,
    body: dict | None = None,
) -> str:
    response = client.post("/v1/corpus/add", json={
        "campaign_id": campaign_id,
        "method": "GET",
        "url": url,
        "path_template": path_template,
        "auth_profile": role,
        "headers": {"Authorization": "Bearer should-be-redacted"},
        "body": body or {},
        "status_code": 200,
        "response_body": response_body,
        "operation_id": operation_id,
        "source": "phase8_bridge_test",
    })
    assert response.status_code == 201
    return response.json()["request_id"]


def _add_bola_corpus(client: TestClient, campaign_id: str) -> dict[str, str]:
    owner_seed = _add_corpus(
        client,
        campaign_id,
        role=OWNER_ROLE,
        url=f"http://testapp.local/api/v1/vehicles/{VEHICLE_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        operation_id=VEHICLE_OPERATION_ID,
        response_body={"id": VEHICLE_OBJECT_ID, "owner": OWNER_ROLE},
        body={"password": "owner-secret"},
    )
    attacker_attack = _add_corpus(
        client,
        campaign_id,
        role=ATTACKER_ROLE,
        url=f"http://testapp.local/api/v1/vehicles/{VEHICLE_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        operation_id=VEHICLE_OPERATION_ID,
        response_body={"id": VEHICLE_OBJECT_ID, "owner": OWNER_ROLE},
        body={"access_token": "attacker-secret"},
    )
    attacker_self = _add_corpus(
        client,
        campaign_id,
        role=ATTACKER_ROLE,
        url=f"http://testapp.local/api/v1/vehicles/{ATTACKER_OWN_OBJECT_ID}",
        path_template=VEHICLE_PATH,
        operation_id=VEHICLE_OPERATION_ID,
        response_body={"id": ATTACKER_OWN_OBJECT_ID, "owner": ATTACKER_ROLE},
    )
    owner_collection = _add_corpus(
        client,
        campaign_id,
        role=OWNER_ROLE,
        url="http://testapp.local/api/v1/vehicles",
        path_template=VEHICLE_COLLECTION_PATH,
        operation_id=VEHICLE_COLLECTION_OPERATION_ID,
        response_body={"id": VEHICLE_OBJECT_ID},
    )
    attacker_collection = _add_corpus(
        client,
        campaign_id,
        role=ATTACKER_ROLE,
        url="http://testapp.local/api/v1/vehicles",
        path_template=VEHICLE_COLLECTION_PATH,
        operation_id=VEHICLE_COLLECTION_OPERATION_ID,
        response_body={"id": ATTACKER_OWN_OBJECT_ID},
    )
    return {
        "owner_seed": owner_seed,
        "attacker_attack": attacker_attack,
        "attacker_self": attacker_self,
        "owner_collection": owner_collection,
        "attacker_collection": attacker_collection,
    }


def _prepare_campaign_with_bola_corpus(client: TestClient) -> tuple[str, dict[str, str]]:
    campaign_id = _create_campaign(client)
    _build_graph(client, campaign_id)
    refs = _add_bola_corpus(client, campaign_id)
    return campaign_id, refs


def _create_cross_role_signal(client: TestClient, campaign_id: str) -> dict:
    response = client.post(
        f"/v1/corpus/{campaign_id}/cross-role-signals",
        json={"operation_id": VEHICLE_OPERATION_ID, "limit": 10},
    )
    assert response.status_code == 200
    return response.json()


def test_corpus_cross_role_signals_creates_observation_from_candidate():
    _reset_store()
    client = _client()
    campaign_id, refs = _prepare_campaign_with_bola_corpus(client)

    body = _create_cross_role_signal(client, campaign_id)

    assert body["campaign_id"] == campaign_id
    assert body["observations_created"] == 1
    assert body["already_existing"] == 0
    obs = body["observations"][0]
    assert obs["type"] == "cross_role_access_signal"
    assert obs["campaign_id"] == campaign_id
    assert obs["operation_id"] == VEHICLE_OPERATION_ID
    assert obs["request_id"] == refs["attacker_attack"]
    assert obs["auth_profile"] == ATTACKER_ROLE
    assert obs["details"]["object_id"] == VEHICLE_OBJECT_ID
    assert obs["details"]["owner_role"] == OWNER_ROLE
    assert obs["details"]["attacker_role"] == ATTACKER_ROLE
    assert obs["details"]["owner_request_id"] == refs["owner_seed"]
    assert obs["details"]["attack_request_id"] == refs["attacker_attack"]
    assert obs["details"]["baseline_request_id"] == refs["owner_seed"]
    assert obs["details"]["candidate"]["source"] == "request_corpus.cross_role_candidate"


def test_corpus_cross_role_signals_is_idempotent():
    _reset_store()
    client = _client()
    campaign_id, _ = _prepare_campaign_with_bola_corpus(client)

    first = _create_cross_role_signal(client, campaign_id)
    second = _create_cross_role_signal(client, campaign_id)

    assert first["observations_created"] == 1
    assert second["observations_created"] == 0
    assert second["already_existing"] == 1
    assert first["observations"][0]["observation_id"] == second["observations"][0]["observation_id"]
    assert len(memory_store.list_observations_by_campaign(campaign_id)) == 1


def test_corpus_cross_role_signals_operation_filter_mismatch_returns_empty():
    _reset_store()
    client = _client()
    campaign_id, _ = _prepare_campaign_with_bola_corpus(client)

    response = client.post(
        f"/v1/corpus/{campaign_id}/cross-role-signals",
        json={"operation_id": "op_GET_/api/v1/other/{id}", "limit": 10},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["observations_created"] == 0
    assert body["already_existing"] == 0
    assert body["observations"] == []
    assert memory_store.list_observations_by_campaign(campaign_id) == []


def test_corpus_cross_role_signals_limit_applies():
    _reset_store()
    client = _client()
    campaign_id, _ = _prepare_campaign_with_bola_corpus(client)
    _add_corpus(
        client,
        campaign_id,
        role=OWNER_ROLE,
        url="http://testapp.local/api/v1/vehicles/veh_789",
        path_template=VEHICLE_PATH,
        operation_id=VEHICLE_OPERATION_ID,
        response_body={"id": "veh_789", "owner": OWNER_ROLE},
    )
    _add_corpus(
        client,
        campaign_id,
        role=ATTACKER_ROLE,
        url="http://testapp.local/api/v1/vehicles/veh_789",
        path_template=VEHICLE_PATH,
        operation_id=VEHICLE_OPERATION_ID,
        response_body={"id": "veh_789", "owner": OWNER_ROLE},
    )

    response = client.post(
        f"/v1/corpus/{campaign_id}/cross-role-signals",
        json={"operation_id": VEHICLE_OPERATION_ID, "limit": 1},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["observations_created"] == 1
    assert body["already_existing"] == 0
    assert len(body["observations"]) == 1
    assert len(memory_store.list_observations_by_campaign(campaign_id)) == 1


def test_corpus_cross_role_signals_404_for_missing_campaign():
    _reset_store()
    response = _client().post("/v1/corpus/cmp_missing/cross-role-signals", json={})
    assert response.status_code == 404
    assert response.json()["error"] == "campaign_not_found"


def test_corpus_cross_role_signals_does_not_create_evidence_or_findings():
    _reset_store()
    client = _client()
    campaign_id, _ = _prepare_campaign_with_bola_corpus(client)

    _create_cross_role_signal(client, campaign_id)

    assert memory_store.evidence_packs == {}
    assert memory_store.judge_decisions == {}
    assert memory_store.confirmed_findings == {}
    assert memory_store.findings == []
    assert memory_store.evidence_records == []


def test_corpus_cross_role_signals_campaign_isolation():
    _reset_store()
    client = _client()
    campaign_a, _ = _prepare_campaign_with_bola_corpus(client)
    campaign_b, _ = _prepare_campaign_with_bola_corpus(client)

    body_a = _create_cross_role_signal(client, campaign_a)
    body_b = _create_cross_role_signal(client, campaign_b)

    obs_a = body_a["observations"][0]
    obs_b = body_b["observations"][0]
    assert obs_a["campaign_id"] == campaign_a
    assert obs_b["campaign_id"] == campaign_b
    assert obs_a["observation_id"] != obs_b["observation_id"]
    assert len(memory_store.list_observations_by_campaign(campaign_a)) == 1
    assert len(memory_store.list_observations_by_campaign(campaign_b)) == 1


def test_backend_bridge_bola_route_smoke_to_confirmed_finding():
    _reset_store()
    client = _client()
    campaign_id, _ = _prepare_campaign_with_bola_corpus(client)

    signal_body = _create_cross_role_signal(client, campaign_id)
    observation_id = signal_body["observations"][0]["observation_id"]

    triage = client.post(f"/v1/observations/triage/{observation_id}")
    assert triage.status_code == 200
    plan = triage.json()["verification_plan"]
    assert plan["goal"] == "prove_ownership"
    plan_id = plan["verification_plan_id"]

    evidence = client.post(f"/v1/evidence/build-from-plan/{plan_id}")
    assert evidence.status_code == 200
    pack = evidence.json()["evidence_pack"]
    assert pack["status"] == "ready_for_judge"
    assert pack["judge_ready"] is True
    assert pack["missing_evidence"] == []
    assert pack["baseline"] is not None
    assert pack["attack"] is not None
    assert pack["ownership_proof"] is not None
    assert pack["controls"]
    assert pack["diff"] is not None
    assert pack["replay_steps"]

    apply = client.post("/v1/judge/apply", json={
        "campaign_id": campaign_id,
        "evidence_id": pack["evidence_id"],
        "task_id": "task_phase8_bridge",
        "verdict": {
            "schema_version": "judge-verdict/v1",
            "verdict": "confirmed",
            "confidence": 0.95,
            "severity": "high",
            "reason": "Synthetic route smoke proof is complete.",
            "finding_candidate": {
                "title": "BOLA allows attacker vehicle access",
                "severity": "high",
                "vulnerability_class": "cross_role_access_signal",
                "summary": "Attacker can read owner vehicle.",
                "extras": {"source": "phase8_bridge_route_smoke"},
            },
            "judge_source": "route-test",
            "judge_model": "unit-test",
        },
    })
    assert apply.status_code == 200
    finding_id = apply.json()["finding_id"]
    assert finding_id

    findings = client.get(f"/v1/findings/confirmed/{campaign_id}")
    assert findings.status_code == 200
    assert len(findings.json()) == 1
    assert findings.json()[0]["finding_id"] == finding_id


def _new_workflow_text() -> str:
    return NEW_WORKFLOW.read_text(encoding="utf-8")


def test_new_dify_bridge_workflow_exists():
    assert NEW_WORKFLOW.exists()
    assert "wf-backend-bridge-smoke" in _new_workflow_text()


def test_new_dify_bridge_workflow_does_not_modify_legacy_scheduler_loop():
    assert LEGACY_WORKFLOW.exists()
    legacy = LEGACY_WORKFLOW.read_text(encoding="utf-8")
    assert "/v1/schedule/update-queue" in legacy
    assert "wf-multiagent-dast-tool-agents-judge" in legacy


def test_new_dify_bridge_workflow_uses_new_backend_endpoints():
    text = _new_workflow_text()
    for endpoint in [
        "/v1/campaigns",
        "/v1/graph/",
        "/build",
        "/summary",
        "/v1/corpus/",
        "/cross-role-signals",
        "/v1/observations/triage/",
        "/v1/evidence/build-from-plan/",
        "/v1/judge/apply",
        "/v1/findings/confirmed/",
    ]:
        assert endpoint in text


def test_new_dify_bridge_workflow_does_not_call_schedule_update_queue():
    text = _new_workflow_text()
    assert "/v1/schedule/update-queue" not in text
    assert "/v1/schedule/next-task" not in text


def test_new_dify_bridge_workflow_does_not_call_legacy_tools_wrappers_execute():
    text = _new_workflow_text()
    assert "/v1/tools/wrappers/execute" not in text


def test_new_dify_bridge_workflow_mentions_judge_apply():
    text = _new_workflow_text()
    assert "/v1/judge/apply" in text
    assert "Apply Judge Verdict" in text


def test_new_dify_bridge_workflow_requires_judge_verdict_payload():
    text = _new_workflow_text()
    assert "JudgeVerdictPayload" in text
    assert '"schema_version": "judge-verdict/v1"' in text
    assert '"verdict": "confirmed|rejected|rework|duplicate|out_of_scope|inconclusive"' in text
    apply_block = text.split("id: apply_judge_verdict", 1)[1].split("id: list_confirmed_findings", 1)[0]
    assert 'verdict: {{#judge_verdict.text#}}' in apply_block
    assert 'verdict: "{{#judge_verdict.text#}}"' not in apply_block
    for field in [
        '"confidence":',
        '"severity":',
        '"reason":',
        '"finding_candidate":',
        '"duplicate_of_finding_id":',
        '"judge_source":',
        '"judge_model":',
    ]:
        assert field in text
