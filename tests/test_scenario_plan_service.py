"""Phase 15A — LLM OpenAPI Scenario Planner (stateless, sidecar)."""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.models.api_graph import ApiGraph, GraphSummary, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation, ObservationType, SecurityRelevance
from backend.models.scenario_plan import (
    ScenarioPlanRequestBody,
    ScenarioStatus,
    ScenarioType,
)
from backend.services.api_graph_service import ApiGraphService
from backend.services.openapi_scenario_llm_planner import PromptBuilder, StubScenarioLlmClient
from backend.services.scenario_graph_compact_service import ScenarioGraphCompactService
from backend.services.scenario_plan_service import ScenarioPlanService
from backend.services.tool_registry import ToolRegistry
from backend.storage.memory_store import memory_store


client = TestClient(app)


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


def _store_campaign(
    campaign_id: str = "cmp_scn",
    *,
    roles_json: list[dict[str, Any]] | None = None,
) -> None:
    c = Campaign(
        campaign_id=campaign_id,
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=600),
        roles_json=roles_json
        or [
            {"name": "owner", "headers": {"X-Role": "owner"}},
            {"name": "attacker", "headers": {"X-Role": "attacker"}},
        ],
    )
    memory_store.store_campaign(campaign_id, c.model_dump(mode="json"))


def _store_graph_bola_and_schema(
    campaign_id: str = "cmp_scn",
    *,
    object_op_id: str = "op_GET_/api/v1/items/{id}",
) -> None:
    graph = ApiGraph(
        campaign_id=campaign_id,
        operations=[
            Operation(
                operation_id=object_op_id,
                method="GET",
                path_template="/api/v1/items/{id}",
                owasp_candidates=["API1_BOLA"],
                risk_hints=["object_id_in_path"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/api/v1/items",
                method="POST",
                path_template="/api/v1/items",
                owasp_candidates=["API3_BOPLA"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_GET_/api/v1/admin/users",
                method="GET",
                path_template="/api/v1/admin/users",
                owasp_candidates=["API5_BFLA"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign(campaign_id, graph.model_dump(mode="json"))


class _FakeLlmClient:
    def __init__(self, raw: dict[str, Any]) -> None:
        self._raw = raw

    def generate_raw_plan(
        self,
        *,
        campaign_id: str,
        compact_graph: dict[str, Any],
        request: ScenarioPlanRequestBody,
    ) -> dict[str, Any]:
        return self._raw


class _FakeRegistry(ToolRegistry):
    def has_adapter(self, tool_name: str) -> bool:
        if tool_name == "schemathesis_negative_test":
            return True
        return super().has_adapter(tool_name)


def test_scenario_plan_route_campaign_missing_returns_404() -> None:
    _reset_store()
    r = client.post(
        "/v1/scenarios/plan/missing",
        json=ScenarioPlanRequestBody().model_dump(mode="json"),
    )
    assert r.status_code == 404
    assert r.json()["error"] == "campaign_not_found"


def test_scenario_plan_graph_empty_returns_warning_and_no_accepted() -> None:
    _reset_store()
    _store_campaign()
    r = client.post(
        "/v1/scenarios/plan/cmp_scn",
        json=ScenarioPlanRequestBody().model_dump(mode="json"),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["graph_empty"] is True
    assert "api_graph_empty_or_missing" in data["warnings"]
    assert data["scenarios"] == []
    assert not any(s.get("status") == ScenarioStatus.accepted.value for s in data["scenarios"])


def test_scenario_plan_rejects_unknown_scenario_type() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "not_a_valid_type",
                "vulnerability_classes": ["BOLA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": [],
                "candidate_workers": ["bola_replay_probe"],
                "confidence": 0.5,
                "rationale": "x",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any(s.status == ScenarioStatus.rejected for s in resp.scenarios)
    assert any("unknown_scenario_type" in e for s in resp.scenarios for e in s.errors)


def test_scenario_plan_rejects_unknown_operation_id() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_UNKNOWN"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 0.5,
                "rationale": "x",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any("unknown_operation_id" in (e or "") for s in resp.scenarios for e in s.errors)


def test_scenario_plan_rejects_unknown_tool_name() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["not_a_real_tool_zzz"],
                "confidence": 0.5,
                "rationale": "x",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any("unknown_tool" in e for s in resp.scenarios for e in s.errors)


def test_scenario_plan_rejects_raw_url_in_scenario_fields() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 0.5,
                "rationale": "See https://example.com/path for context",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any("raw_url_not_allowed" in e for s in resp.scenarios for e in s.errors)


def test_graph_empty_never_returns_accepted_scenarios(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()

    def _empty_ops_summary(self: ApiGraphService, campaign_id: str) -> GraphSummary:
        return GraphSummary(campaign_id=campaign_id, operations_total=0)

    monkeypatch.setattr(ApiGraphService, "summary_for_planner", _empty_ops_summary)

    oid = "op_GET_/api/v1/items/{id}"
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": [oid],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 0.5,
                "rationale": "valid without urls",
            },
        ],
    }
    reg = _FakeRegistry()
    svc = ScenarioPlanService(registry=reg, llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert resp.graph_empty is True
    assert "api_graph_empty_or_missing" in resp.warnings
    assert resp.scenarios
    assert all(s.status == ScenarioStatus.blocked for s in resp.scenarios)
    assert all("graph_empty" in (s.blocking_codes or []) for s in resp.scenarios)


def test_scenario_plan_rejects_secret_in_rationale() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 0.5,
                "rationale": "Bearer leaked-token-here",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any("secret_pattern" in e for s in resp.scenarios for e in s.errors)


def test_scenario_plan_validates_confidence_range() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 99.0,
                "rationale": "x",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert any("invalid_confidence_range" in e for s in resp.scenarios for e in s.errors)


def test_scenario_plan_truncates_rationale() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    long_text = "a" * 1200
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["bola_replay_probe"],
                "confidence": 0.5,
                "rationale": long_text,
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    s = next(x for x in resp.scenarios if x.scenario_id == "scn_x")
    assert len(s.rationale) == 800


def test_scenario_plan_duplicate_scenarios_warning_or_merge() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    oid = "op_GET_/api/v1/items/{id}"
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_a",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": [oid],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["bola_replay_probe"],
                "confidence": 0.5,
                "rationale": "first",
            },
            {
                "scenario_id": "scn_b",
                "scenario_type": "schema_negative_testing",
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": [oid],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["bola_replay_probe"],
                "confidence": 0.6,
                "rationale": "second",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    assert len(resp.scenarios) == 1
    assert "duplicate_scenario_merged" in (resp.scenarios[0].warnings or [])


def test_compact_graph_does_not_include_tokens_headers_cookies() -> None:
    _reset_store()
    _store_campaign(
        roles_json=[
            {
                "name": "user_a",
                "headers": {"Authorization": "Bearer secret-token-value"},
                "Cookie": "session=abc",
            },
        ],
    )
    _store_graph_bola_and_schema()
    c = Campaign.model_validate(memory_store.get_campaign("cmp_scn"))
    compact = ScenarioGraphCompactService().build(c, max_operations=50)
    blob = json.dumps(compact, ensure_ascii=False)
    assert "Authorization" not in blob
    assert "Bearer" not in blob
    assert "Cookie" not in blob
    assert "secret-token" not in blob


def test_scenario_plan_blocks_bola_without_roles_or_object_preconditions() -> None:
    _reset_store()
    _store_campaign(
        roles_json=[{"name": "only_one", "headers": {"X": "1"}}],
    )
    _store_graph_bola_and_schema()
    svc = ScenarioPlanService()
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    bola = [s for s in resp.scenarios if s.scenario_type == "access_control_bola"]
    assert bola
    assert bola[0].status == ScenarioStatus.blocked
    assert "missing_two_authenticated_roles" in bola[0].blocking_codes


def test_scenario_plan_accepts_schema_negative_testing_for_graph_operations_when_tool_known() -> (
    None
):
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    reg = _FakeRegistry()
    svc = ScenarioPlanService(registry=reg, llm_client=StubScenarioLlmClient())
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    schema = [s for s in resp.scenarios if s.scenario_type == "schema_negative_testing"]
    assert schema
    assert schema[0].status == ScenarioStatus.accepted
    assert "schemathesis_negative_test" in schema[0].candidate_workers


def test_scenario_plan_marks_no_adapter_as_blocked() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_x",
                "scenario_type": "mass_assignment",
                "vulnerability_classes": ["MASS_ASSIGNMENT"],
                "operation_ids": ["op_POST_/api/v1/items"],
                "resource_type": "",
                "required_preconditions": ["writable_schema"],
                "candidate_workers": ["property_mutation_test"],
                "confidence": 0.5,
                "rationale": "no adapter in phase5 stub",
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    s = resp.scenarios[0]
    assert s.status == ScenarioStatus.blocked
    assert "no_executable_adapter" in s.blocking_codes


def test_route_returns_validated_payload() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    r = client.post(
        "/v1/scenarios/plan/cmp_scn",
        json=ScenarioPlanRequestBody().model_dump(mode="json"),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["schema_version"] == "scenario-plan-response/v1"
    assert data["campaign_id"] == "cmp_scn"
    assert isinstance(data["scenarios"], list)


def test_scenario_plan_does_not_create_worker_command_toolrun_evidence_or_finding() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    cmds_before = len(memory_store.commands)
    runs_before = len(memory_store.tool_runs)
    ev_before = len(memory_store.evidence_packs)
    fin_before = len(memory_store.confirmed_findings)
    client.post(
        "/v1/scenarios/plan/cmp_scn",
        json=ScenarioPlanRequestBody().model_dump(mode="json"),
    )
    assert len(memory_store.commands) == cmds_before
    assert len(memory_store.tool_runs) == runs_before
    assert len(memory_store.evidence_packs) == ev_before
    assert len(memory_store.confirmed_findings) == fin_before


def test_stub_llm_disabled_returns_safe_empty_or_heuristic_plan() -> None:
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    r = client.post(
        "/v1/scenarios/plan/cmp_scn",
        json=ScenarioPlanRequestBody(
            llm={"enabled": False, "model": "", "prompt_version": "scenario-planner/v1"},
        ).model_dump(mode="json"),
    )
    assert r.status_code == 200
    data = r.json()
    assert "llm_disabled_using_stub_heuristic" in data["warnings"]
    assert len(data["scenarios"]) >= 1


def test_prompt_explicitly_disallows_finding_creation() -> None:
    sys_prompt = PromptBuilder.system_prompt(prompt_version="scenario-planner/v1")
    assert "Do not create findings." in sys_prompt
    assert "analysis-only" in sys_prompt.lower()


def test_prompt_instructs_llm_to_use_only_allowed_operation_ids_and_no_http() -> None:
    sys_prompt = PromptBuilder.system_prompt(prompt_version="scenario-planner/v1")
    assert "operation_id" in sys_prompt.lower()
    assert "allowlist" in sys_prompt.lower() or "provided" in sys_prompt.lower()
    assert "https://" in sys_prompt.lower()
    user = PromptBuilder.user_prompt(
        campaign_id="cmp",
        compact_graph={"operations_compact": [{"operation_id": "op_x"}]},
    )
    assert "op_x" in user
    assert "allowed_operation_ids_sample" in user


def test_scenario_plan_route_invalid_body_returns_400() -> None:
    _reset_store()
    r = client.post("/v1/scenarios/plan/cmp_x", json={"max_operations": 0})
    assert r.status_code == 400
    assert r.json()["error"] == "invalid_scenario_plan_request"


def test_scenario_plan_sees_graph_after_build_from_openapi_url() -> None:
    """Phase 15C-fix: graph built via URL fetch → ScenarioPlan is not graph-empty."""
    from tests.test_api_graph_service import SAMPLE_SPEC_TEXT

    _reset_store()
    cr = client.post(
        "/v1/campaigns",
        json={
            "target_url": "http://localhost:8888",
            "openapi_url": "https://example.com/crAPI-openapi.json",
        },
    )
    assert cr.status_code == 201
    cid = cr.json()["campaign_id"]
    with patch(
        "backend.api.routes_graph._fetch_openapi_spec_from_url",
        return_value=SAMPLE_SPEC_TEXT,
    ):
        br = client.post(f"/v1/graph/{cid}/build", json={})
    assert br.status_code == 201
    assert br.json()["operations_count"] > 0

    r = client.post(
        f"/v1/scenarios/plan/{cid}",
        json=ScenarioPlanRequestBody(
            llm={"enabled": False, "model": "", "prompt_version": "scenario-planner/v1"},
        ).model_dump(mode="json"),
    )
    assert r.status_code == 200
    data = r.json()
    assert data["graph_empty"] is False
    assert "api_graph_empty_or_missing" not in data["warnings"]


def test_scenario_plan_schema_negative_testing_accepted_with_real_tool_registry() -> None:
    """Phase 16A: schemathesis_negative_test has Phase 5 adapter → no no_executable_adapter."""
    _reset_store()
    _store_campaign()
    _store_graph_bola_and_schema()
    raw = {
        "schema_version": "scenario-plan/v1",
        "campaign_id": "cmp_scn",
        "source": "test",
        "scenarios": [
            {
                "scenario_id": "scn_schema",
                "status": "accepted",
                "scenario_type": ScenarioType.schema_negative_testing.value,
                "vulnerability_classes": ["SCHEMA"],
                "operation_ids": ["op_GET_/api/v1/items/{id}"],
                "resource_type": "",
                "required_preconditions": ["openapi_schema"],
                "candidate_workers": ["schemathesis_negative_test"],
                "confidence": 0.7,
                "rationale": "negative schema coverage",
                "blocking_codes": [],
                "errors": [],
                "warnings": [],
            },
        ],
    }
    svc = ScenarioPlanService(llm_client=_FakeLlmClient(raw))
    resp = svc.plan("cmp_scn", ScenarioPlanRequestBody())
    s = next(x for x in resp.scenarios if x.scenario_type == ScenarioType.schema_negative_testing)
    assert s.status == ScenarioStatus.accepted
    assert "no_executable_adapter" not in (s.blocking_codes or [])
