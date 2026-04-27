"""Phase 5.6 — Observation Normalizer / Triage / VerificationPlan tests.

30 tests covering:
- ObservationNormalizer behavior
- ObservationTriage behavior
- VerificationPlan generation
- Route-level endpoints
- Regression guards (no findings, no Judge)
"""
from __future__ import annotations

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.models.campaign import Campaign, CampaignLimits
from backend.models.observation import Observation, VerificationPlan
from backend.models.tool_run import (
    ToolResult,
    ToolResultError,
    ToolResultObservationLite,
    ToolResultResponse,
    ToolResultRequest,
    ToolRun,
    ToolRunStatus,
    ToolExecutionMode,
)
from backend.services.observation_normalizer import ObservationNormalizer, NormalizeError
from backend.services.observation_triage import ObservationTriage
from backend.storage.memory_store import memory_store


def _reset_store() -> None:
    memory_store.campaigns.clear()
    memory_store.campaign_by_run_id.clear()
    memory_store.campaign_by_session_id.clear()
    memory_store.corpus_items.clear()
    memory_store.corpus_by_campaign.clear()
    memory_store.resource_instances.clear()
    memory_store.resources_by_campaign.clear()
    memory_store.graphs_by_campaign.clear()
    memory_store.commands.clear()
    memory_store.commands_by_campaign.clear()
    memory_store.command_fingerprints.clear()
    memory_store.tool_runs.clear()
    memory_store.tool_runs_by_campaign.clear()
    memory_store.tool_results.clear()
    memory_store.artifacts.clear()
    memory_store.artifacts_by_run.clear()
    memory_store.observations.clear()
    memory_store.observations_by_campaign.clear()
    memory_store.observations_by_tool_run.clear()
    memory_store.verification_plans.clear()
    memory_store.verification_plans_by_campaign.clear()


def _create_campaign(campaign_id: str = "cmp_obs1") -> None:
    campaign = Campaign(
        campaign_id=campaign_id,
        target_url="http://testapp.local",
        allowed_hosts=["testapp.local"],
        limits=CampaignLimits(max_requests=1000, max_duration_sec=1800),
    )
    memory_store.store_campaign(campaign_id, campaign.model_dump(mode="json"))


def _store_finished_run(
    tool_run_id: str = "toolrun_obs_test",
    campaign_id: str = "cmp_obs1",
    tool_name: str = "custom_request_executor",
) -> None:
    run = ToolRun(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name=tool_name,
        status=ToolRunStatus.finished,
        result_ready=True,
    )
    memory_store.store_tool_run(tool_run_id, campaign_id, run.model_dump(mode="json"))


def _store_running_run(
    tool_run_id: str = "toolrun_running",
    campaign_id: str = "cmp_obs1",
) -> None:
    run = ToolRun(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name="schemathesis_negative_test",
        execution_mode=ToolExecutionMode.async_,
        status=ToolRunStatus.running,
    )
    memory_store.store_tool_run(tool_run_id, campaign_id, run.model_dump(mode="json"))


def _store_partial_run(
    tool_run_id: str = "toolrun_partial",
    campaign_id: str = "cmp_obs1",
) -> None:
    # `partial` is currently produced by ToolExecutor status override, but is not
    # part of ToolRunStatus enum; store raw run payload to mirror runtime state.
    memory_store.store_tool_run(
        tool_run_id,
        campaign_id,
        {
            "schema_version": "tool-run/v1",
            "tool_run_id": tool_run_id,
            "campaign_id": campaign_id,
            "tool_name": "schemathesis_negative_test",
            "execution_mode": "sync",
            "status": "partial",
            "started_at": "",
            "finished_at": "",
            "progress": {"requests_sent": 0, "max_requests": 0, "elapsed_sec": 0.0},
            "result_ready": True,
            "artifact_refs": [],
            "error": None,
        },
    )


def _store_tool_result(tool_run_id: str, result: ToolResult) -> None:
    memory_store.store_tool_result(tool_run_id, result.model_dump(mode="json"))


def _make_500_result(tool_run_id: str = "toolrun_obs_test", campaign_id: str = "cmp_obs1") -> ToolResult:
    return ToolResult(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name="custom_request_executor",
        status="finished",
        requests=[ToolResultRequest(request_id="req_1", method="POST", url="http://testapp.local/api/orders")],
        responses=[ToolResultResponse(request_id="req_1", status_code=500)],
    )


def _make_failed_result(
    tool_run_id: str = "toolrun_obs_test",
    campaign_id: str = "cmp_obs1",
    error_type: str = "adapter_error",
    message: str = "Something broke",
) -> ToolResult:
    return ToolResult(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name="custom_request_executor",
        status="failed",
        errors=[ToolResultError(error_type=error_type, message=message)],
    )


def _make_clean_result(tool_run_id: str = "toolrun_obs_test", campaign_id: str = "cmp_obs1") -> ToolResult:
    return ToolResult(
        tool_run_id=tool_run_id,
        campaign_id=campaign_id,
        tool_name="custom_request_executor",
        status="finished",
        requests=[ToolResultRequest(request_id="req_1", method="GET", url="http://testapp.local/api/users")],
        responses=[ToolResultResponse(request_id="req_1", status_code=200)],
    )


def _store_observation(obs: Observation) -> None:
    memory_store.store_observation(
        obs.observation_id, obs.campaign_id, obs.tool_run_id,
        obs.model_dump(mode="json"),
    )


# ─── ObservationNormalizer tests ──────────────────────────────────


def test_normalize_unexpected_500_into_observation():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())

    normalizer = ObservationNormalizer()
    result = normalizer.normalize("toolrun_obs_test")
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    obs = result[0]
    assert obs.type == "unexpected_500"
    assert obs.status_code == 500
    assert obs.judge_worthy is False
    assert obs.recommended_next_action == "replay_minimized_payload"


def test_normalize_failed_tool_result_into_diagnostic_observation():
    _reset_store()
    _create_campaign()
    run_id = "toolrun_fail"
    run = ToolRun(
        tool_run_id=run_id,
        campaign_id="cmp_obs1",
        tool_name="custom_request_executor",
        status=ToolRunStatus.failed,
    )
    memory_store.store_tool_run(run_id, "cmp_obs1", run.model_dump(mode="json"))
    _store_tool_result(run_id, _make_failed_result(tool_run_id=run_id))

    result = ObservationNormalizer().normalize(run_id)
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    assert result[0].type == "tool_error"
    assert result[0].security_relevance == "informational"
    assert result[0].recommended_next_action == "store_only"


def test_normalize_timeout_tool_result_into_timeout_signal():
    _reset_store()
    _create_campaign()
    run_id = "toolrun_timeout"
    run = ToolRun(
        tool_run_id=run_id,
        campaign_id="cmp_obs1",
        tool_name="schemathesis_negative_test",
        status=ToolRunStatus.timeout,
    )
    memory_store.store_tool_run(run_id, "cmp_obs1", run.model_dump(mode="json"))
    _store_tool_result(run_id, _make_failed_result(
        tool_run_id=run_id, error_type="timeout", message="Exceeded budget",
    ))

    result = ObservationNormalizer().normalize(run_id)
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    assert result[0].type == "timeout_signal"
    assert result[0].judge_worthy is False


def test_normalize_tool_result_observation_lite_mapped():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    tr = _make_clean_result()
    tr.observations = [
        ToolResultObservationLite(
            observation_type="cross_role_access_signal",
            confidence=0.8,
            details={"object_id": "123", "attacker_role": "user_b"},
        )
    ]
    _store_tool_result("toolrun_obs_test", tr)

    result = ObservationNormalizer().normalize("toolrun_obs_test")
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    obs = result[0]
    assert obs.type == "cross_role_access_signal"
    assert obs.confidence == 0.8
    assert obs.details.get("object_id") == "123"
    assert obs.judge_worthy is False


def test_normalize_validated_security_header_issue_observation_lite_mapped():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    tr = _make_clean_result()
    tr.observations = [
        ToolResultObservationLite(
            observation_type="validated_security_header_issue",
            confidence=0.85,
            details={
                "header_name": "X-Frame-Options",
                "alert_name": "X-Frame-Options Header Not Set",
                "actual_state": "missing",
                "validation_mode": "single_replay_header_check",
                "source_observation_id": "obs_zap_1",
                "url": "http://testapp.local/frame",
            },
        )
    ]
    _store_tool_result("toolrun_obs_test", tr)

    result = ObservationNormalizer().normalize("toolrun_obs_test")
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    obs = result[0]
    assert obs.type == "validated_security_header_issue"
    assert obs.confidence == 0.85
    assert obs.details.get("header_name") == "X-Frame-Options"


def test_normalize_tool_result_observation_lite_propagates_context_fields():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    tr = _make_clean_result()
    tr.observations = [
        ToolResultObservationLite(
            observation_type="auth_anomaly",
            confidence=0.7,
            details={
                "operation_id": "op_get_users",
                "request_id": "req_ctx_1",
                "auth_profile": "user_a",
            },
        )
    ]
    _store_tool_result("toolrun_obs_test", tr)

    result = ObservationNormalizer().normalize("toolrun_obs_test")
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    obs = result[0]
    assert obs.operation_id == "op_get_users"
    assert obs.request_id == "req_ctx_1"
    assert obs.auth_profile == "user_a"


def test_normalize_returns_empty_list_for_clean_result():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_clean_result())

    result = ObservationNormalizer().normalize("toolrun_obs_test")
    assert not isinstance(result, NormalizeError)
    assert result == []


def test_normalize_is_idempotent_for_same_tool_run():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())

    normalizer = ObservationNormalizer()
    first = normalizer.normalize("toolrun_obs_test")
    assert not isinstance(first, NormalizeError)
    assert len(first) == 1
    first_id = first[0].observation_id

    second = normalizer.normalize("toolrun_obs_test")
    assert not isinstance(second, NormalizeError)
    assert len(second) == 1
    assert second[0].observation_id == first_id


def test_normalize_409_for_running_tool_run():
    _reset_store()
    _create_campaign()
    _store_running_run()

    result = ObservationNormalizer().normalize("toolrun_running")
    assert isinstance(result, NormalizeError)
    assert result.code == "tool_run_not_terminal"


def test_normalize_partial_tool_run_is_treated_as_terminal():
    _reset_store()
    _create_campaign()
    _store_partial_run()
    tr = ToolResult(
        tool_run_id="toolrun_partial",
        campaign_id="cmp_obs1",
        tool_name="schemathesis_negative_test",
        status="partial",
        observations=[
            ToolResultObservationLite(
                observation_type="schema_mismatch",
                confidence=0.6,
                details={"operation_id": "op_GET_/api/v1/items/{id}"},
            ),
        ],
    )
    _store_tool_result("toolrun_partial", tr)

    result = ObservationNormalizer().normalize("toolrun_partial")
    assert not isinstance(result, NormalizeError)
    assert len(result) == 1
    assert result[0].type == "schema_mismatch"


def test_normalize_partial_tool_run_with_no_signals_returns_empty_not_error():
    _reset_store()
    _create_campaign()
    _store_partial_run("toolrun_partial_empty")
    tr = ToolResult(
        tool_run_id="toolrun_partial_empty",
        campaign_id="cmp_obs1",
        tool_name="schemathesis_negative_test",
        status="partial",
        observations=[],
        errors=[],
    )
    _store_tool_result("toolrun_partial_empty", tr)

    result = ObservationNormalizer().normalize("toolrun_partial_empty")
    assert not isinstance(result, NormalizeError)
    assert result == []


def test_normalize_terminal_run_without_tool_result_returns_controlled_error():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    result = ObservationNormalizer().normalize("toolrun_obs_test")
    assert isinstance(result, NormalizeError)
    assert result.code == "tool_result_not_found"


# ─── ObservationTriage tests ─────────────────────────────────────


def _make_obs(obs_type: str, campaign_id: str = "cmp_obs1", **kwargs) -> Observation:
    obs = Observation(
        observation_id=f"obs_test_{obs_type}",
        campaign_id=campaign_id,
        tool_run_id="toolrun_obs_test",
        type=obs_type,
        **kwargs,
    )
    _store_observation(obs)
    return obs


def test_triage_single_500_creates_replay_minimized_payload_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("unexpected_500", status_code=500)
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "replay_minimized_payload"
    assert triaged.judge_worthy is False
    assert plan is not None
    assert plan.goal == "replay_minimized_payload"
    assert plan.status == "pending"


def test_triage_is_idempotent_for_same_observation():
    _reset_store()
    _create_campaign()
    obs = _make_obs("unexpected_500", status_code=500)
    triaged_1, plan_1, err_1 = ObservationTriage().triage(obs.observation_id)
    triaged_2, plan_2, err_2 = ObservationTriage().triage(obs.observation_id)

    assert err_1 is None
    assert err_2 is None
    assert triaged_1 is not None
    assert triaged_2 is not None
    assert plan_1 is not None
    assert plan_2 is not None
    assert plan_1.verification_plan_id == plan_2.verification_plan_id
    plans = memory_store.list_verification_plans_by_campaign("cmp_obs1")
    matching = [p for p in plans if p.get("parent_observation_id") == obs.observation_id]
    assert len(matching) == 1


def test_triage_cross_role_access_creates_prove_ownership_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("cross_role_access_signal", confidence=0.8)
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "prove_ownership"
    assert triaged.security_relevance == "high"
    assert triaged.judge_worthy is False
    assert plan is not None
    assert plan.goal == "prove_ownership"
    assert "owner_collection_contains_object" in plan.required_evidence


def test_triage_schema_mismatch_store_only_without_impact():
    _reset_store()
    _create_campaign()
    obs = _make_obs("schema_mismatch", details={})
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "store_only"
    assert triaged.judge_worthy is False
    assert plan is None


def test_triage_schema_mismatch_with_impact_creates_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("schema_mismatch", details={"impact": "data_leak"})
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "impact_validation"
    assert plan is not None
    assert plan.goal == "impact_validation"


def test_triage_unsupported_tool_error_store_only():
    _reset_store()
    _create_campaign()
    obs = _make_obs("unsupported_tool_signal")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "store_only"
    assert triaged.judge_worthy is False
    assert plan is None


def test_triage_discovered_endpoint_creates_auth_check_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("discovered_endpoint")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "undocumented_endpoint_auth_check"
    assert plan is not None
    assert plan.goal == "undocumented_endpoint_auth_check"


def test_triage_zap_alert_creates_replay_misconfiguration_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("zap_alert")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "replay_misconfiguration"
    assert plan is not None
    assert plan.goal == "replay_misconfiguration"


def test_triage_validated_security_header_issue_creates_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("validated_security_header_issue")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "prove_security_header_misconfiguration"
    assert triaged.security_relevance == "medium"
    assert triaged.judge_worthy is False
    assert plan is not None
    assert plan.goal == "prove_security_header_misconfiguration"
    assert plan.worker_class == "misconfiguration"
    assert plan.strategy == "prove_security_header_misconfiguration"


def test_triage_nuclei_match_creates_validate_template_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("nuclei_match")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "validate_template_match"
    assert plan is not None
    assert plan.goal == "validate_template_match"


def test_triage_auth_anomaly_creates_auth_replay_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("auth_anomaly")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "auth_replay_validation"
    assert plan is not None
    assert plan.goal == "auth_replay_validation"


def test_triage_hidden_parameter_creates_parameter_replay_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("hidden_parameter")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "parameter_replay_validation"
    assert plan is not None
    assert plan.goal == "parameter_replay_validation"


def test_triage_timeout_signal_is_store_only():
    _reset_store()
    _create_campaign()
    obs = _make_obs("timeout_signal")
    triaged, plan, err = ObservationTriage().triage(obs.observation_id)
    assert err is None
    assert triaged.recommended_next_action == "store_only"
    assert plan is None


def test_no_observation_creates_finding():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())

    ObservationNormalizer().normalize("toolrun_obs_test")
    assert len(memory_store.findings) == 0


def test_no_triage_calls_judge():
    _reset_store()
    _create_campaign()
    obs = _make_obs("cross_role_access_signal", confidence=0.9)
    ObservationTriage().triage(obs.observation_id)
    assert len(memory_store.evidence_records) == 0
    assert len(memory_store.findings) == 0


def test_observation_isolation_per_campaign():
    _reset_store()
    _create_campaign("cmp_a")
    _create_campaign("cmp_b")

    run_a = ToolRun(tool_run_id="toolrun_a", campaign_id="cmp_a", tool_name="t", status=ToolRunStatus.finished)
    run_b = ToolRun(tool_run_id="toolrun_b", campaign_id="cmp_b", tool_name="t", status=ToolRunStatus.finished)
    memory_store.store_tool_run("toolrun_a", "cmp_a", run_a.model_dump(mode="json"))
    memory_store.store_tool_run("toolrun_b", "cmp_b", run_b.model_dump(mode="json"))
    _store_tool_result("toolrun_a", _make_500_result(tool_run_id="toolrun_a", campaign_id="cmp_a"))
    _store_tool_result("toolrun_b", _make_clean_result(tool_run_id="toolrun_b", campaign_id="cmp_b"))

    ObservationNormalizer().normalize("toolrun_a")
    ObservationNormalizer().normalize("toolrun_b")

    assert len(memory_store.list_observations_by_campaign("cmp_a")) == 1
    assert len(memory_store.list_observations_by_campaign("cmp_b")) == 0


def test_observations_linked_to_tool_run():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())

    ObservationNormalizer().normalize("toolrun_obs_test")
    linked = memory_store.list_observations_by_tool_run("toolrun_obs_test")
    assert len(linked) == 1
    assert linked[0]["tool_run_id"] == "toolrun_obs_test"


def test_verification_plan_status_is_pending():
    _reset_store()
    _create_campaign()
    obs = _make_obs("cross_role_access_signal")
    _, plan, _ = ObservationTriage().triage(obs.observation_id)
    assert plan is not None
    assert plan.status == "pending"


# ─── Route-level tests ────────────────────────────────────────────


def _get_test_client():
    from fastapi.testclient import TestClient
    from backend.main import app
    return TestClient(app)


def test_routes_normalize_returns_observations():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())

    client = _get_test_client()
    resp = client.post("/v1/observations/normalize/toolrun_obs_test")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observations_created"] == 1
    assert len(body["observations"]) == 1
    assert body["observations"][0]["type"] == "unexpected_500"


def test_routes_normalize_reports_already_normalized_on_second_call():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())
    client = _get_test_client()

    first = client.post("/v1/observations/normalize/toolrun_obs_test")
    assert first.status_code == 200
    first_body = first.json()
    assert first_body["already_normalized"] is False
    assert first_body["observations_created"] > 0

    second = client.post("/v1/observations/normalize/toolrun_obs_test")
    assert second.status_code == 200
    second_body = second.json()
    assert second_body["already_normalized"] is True
    assert second_body["observations_created"] == 0
    assert len(second_body["observations"]) == len(first_body["observations"])


def test_routes_normalize_404_for_missing_tool_run():
    _reset_store()
    client = _get_test_client()
    resp = client.post("/v1/observations/normalize/toolrun_nonexistent")
    assert resp.status_code == 404
    assert resp.json()["error"] == "tool_run_not_found"


def test_routes_normalize_409_for_running_tool_run():
    _reset_store()
    _create_campaign()
    _store_running_run()

    client = _get_test_client()
    resp = client.post("/v1/observations/normalize/toolrun_running")
    assert resp.status_code == 409
    assert resp.json()["error"] == "tool_run_not_terminal"


def test_routes_normalize_200_for_partial_tool_run():
    _reset_store()
    _create_campaign()
    _store_partial_run()
    tr = ToolResult(
        tool_run_id="toolrun_partial",
        campaign_id="cmp_obs1",
        tool_name="schemathesis_negative_test",
        status="partial",
        observations=[
            ToolResultObservationLite(
                observation_type="schema_mismatch",
                confidence=0.6,
                details={"operation_id": "op_GET_/api/v1/items/{id}"},
            ),
        ],
    )
    _store_tool_result("toolrun_partial", tr)

    client = _get_test_client()
    resp = client.post("/v1/observations/normalize/toolrun_partial")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observations_created"] == 1
    assert body["observations"][0]["type"] == "schema_mismatch"


def test_routes_normalize_tool_result_missing_returns_controlled_error():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    client = _get_test_client()
    resp = client.post("/v1/observations/normalize/toolrun_obs_test")
    assert resp.status_code in {404, 409}
    assert resp.json()["error"] in {"tool_result_not_found", "tool_run_not_terminal"}


def test_routes_triage_returns_observation_and_plan():
    _reset_store()
    _create_campaign()
    obs = _make_obs("unexpected_500", status_code=500)

    client = _get_test_client()
    resp = client.post(f"/v1/observations/triage/{obs.observation_id}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["observation"]["recommended_next_action"] == "replay_minimized_payload"
    assert body["verification_plan"] is not None
    assert body["verification_plan"]["goal"] == "replay_minimized_payload"


def test_routes_triage_404_for_missing_observation():
    _reset_store()
    client = _get_test_client()
    resp = client.post("/v1/observations/triage/obs_nonexistent")
    assert resp.status_code == 404


def test_routes_list_observations_by_campaign():
    _reset_store()
    _create_campaign()
    _store_finished_run()
    _store_tool_result("toolrun_obs_test", _make_500_result())
    ObservationNormalizer().normalize("toolrun_obs_test")

    client = _get_test_client()
    resp = client.get("/v1/observations/cmp_obs1")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["type"] == "unexpected_500"


def test_routes_list_verification_plans_by_campaign():
    _reset_store()
    _create_campaign()
    obs = _make_obs("cross_role_access_signal")
    ObservationTriage().triage(obs.observation_id)

    client = _get_test_client()
    resp = client.get("/v1/verification-plans/cmp_obs1")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 1
    assert body[0]["goal"] == "prove_ownership"
    assert body[0]["status"] == "pending"


def test_observation_model_rejects_invalid_type_and_security_relevance():
    _reset_store()
    _create_campaign()
    try:
        Observation(
            observation_id="obs_bad_type",
            campaign_id="cmp_obs1",
            type="not_a_real_type",
        )
        assert False, "Expected validation error for invalid Observation.type"
    except Exception:
        pass

    try:
        Observation(
            observation_id="obs_bad_sec",
            campaign_id="cmp_obs1",
            type="unexpected_500",
            security_relevance="not_real_relevance",
        )
        assert False, "Expected validation error for invalid Observation.security_relevance"
    except Exception:
        pass

    try:
        VerificationPlan(
            verification_plan_id="vplan_bad_status",
            campaign_id="cmp_obs1",
            goal="x",
            status="not_a_real_status",
        )
        assert False, "Expected validation error for invalid VerificationPlan.status"
    except Exception:
        pass
