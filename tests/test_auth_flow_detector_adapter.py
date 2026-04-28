from __future__ import annotations

import json

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.auth_flow_detector_adapter import AuthFlowDetectorAdapter
from backend.storage.memory_store import memory_store


def _reset() -> None:
    memory_store.graphs_by_campaign.clear()
    memory_store.campaigns.clear()


def _campaign() -> Campaign:
    c = Campaign(
        campaign_id="cmp_afd",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign("cmp_afd", c.model_dump(mode="json"))
    return c


def _cmd() -> WorkerCommand:
    return WorkerCommand(
        campaign_id="cmp_afd",
        worker_class="auth_context",
        strategy="detect_auth_flow",
        tool_name="auth_flow_detector",
        operation_id="",
        inputs={"validation_mode": "auth_flow_detection", "max_operations_scanned": 200},
        budget=CommandBudget(max_requests=0, timeout_sec=10),
    )


def test_auth_flow_detects_signup_from_path_and_email_password() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/v1/signup",
                method="POST",
                path_template="/api/v1/signup",
                body_fields=["email", "password", "name"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr1")
    assert r.status == "finished"
    assert len(r.observations) == 1
    det = r.observations[0].details
    assert det.get("auth_flow_detected") is True
    assert len(det.get("signup_candidates") or []) >= 1


def test_auth_flow_detects_login_from_path_and_credentials() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/auth/login",
                method="POST",
                path_template="/api/auth/login",
                body_fields=["username", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr2")
    det = r.observations[0].details
    assert len(det.get("login_candidates") or []) >= 1


def test_auth_flow_detects_token_response_from_response_fields() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/oauth/token",
                method="POST",
                path_template="/oauth/token",
                body_fields=["grant_type"],
                response_fields=["access_token", "expires_in"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr3")
    det = r.observations[0].details
    assert len(det.get("token_response_candidates") or []) >= 1


def test_auth_flow_detects_profile_me_get() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/me",
                method="GET",
                path_template="/api/v1/me",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr4")
    det = r.observations[0].details
    assert len(det.get("profile_candidates") or []) >= 1


def test_auth_flow_no_candidates_sets_detected_false() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_GET_/api/v1/health",
                method="GET",
                path_template="/api/v1/health",
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr5")
    det = r.observations[0].details
    assert det.get("auth_flow_detected") is False
    assert "no_auth_flow_patterns" in (det.get("reason_codes") or [])


def test_normal_login_candidate_includes_plain_login_path() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/v1/auth/login",
                method="POST",
                path_template="/api/v1/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr_login_plain")
    det = r.observations[0].details
    kinds = [c.get("path") for c in (det.get("login_candidates") or [])]
    assert "/api/v1/auth/login" in kinds


def test_check_otp_not_in_normal_login_candidates() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/auth/v2/check-otp",
                method="POST",
                path_template="/api/auth/v2/check-otp",
                body_fields=["email", "password", "otp"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr_otp")
    det = r.observations[0].details
    assert not det.get("login_candidates")
    assert len(det.get("otp_candidates") or []) >= 1


def test_forget_password_not_in_normal_login_candidates() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/auth/forget-password",
                method="POST",
                path_template="/api/auth/forget-password",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr_fp")
    det = r.observations[0].details
    assert not det.get("login_candidates")
    assert len(det.get("password_reset_candidates") or []) >= 1


def test_login_with_token_not_in_normal_login_candidates() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/v4/user/login-with-token",
                method="POST",
                path_template="/api/v4/user/login-with-token",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr_lwt")
    det = r.observations[0].details
    assert not det.get("login_candidates")
    assert len(det.get("token_login_candidates") or []) >= 1


def test_auth_flow_no_raw_leakage() -> None:
    _reset()
    _campaign()
    graph = ApiGraph(
        campaign_id="cmp_afd",
        operations=[
            Operation(
                operation_id="op_POST_/api/register",
                method="POST",
                path_template="/api/register",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_afd", graph.model_dump(mode="json"))
    r = AuthFlowDetectorAdapter().execute(_cmd(), _campaign(), "tr6")
    blob = json.dumps(r.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("secret", "bearer ", "authorization", "set-cookie", "response_body", "request_body"):
        assert bad not in blob
