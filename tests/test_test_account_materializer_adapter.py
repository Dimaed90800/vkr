from __future__ import annotations

import json

import httpx

from backend.models.api_graph import ApiGraph, Operation
from backend.models.campaign import Campaign, CampaignLimits
from backend.models.worker_command import CommandBudget, WorkerCommand
from backend.services.adapters.test_account_materializer_adapter import TestAccountMaterializerAdapter
from backend.services.auth_profile_store import AuthProfileStore
from backend.services.http.safe_http_client import SafeHttpClient
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
    ]:
        getattr(memory_store, name).clear()


def _campaign() -> Campaign:
    campaign = Campaign(
        campaign_id="cmp_authmat",
        target_url="http://target.local",
        allowed_hosts=["target.local"],
        limits=CampaignLimits(max_requests=100, max_duration_sec=60),
    )
    memory_store.store_campaign(campaign.campaign_id, campaign.model_dump(mode="json"))
    return campaign


def _store_graph() -> None:
    graph = ApiGraph(
        campaign_id="cmp_authmat",
        operations=[
            Operation(
                operation_id="op_POST_/identity/api/auth/signup",
                method="POST",
                path_template="/identity/api/auth/signup",
                body_fields=["name", "email", "number", "password"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/identity/api/auth/login",
                method="POST",
                path_template="/identity/api/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_authmat", graph.model_dump(mode="json"))


def _command(**inputs_overrides) -> WorkerCommand:
    inputs = {
        "target_url": "http://target.local",
        "signup_operation_id": "op_POST_/identity/api/auth/signup",
        "login_operation_id": "op_POST_/identity/api/auth/login",
        "validation_mode": "test_account_materialization",
        "max_accounts": 2,
        "max_response_bytes": 262144,
    }
    inputs.update(inputs_overrides)
    return WorkerCommand(
        campaign_id="cmp_authmat",
        worker_class="auth_context",
        strategy="materialize_test_accounts",
        tool_name="test_account_materializer",
        operation_id="op_POST_/identity/api/auth/signup",
        inputs=inputs,
        budget=CommandBudget(max_requests=6, timeout_sec=15),
    )


def test_successful_signup_login_creates_two_auth_profiles() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/signup"):
            return httpx.Response(201, json={"status": "created"})
        return httpx.Response(200, json={"token": f"tok-{request.content.decode('utf-8').count('@')}"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_command(), campaign, "toolrun_authmat_ok")
    assert result.status == "finished"
    assert len(result.observations) == 1
    details = result.observations[0].details
    assert details["auth_profiles_created_count"] == 2
    assert details["signup_success_count"] == 2
    assert details["login_success_count"] == 2
    assert details["owner_auth_profile_id"].startswith("authprof_")
    assert details["attacker_auth_profile_id"].startswith("authprof_")


def test_token_extracted_from_access_token_field() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/signup"):
            return httpx.Response(201, json={"status": "created"})
        return httpx.Response(200, json={"access_token": "access-secret-123"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_command(), campaign, "toolrun_authmat_token")
    details = result.observations[0].details
    store = AuthProfileStore()
    owner_profile = memory_store.get_auth_profile(details["owner_auth_profile_id"])
    assert owner_profile is not None
    assert store.get_token_by_ref(str(owner_profile.get("token_ref") or "")) == "access-secret-123"


def test_signup_failure_returns_safe_result_without_raw_leakage() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph()

    def handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "bad signup", "token": "should-not-leak"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_command(), campaign, "toolrun_authmat_signup_fail")
    assert result.status == "finished"
    details = result.observations[0].details
    assert details["auth_profiles_created_count"] == 0
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    for bad in ("should-not-leak", "authorization", "cookie", "set-cookie", "bearer ", "response_body", "request_body"):
        assert bad not in blob
    assert "Vkr!" not in blob
    assert "@example.test" not in blob


def test_payload_generation_covers_email_password_name_and_number() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph()
    captured: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8") or "{}")
        captured.append(body)
        if request.url.path.endswith("/signup"):
            return httpx.Response(201, json={"status": "created"})
        return httpx.Response(200, json={"jwt": "jwt-secret"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    adapter.execute(_command(), campaign, "toolrun_authmat_payload")
    signup_payload = captured[0]
    login_payload = captured[1]
    assert "email" in signup_payload and str(signup_payload["email"]).endswith("@example.test")
    assert "password" in signup_payload and signup_payload["password"]
    assert "name" in signup_payload and "vkr" in str(signup_payload["name"]).lower()
    assert "number" in signup_payload and str(signup_payload["number"]).isdigit()
    assert set(login_payload) == {"email", "password"}


def test_no_observations_when_login_fails_keeps_safe_artifact_only_metadata() -> None:
    _reset_store()
    campaign = _campaign()
    _store_graph()

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/signup"):
            return httpx.Response(201, json={"status": "created"})
        return httpx.Response(401, json={"message": "invalid credentials", "token": "never-store-this"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_command(), campaign, "toolrun_authmat_login_fail")
    assert result.status == "finished"
    details = result.observations[0].details
    assert details["login_success_count"] == 0
    assert details["auth_profiles_created_count"] == 0
    artifact = memory_store.list_artifacts_by_run("toolrun_authmat_login_fail")[0]
    blob = json.dumps({"details": details, "artifact": artifact}, sort_keys=True).lower()
    for bad in ("never-store-this", "authorization", "cookie", "set-cookie", "bearer ", "response_body", "request_body", "headers"):
        assert bad not in blob
    assert "Vkr!" not in blob
    assert "@example.test" not in blob


def _graph_with_distractions() -> None:
    graph = ApiGraph(
        campaign_id="cmp_authmat",
        operations=[
            Operation(
                operation_id="op_POST_/svc/mechanic/signup",
                method="POST",
                path_template="/svc/mechanic/signup",
                body_fields=["email", "password", "name"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/svc/auth/v2/check-otp",
                method="POST",
                path_template="/svc/auth/v2/check-otp",
                body_fields=["email", "password", "otp"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/svc/api/auth/signup",
                method="POST",
                path_template="/svc/api/auth/signup",
                body_fields=["name", "email", "number", "password"],
                sources=["openapi"],
            ),
            Operation(
                operation_id="op_POST_/svc/api/auth/login",
                method="POST",
                path_template="/svc/api/auth/login",
                body_fields=["email", "password"],
                sources=["openapi"],
            ),
        ],
    )
    memory_store.store_graph_for_campaign("cmp_authmat", graph.model_dump(mode="json"))


def test_materializer_prefers_generic_auth_signup_login_over_mechanic_and_check_otp() -> None:
    _reset_store()
    campaign = _campaign()
    _graph_with_distractions()
    captured: list[tuple[str, dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8") or "{}")
        captured.append((request.url.path, body))
        if "signup" in request.url.path:
            return httpx.Response(201, json={"ok": True})
        return httpx.Response(200, json={"token": "tok-x"})

    cmd = _command(
        signup_operation_id="op_POST_/svc/mechanic/signup",
        login_operation_id="op_POST_/svc/auth/v2/check-otp",
    )
    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(cmd, campaign, "toolrun_pick_pair")
    det = result.observations[0].details
    assert det["signup_operation_id"] == "op_POST_/svc/api/auth/signup"
    assert det["login_operation_id"] == "op_POST_/svc/api/auth/login"
    assert det.get("selected_signup_path") == "/svc/api/auth/signup"
    assert det.get("selected_login_path") == "/svc/api/auth/login"
    paths = [p for p, _ in captured]
    assert "/svc/api/auth/signup" in paths
    assert "/svc/api/auth/login" in paths


def test_materializer_login_reuses_signup_credentials_per_identity() -> None:
    _reset_store()
    campaign = _campaign()
    _graph_with_distractions()
    pairs: list[tuple[dict[str, object], dict[str, object]]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content.decode("utf-8") or "{}")
        if "signup" in request.url.path:
            pairs.append((body, {}))
            return httpx.Response(201, json={"ok": True})
        login_body = body
        su, _ = pairs[-1]
        pairs[-1] = (su, login_body)
        return httpx.Response(200, json={"token": "tok"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    adapter.execute(_command(), campaign, "toolrun_reuse")
    for signup_body, login_body in pairs:
        assert signup_body.get("email") == login_body.get("email")
        assert signup_body.get("password") == login_body.get("password")


def test_materializer_login_403_adds_reason_codes_and_selected_login_path() -> None:
    _reset_store()
    campaign = _campaign()
    _graph_with_distractions()

    def handler(request: httpx.Request) -> httpx.Response:
        if "signup" in request.url.path:
            return httpx.Response(201, json={"ok": True})
        return httpx.Response(403, json={"error": "forbidden"})

    adapter = TestAccountMaterializerAdapter(
        http_client=SafeHttpClient(transport=httpx.MockTransport(handler))
    )
    result = adapter.execute(_command(), campaign, "toolrun_403")
    det = result.observations[0].details
    assert det.get("login_success_count") == 0
    assert "login_http_403" in det.get("reason_codes", [])
    assert "possible_invalid_credentials_or_wrong_login_endpoint" in det.get("reason_codes", [])
    assert det.get("selected_login_path") == "/svc/api/auth/login"
    blob = json.dumps(result.model_dump(mode="json"), sort_keys=True).lower()
    assert "forbidden" not in blob
    assert "Vkr!" not in blob
