"""Phase 9A — SafeHttpClient and AuthMaterializer tests.

All tests use mocked httpx transports. No real network I/O.
"""
from __future__ import annotations

import json

import httpx

from backend.models.campaign import Campaign
from backend.services.auth_materializer import AuthMaterializer
from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage


def _campaign(**overrides) -> Campaign:
    data = {
        "campaign_id": "cmp_safe_http",
        "target_url": "http://crapi.local:8888",
        "allowed_hosts": ["crapi.local:8888"],
        "roles_json": [
            {
                "name": "owner",
                "headers": {"X-Role": "owner"},
                "cookies": {"session": "owner-secret"},
            },
            {
                "name": "attacker",
                "bearer_token": "attacker-token",
            },
        ],
    }
    data.update(overrides)
    return Campaign(**data)


def test_safe_http_client_rejects_out_of_scope_absolute_url():
    client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))

    result = client.request(_campaign(), method="GET", url="http://evil.local/api")

    assert result.error is not None
    assert result.error.code == "host_not_allowed"


def test_safe_http_client_rejects_when_allowed_hosts_empty():
    client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))

    result = client.request(
        _campaign(allowed_hosts=[]),
        method="GET",
        url="http://crapi.local:8888/api",
    )

    assert result.error is not None
    assert result.error.code == "allowed_hosts_not_configured"


def test_safe_http_client_resolves_relative_url_against_campaign_target():
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json={"id": "veh_123"})

    client = SafeHttpClient(transport=httpx.MockTransport(handler))

    result = client.request(_campaign(), method="GET", url="/api/v1/vehicles/veh_123")

    assert result.error is None
    assert seen == ["http://crapi.local:8888/api/v1/vehicles/veh_123"]
    assert result.response_body == {"id": "veh_123"}


def test_safe_http_client_exact_host_matching_with_port_support():
    ok_client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))

    ok = ok_client.request(
        _campaign(allowed_hosts=["crapi.local:8888"]),
        method="GET",
        url="http://crapi.local:8888/api",
    )
    blocked = ok_client.request(
        _campaign(allowed_hosts=["crapi.local"]),
        method="GET",
        url="http://evil-crapi.local/api",
    )

    assert ok.error is None
    assert blocked.error is not None
    assert blocked.error.code == "host_not_allowed"


def test_safe_http_client_rejects_malicious_suffix_host():
    client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))

    result = client.request(
        _campaign(allowed_hosts=["crapi.local"]),
        method="GET",
        url="http://evil-crapi.local/api",
    )

    assert result.error is not None
    assert result.error.code == "host_not_allowed"


def test_safe_http_client_rejects_redirect_outside_allowed_host():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "http://evil.local/callback"})

    client = SafeHttpClient(transport=httpx.MockTransport(handler))

    result = client.request(_campaign(), method="GET", url="/api")

    assert result.error is not None
    assert result.error.code == "redirect_host_not_allowed"


def test_safe_http_client_follow_redirects_true_returns_controlled_error():
    client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200)))

    result = client.request(
        _campaign(),
        method="GET",
        url="/api",
        follow_redirects=True,
    )

    assert result.error is not None
    assert result.error.code == "redirect_not_supported"


def test_safe_http_client_response_size_limit_maps_to_error():
    client = SafeHttpClient(
        transport=httpx.MockTransport(lambda req: httpx.Response(200, content=b"x" * 20)),
        max_response_bytes=10,
    )

    result = client.request(_campaign(), method="GET", url="/api")

    assert result.error is not None
    assert result.error.code == "response_too_large"


def test_safe_http_client_timeout_maps_to_error():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    client = SafeHttpClient(transport=httpx.MockTransport(handler))

    result = client.request(_campaign(), method="GET", url="/api", timeout_sec=0.01)

    assert result.error is not None
    assert result.error.code == "timeout"


def test_safe_http_client_redacts_headers_cookies_and_body_metadata():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer secret"
        assert request.headers["cookie"] == "session=cookie-secret"
        return httpx.Response(200, json={"access_token": "response-secret", "id": "veh_123"})

    client = SafeHttpClient(transport=httpx.MockTransport(handler))

    result = client.request(
        _campaign(),
        method="POST",
        url="/api",
        headers={"Authorization": "Bearer secret"},
        cookies={"session": "cookie-secret"},
        body={"password": "body-secret", "name": "safe"},
    )

    assert result.error is None
    assert result.request_headers_redacted["Authorization"] == "<redacted>"
    assert result.request_cookies_redacted["session"] == "<redacted>"
    assert result.request_body_redacted["password"] == "<redacted>"
    assert result.response_body["access_token"] == "<redacted>"


def test_safe_http_client_storage_url_sanitized_userinfo_query():
    client = SafeHttpClient(transport=httpx.MockTransport(lambda req: httpx.Response(200, json={"id": "veh_123"})))

    result = client.request(
        _campaign(allowed_hosts=["crapi.local:8888"]),
        method="GET",
        url="http://user:pass@crapi.local:8888/api/v1/vehicles/veh_123?token=abc&id=123",
    )

    assert result.error is None
    assert "user:pass@" not in result.url
    assert "token=abc" not in result.url
    assert "id=123" not in result.url
    assert result.url.endswith("?token=%3Credacted%3E&id=%3Credacted%3E")
    assert sanitize_url_for_storage("http://user:pass@crapi.local:8888/a?x=1") == (
        "http://crapi.local:8888/a?x=%3Credacted%3E"
    )


def test_safe_http_client_parses_set_cookie_flags_into_safe_summaries():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[
                ("Set-Cookie", "sessionid=abc123; HttpOnly; Secure; SameSite=Lax"),
                ("Set-Cookie", "prefs=dark; SameSite=None"),
            ],
            json={"ok": True},
        )

    client = SafeHttpClient(transport=httpx.MockTransport(handler))
    result = client.request(_campaign(), method="GET", url="/api")

    assert result.error is None
    assert len(result.cookie_summaries) == 2
    assert result.cookie_summaries[0]["has_httponly"] is True
    assert result.cookie_summaries[0]["has_secure"] is True
    assert result.cookie_summaries[0]["samesite_state"] == "lax"
    assert result.cookie_summaries[1]["has_httponly"] is False
    assert result.cookie_summaries[1]["has_secure"] is False
    assert result.cookie_summaries[1]["samesite_state"] == "none"


def test_safe_http_client_cookie_summaries_do_not_leak_raw_cookie_names_or_values():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers=[("Set-Cookie", "VerySensitiveSession=super-secret-token; Secure; SameSite=Strict")],
            json={"ok": True},
        )

    client = SafeHttpClient(transport=httpx.MockTransport(handler))
    result = client.request(_campaign(), method="GET", url="/api")

    blob = json.dumps({"cookie_summaries": result.cookie_summaries}, sort_keys=True).lower()
    assert "verysensitivesession" not in blob
    assert "super-secret-token" not in blob
    assert "set-cookie" not in blob
    assert "cookie_name_hash" in blob


def test_auth_materializer_applies_headers_bearer_and_cookies():
    materializer = AuthMaterializer()

    owner, owner_error = materializer.materialize(_campaign(), "owner")
    attacker, attacker_error = materializer.materialize(_campaign(), "attacker")

    assert owner_error is None
    assert owner is not None
    assert owner.headers["X-Role"] == "owner"
    assert owner.cookies["session"] == "owner-secret"
    assert owner.redacted()["cookies"]["session"] == "<redacted>"
    assert attacker_error is None
    assert attacker is not None
    assert attacker.headers["Authorization"] == "Bearer attacker-token"
    assert attacker.redacted()["headers"]["Authorization"] == "<redacted>"


def test_auth_materializer_missing_role_returns_controlled_error():
    auth, error = AuthMaterializer().materialize(_campaign(), "ghost")

    assert auth is None
    assert error is not None
    assert error.code == "auth_profile_not_found"
