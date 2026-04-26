"""Phase 11A — ZapPassiveClient tests.

All tests use mocked httpx transport. No real ZAP/network I/O.
"""
from __future__ import annotations

import httpx

from backend.services.zap_passive_client import ZapPassiveClient, ZapPassiveClientError


def test_zap_passive_client_runs_spider_and_collects_passive_alerts():
    calls: list[str] = []
    statuses = iter(["50", "100"])
    records = iter(["1", "0"])

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        calls.append(path)
        if path == "/JSON/core/view/version/":
            return httpx.Response(200, json={"version": "2.16.1"})
        if path == "/JSON/spider/action/scan/":
            return httpx.Response(200, json={"scan": "scan-1"})
        if path == "/JSON/spider/view/status/":
            return httpx.Response(200, json={"status": next(statuses)})
        if path == "/JSON/core/view/urls/":
            return httpx.Response(200, json={
                "urls": [
                    "http://target.local/api/users",
                    "http://target.local/api/admin",
                ]
            })
        if path == "/JSON/pscan/view/recordsToScan/":
            return httpx.Response(200, json={"recordsToScan": next(records)})
        if path == "/JSON/alert/view/alerts/":
            return httpx.Response(200, json={"alerts": [{
                "alert": "X-Content-Type-Options Header Missing",
                "risk": "Low",
                "confidence": "Medium",
                "url": "http://target.local/api/users",
                "pluginId": "10021",
            }]})
        raise AssertionError(f"Unexpected ZAP endpoint: {path}")

    client = ZapPassiveClient(
        "http://zap:8080",
        transport=httpx.MockTransport(handler),
        sleep_func=lambda _: None,
    )

    result = client.run_discovery_passive(
        target_url="http://target.local",
        max_duration_sec=5,
    )

    assert result.version == "2.16.1"
    assert result.discovered_urls == [
        "http://target.local/api/users",
        "http://target.local/api/admin",
    ]
    assert len(result.alerts) == 1
    assert "/JSON/ascan/action/scan/" not in calls


def test_zap_passive_client_spider_timeout_is_structured():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/JSON/core/view/version/":
            return httpx.Response(200, json={"version": "2.16.1"})
        if request.url.path == "/JSON/spider/action/scan/":
            return httpx.Response(200, json={"scan": "scan-1"})
        if request.url.path == "/JSON/spider/view/status/":
            return httpx.Response(200, json={"status": "1"})
        return httpx.Response(200, json={})

    client = ZapPassiveClient(
        "http://zap:8080",
        transport=httpx.MockTransport(handler),
        sleep_func=lambda _: None,
    )

    try:
        client.run_discovery_passive(
            target_url="http://target.local",
            max_duration_sec=1,
        )
        assert False, "Expected ZapPassiveClientError"
    except ZapPassiveClientError as exc:
        assert exc.code == "zap_spider_timeout"


def test_zap_passive_client_unreachable_is_structured():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    client = ZapPassiveClient(
        "http://zap:8080",
        transport=httpx.MockTransport(handler),
    )

    try:
        client.version()
        assert False, "Expected ZapPassiveClientError"
    except ZapPassiveClientError as exc:
        assert exc.code == "zap_unreachable"


def test_zap_passive_client_passive_timeout_is_structured():
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/JSON/core/view/version/":
            return httpx.Response(200, json={"version": "2.16.1"})
        if path == "/JSON/core/view/urls/":
            return httpx.Response(200, json={"urls": ["http://target.local/api"]})
        if path == "/JSON/pscan/view/recordsToScan/":
            return httpx.Response(200, json={"recordsToScan": "3"})
        return httpx.Response(200, json={})

    client = ZapPassiveClient(
        "http://zap:8080",
        transport=httpx.MockTransport(handler),
        sleep_func=lambda _: None,
    )

    try:
        client.run_discovery_passive(
            target_url="http://target.local",
            use_spider=False,
            max_duration_sec=1,
        )
        assert False, "Expected ZapPassiveClientError"
    except ZapPassiveClientError as exc:
        assert exc.code == "zap_passive_timeout"
