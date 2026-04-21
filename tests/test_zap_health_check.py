from fastapi.testclient import TestClient

from backend.main import app
from backend.models.discovery import DiscoveryRequest
from backend.services.discovery_service import DiscoveryService


def test_zap_health_check_zap_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.services.discovery_service.ZapClient.health_check",
        lambda self, target_url, max_duration_sec=15: {
            "zap_reachable": False,
            "zap_version": None,
            "target_reachable_from_backend": False,
            "target_reachable_from_zap": False,
            "spider_completed": False,
            "urls_discovered": 0,
            "api_like_urls": 0,
            "diagnosis": "",
            "recommendation": "",
            "stage": "connect_zap",
            "error": "[Errno 111] Connection refused",
            "raw_urls": [],
            "spider_status": "",
            "only_static_content_detected": False,
            "zap_base_url": "http://zap:8080",
            "target_url": target_url,
        },
    )
    monkeypatch.setattr(DiscoveryService, "_target_reachable_from_backend", lambda self, target_url, allowed_hosts: False)

    response = TestClient(app).post(
        "/v1/recon/zap-health-check",
        json={"target_url": "http://host.docker.internal:8888", "zap_base_url": "http://zap:8080"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["zap_reachable"] is False
    assert body["stage"] == "connect_zap"
    assert "Connection refused" in body["error"]


def test_zap_health_check_target_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.services.discovery_service.ZapClient.health_check",
        lambda self, target_url, max_duration_sec=15: {
            "zap_reachable": True,
            "zap_version": "2.17.0",
            "target_reachable_from_backend": False,
            "target_reachable_from_zap": False,
            "spider_completed": False,
            "urls_discovered": 0,
            "api_like_urls": 0,
            "diagnosis": "",
            "recommendation": "",
            "stage": "reach_target_from_zap",
            "error": "target timeout",
            "raw_urls": [],
            "spider_status": "",
            "only_static_content_detected": False,
            "zap_base_url": "http://zap:8080",
            "target_url": target_url,
        },
    )
    monkeypatch.setattr(DiscoveryService, "_target_reachable_from_backend", lambda self, target_url, allowed_hosts: False)

    response = TestClient(app).post(
        "/v1/recon/zap-health-check",
        json={"target_url": "http://host.docker.internal:8888", "zap_base_url": "http://zap:8080"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["zap_reachable"] is True
    assert body["target_reachable_from_zap"] is False
    assert body["stage"] == "reach_target_from_zap"


def test_zap_health_check_spider_empty(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.services.discovery_service.ZapClient.health_check",
        lambda self, target_url, max_duration_sec=15: {
            "zap_reachable": True,
            "zap_version": "2.17.0",
            "target_reachable_from_backend": True,
            "target_reachable_from_zap": True,
            "spider_completed": True,
            "urls_discovered": 0,
            "api_like_urls": 0,
            "diagnosis": "no_urls_discovered",
            "recommendation": "verify_target_routing_or_try_browser_capture",
            "stage": "collect_urls",
            "error": "spider_returned_no_urls",
            "raw_urls": [],
            "spider_status": "100",
            "only_static_content_detected": False,
            "zap_base_url": "http://zap:8080",
            "target_url": target_url,
        },
    )
    monkeypatch.setattr(DiscoveryService, "_target_reachable_from_backend", lambda self, target_url, allowed_hosts: True)

    response = TestClient(app).post(
        "/v1/recon/zap-health-check",
        json={"target_url": "http://host.docker.internal:8888", "zap_base_url": "http://zap:8080"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["spider_completed"] is True
    assert body["urls_discovered"] == 0
    assert body["diagnosis"] == "no_urls_discovered"


def test_zap_health_check_static_only(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.services.discovery_service.ZapClient.health_check",
        lambda self, target_url, max_duration_sec=15: {
            "zap_reachable": True,
            "zap_version": "2.17.0",
            "target_reachable_from_backend": True,
            "target_reachable_from_zap": True,
            "spider_completed": True,
            "urls_discovered": 3,
            "api_like_urls": 0,
            "diagnosis": "only_static_content_detected",
            "recommendation": "use_browser_capture_or_authenticated_discovery",
            "stage": "",
            "error": "",
            "raw_urls": ["http://host/", "http://host/static/app.js", "http://host/images/logo.png"],
            "spider_status": "100",
            "only_static_content_detected": True,
            "zap_base_url": "http://zap:8080",
            "target_url": target_url,
        },
    )
    monkeypatch.setattr(DiscoveryService, "_target_reachable_from_backend", lambda self, target_url, allowed_hosts: True)

    response = TestClient(app).post(
        "/v1/recon/zap-health-check",
        json={"target_url": "http://host.docker.internal:8888", "zap_base_url": "http://zap:8080"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["only_static_content_detected"] is True
    assert body["diagnosis"] == "only_static_content_detected"


def test_zap_health_check_normal_case(monkeypatch) -> None:
    monkeypatch.setattr(
        "backend.services.discovery_service.ZapClient.health_check",
        lambda self, target_url, max_duration_sec=15: {
            "zap_reachable": True,
            "zap_version": "2.17.0",
            "target_reachable_from_backend": True,
            "target_reachable_from_zap": True,
            "spider_completed": True,
            "urls_discovered": 12,
            "api_like_urls": 4,
            "diagnosis": "ok",
            "recommendation": "proceed_with_discovery",
            "stage": "completed",
            "error": "",
            "raw_urls": ["http://host.docker.internal:8888/identity/api"],
            "spider_status": "100",
            "only_static_content_detected": False,
            "zap_base_url": "http://zap:8080",
            "target_url": target_url,
        },
    )
    monkeypatch.setattr(DiscoveryService, "_target_reachable_from_backend", lambda self, target_url, allowed_hosts: True)

    response = TestClient(app).post(
        "/v1/recon/zap-health-check",
        json={"target_url": "http://host.docker.internal:8888", "zap_base_url": "http://zap:8080"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["zap_reachable"] is True
    assert body["target_reachable_from_zap"] is True
    assert body["urls_discovered"] == 12
    assert body["api_like_urls"] == 4
    assert body["diagnosis"] == "ok"


def test_discovery_aborts_with_diagnostics_when_zap_unreachable(monkeypatch) -> None:
    monkeypatch.setattr(
        DiscoveryService,
        "zap_health_check",
        lambda self, request: {
            "zap_reachable": False,
            "target_reachable_from_backend": True,
            "target_reachable_from_zap": False,
            "stage": "connect_zap",
            "error": "[Errno 111] Connection refused",
            "urls_discovered": 0,
            "api_like_urls": 0,
            "spider_status": "",
            "zap_base_url": request.zap_base_url,
            "target_url": str(request.target_url),
        },
    )
    response = DiscoveryService().discover(
        DiscoveryRequest(
            target_url="http://host.docker.internal:8888",
            allowed_hosts=["host.docker.internal:8888"],
            zap_base_url="http://zap:8080",
        )
    )
    assert response.normalized_surface.endpoints == []
    assert response.raw_metadata["diagnosis"] == "zap_unreachable"
    assert response.raw_metadata["zap_diagnostics"]["zap_reachable"] is False
