from types import SimpleNamespace

import httpx

from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
from backend.models.testing import ExecutionContext
from backend.models.traffic_discovery import ObservedHttpRequest, TrafficDiscoveryRequest
from backend.services.capability_inference_service import CapabilityInferenceService
from backend.services.discovery_service import DiscoveryService
from backend.services.openapi_service import OpenAPIService
from backend.services.task_generator import TaskGenerator
from backend.services.traffic_capture_service import TrafficCaptureService


def test_openapi_auto_discovery_path_selection(monkeypatch) -> None:
    seen_urls: list[str] = []

    def fake_get(url: str, timeout: float, follow_redirects: bool):
        seen_urls.append(url)
        if url.endswith("/v3/api-docs"):
            return SimpleNamespace(
                status_code=200,
                text='{"openapi":"3.0.0","paths":{"/identity/api/auth/login":{"post":{}}}}',
            )
        return SimpleNamespace(status_code=404, text="not found")

    monkeypatch.setattr(httpx, "get", fake_get)

    response = OpenAPIService().parse(
        SimpleNamespace(
            target_url="http://example.test",
            openapi_url=None,
            openapi_spec_text=None,
            roles=[],
        )
    )

    assert any(url.endswith("/openapi.json") for url in seen_urls)
    assert any(url.endswith("/v3/api-docs") for url in seen_urls)
    assert response.raw_metadata["source"] == "openapi_autodiscovery"
    assert response.raw_metadata["openapi_url"].endswith("/v3/api-docs")
    assert response.endpoints[0].path == "/identity/api/auth/login"


def test_discovery_service_generates_default_seeds() -> None:
    service = DiscoveryService()
    seeds = service._effective_discovery_seeds([])
    assert "/api" in seeds
    assert "/identity" in seeds
    assert "/payment" in seeds


def test_autonomous_traffic_capture_generates_surface_when_user_requests_missing(monkeypatch) -> None:
    service = TrafficCaptureService()

    monkeypatch.setattr(
        service,
        "_generate_anonymous_requests",
        lambda request: (
            [
                ObservedHttpRequest(
                    method="GET",
                    url="http://example.test/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
                    headers={},
                    cookies={},
                    query_params={},
                    json_body=None,
                )
            ],
            {
                "candidate_path_total": 14,
                "attempted_path_total": 1,
                "accepted_paths": ["/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location"],
                "rejected_paths_with_reasons": [],
            },
        ),
    )

    response = service.capture(
        TrafficDiscoveryRequest(
            requests=[],
            target_url="http://example.test",
            allowed_hosts=["example.test"],
            allow_autonomous_capture=True,
        )
    )

    assert response.raw_metadata["generation_mode"] == "autonomous_anonymous"
    assert response.raw_metadata["generated_request_total"] == 1
    assert response.normalized_surface.endpoints[0].path == "/identity/api/v2/vehicle/{id}/location"


def test_observed_traffic_import_without_requests_is_safe_noop(monkeypatch) -> None:
    service = TrafficCaptureService()

    def fail_if_called(request):
        raise AssertionError("anonymous probing should require allow_autonomous_capture=True")

    monkeypatch.setattr(service, "_generate_anonymous_requests", fail_if_called)

    response = service.capture(
        TrafficDiscoveryRequest(
            requests=[],
            target_url="http://example.test",
            allowed_hosts=["example.test"],
        )
    )

    assert response.raw_metadata["generation_mode"] == "empty_observed_traffic"
    assert response.raw_metadata["observed_request_total"] == 0
    assert response.normalized_surface.endpoints == []


def test_capability_inference_with_no_roles_and_no_user_traffic() -> None:
    capabilities = CapabilityInferenceService().infer(
        execution_context=ExecutionContext(target_url="http://example.test", roles=[], traffic_requests=[]),
        normalized_surface=NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/auth/login",
                    method="POST",
                    sources=["discovery"],
                    candidate_classes=["authorization"],
                )
            ]
        ),
    )

    assert capabilities["has_api_surface"] is True
    assert capabilities["has_auth_profiles"] is False
    assert capabilities["has_login_endpoint"] is True
    assert capabilities["has_discovery_surface"] is True


def test_auth_task_prefers_auto_provision_when_auth_entrypoints_discovered() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/auth/signup",
                    method="POST",
                    candidate_classes=["authorization"],
                    resource_signals=ResourceSignals(),
                ),
                NormalizedEndpoint(
                    path="/identity/api/auth/login",
                    method="POST",
                    candidate_classes=["authorization"],
                    resource_signals=ResourceSignals(),
                ),
            ]
        ),
        roles=[],
        capabilities={
            "has_auth_profiles": False,
            "has_multi_role_auth": False,
            "has_register_endpoint": True,
            "has_login_endpoint": True,
            "has_api_surface": True,
        },
    )

    assert any(task["allowed_tools"] == ["auto_provision"] for task in tasks)


def test_auth_task_reaches_auth_test_access_after_object_prepared() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/orders/{id}",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=["ord-001"],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[{"name": "user_auto_a", "token": "a"}, {"name": "user_auto_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": True,
            "has_prepared_object": True,
            "has_api_surface": True,
        },
    )

    assert tasks[0]["readiness"] == "ready_to_test"
    assert tasks[0]["allowed_tools"] == ["auth_test_access"]
