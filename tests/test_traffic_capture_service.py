from backend.models.traffic_discovery import TrafficDiscoveryRequest
from backend.services.traffic_capture_service import TrafficCaptureService


def test_traffic_capture_normalizes_observed_request_and_auth_signals() -> None:
    service = TrafficCaptureService()

    response = service.capture(
        TrafficDiscoveryRequest(
            requests=[
                {
                    "method": "GET",
                    "url": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location?expand=owner",
                    "headers": {"Authorization": "Bearer token-a"},
                    "query_params": {"expand": "owner"},
                    "json_body": None,
                }
            ]
        )
    )

    assert len(response.normalized_surface.endpoints) == 1
    endpoint = response.normalized_surface.endpoints[0]
    assert endpoint.path == "/identity/api/v2/vehicle/{id}/location"
    assert endpoint.method == "GET"
    assert endpoint.query_params == ["expand"]
    assert endpoint.object_id_candidates == ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"]
    assert endpoint.auth_required is True
    assert endpoint.auth_signals.has_auth_header is True
    assert endpoint.sources == ["traffic"]
