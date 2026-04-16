from backend.models.discovery import DiscoveryRequest
from backend.services.discovery_service import DiscoveryService


def test_discovery_normalizes_uuid_to_id() -> None:
    service = DiscoveryService()

    surface = service._normalize_urls(
        ["http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location"]
    )

    assert len(surface.endpoints) == 1
    endpoint = surface.endpoints[0]
    assert endpoint.path == "/identity/api/v2/vehicle/{id}/location"
    assert endpoint.path_params == ["id"]
    assert endpoint.object_id_candidates == ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"]


def test_discovery_normalizes_numeric_id_to_id() -> None:
    service = DiscoveryService()

    surface = service._normalize_urls(["http://host.docker.internal:8888/users/123/profile"])

    assert surface.endpoints[0].path == "/users/{id}/profile"
    assert surface.endpoints[0].object_id_candidates == ["123"]


def test_discovery_extracts_query_params() -> None:
    service = DiscoveryService()

    surface = service._normalize_urls(
        ["http://host.docker.internal:8888/search?q=test&sort=desc"]
    )

    endpoint = surface.endpoints[0]
    assert endpoint.path == "/search"
    assert endpoint.query_params == ["q", "sort"]


def test_discovery_request_model_defaults() -> None:
    request = DiscoveryRequest(target_url="http://host.docker.internal:8888")

    assert request.discovery_mode == "zap"
    assert request.zap_base_url == "http://zap:8080"


def test_discovery_prefers_api_like_urls_and_filters_noise() -> None:
    service = DiscoveryService()

    filtered = service._filter_urls(
        raw_urls=[
            "http://host.docker.internal:8888/",
            "http://host.docker.internal:8888/robots.txt",
            "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
        ],
        target_url="http://host.docker.internal:8888",
        allowed_hosts=["host.docker.internal:8888"],
        discovery_seeds=["/identity/api"],
    )

    assert filtered == ["http://host.docker.internal:8888/identity/api/v2/vehicle/123/location"]


def test_discovery_builds_absolute_seed_urls() -> None:
    service = DiscoveryService()

    seeds = service._build_seed_urls(
        target_url="http://host.docker.internal:8888",
        discovery_seeds=["/identity/api", "http://host.docker.internal:8888/community/api"],
    )

    assert seeds == [
        "http://host.docker.internal:8888/identity/api",
        "http://host.docker.internal:8888/community/api",
    ]


def test_discovery_extracts_auth_headers_from_roles() -> None:
    service = DiscoveryService()

    headers, cookies, role_name = service._build_authenticated_seed_context(
        [
            {
                "name": "user_a",
                "token": "abc123",
                "auth_headers": {"X-Test": "1"},
                "cookies": {"session": "cookie123"},
            }
        ],
        True,
    )

    assert headers["Authorization"] == "Bearer abc123"
    assert headers["X-Test"] == "1"
    assert cookies == {"session": "cookie123"}
    assert role_name == "user_a"
