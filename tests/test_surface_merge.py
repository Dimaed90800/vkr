from backend.models.api_surface import (
    CandidateScores,
    NormalizedApiSurface,
    NormalizedEndpoint,
    ResourceSignals,
)
from backend.services.surface_merge_service import SurfaceMergeService


def test_merge_prefers_openapi_but_keeps_discovery_object_candidates() -> None:
    service = SurfaceMergeService()
    openapi_surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/identity/api/v2/vehicle/{id}/location",
                method="GET",
                path_params=["id"],
                query_params=[],
                body_fields=[],
                auth_required=True,
                security_schemes=["bearerAuth"],
                object_param_name="carId",
                object_id_candidates=[],
                resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                candidate_scores=CandidateScores(authorization=0.9),
                candidate_classes=["authorization"],
            )
        ]
    )
    discovery_surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/identity/api/v2/vehicle/{id}/location",
                method="GET",
                path_params=["id"],
                query_params=[],
                body_fields=[],
                auth_required=False,
                security_schemes=[],
                object_param_name="id",
                object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                candidate_scores=CandidateScores(authorization=0.9),
                candidate_classes=["authorization"],
            )
        ]
    )

    merged = service.merge(openapi_surface, discovery_surface)

    assert len(merged.endpoints) == 1
    endpoint = merged.endpoints[0]
    assert endpoint.security_schemes == ["bearerAuth"]
    assert endpoint.object_param_name == "carId"
    assert endpoint.object_id_candidates == ["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"]


def test_merge_keeps_openapi_only_and_discovery_only_endpoints() -> None:
    service = SurfaceMergeService()
    openapi_surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(path="/openapi-only", method="GET"),
        ]
    )
    discovery_surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(path="/discovery-only", method="GET"),
        ]
    )

    merged = service.merge(openapi_surface, discovery_surface)

    assert [(item.path, item.method) for item in merged.endpoints] == [
        ("/discovery-only", "GET"),
        ("/openapi-only", "GET"),
    ]
