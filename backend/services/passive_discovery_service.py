from __future__ import annotations

from urllib.parse import urljoin, urlparse

try:
    from backend.models.acquisition import PassiveDiscoveryRequest, PassiveDiscoveryResponse
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint
except ModuleNotFoundError:  # pragma: no cover
    from models.acquisition import PassiveDiscoveryRequest, PassiveDiscoveryResponse
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint


class PassiveDiscoveryService:
    DEFAULT_PATHS = ["/api", "/v1", "/v2", "/identity", "/workshop", "/community", "/auth/login", "/auth/register"]

    def discover(self, request: PassiveDiscoveryRequest) -> PassiveDiscoveryResponse:
        base = str(request.target_url).rstrip("/")
        discovered_urls = [urljoin(base + "/", path.lstrip("/")) for path in self.DEFAULT_PATHS[: max(1, request.max_requests)]]
        script_urls = [urljoin(base + "/", "static/app.js"), urljoin(base + "/", "assets/main.js")]
        doc_urls = [urljoin(base + "/", "openapi.json"), urljoin(base + "/", "swagger-ui/index.html")]
        normalized_surface = NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(path=urlparse(url).path or "/", method="GET", sources=["passive"], source_confidence=0.45)
                for url in discovered_urls
            ]
        )
        return PassiveDiscoveryResponse(
            passive_summary=f"Passive discovery produced {len(discovered_urls)} candidate URLs and {len(normalized_surface.endpoints)} normalized endpoints.",
            normalized_surface=normalized_surface,
            discovered_urls=discovered_urls,
            script_urls=script_urls,
            doc_urls=doc_urls,
            raw_metadata={
                "source": "passive_discovery",
                "discovered_url_total": len(discovered_urls),
                "script_url_total": len(script_urls),
                "doc_url_total": len(doc_urls),
            },
        )
