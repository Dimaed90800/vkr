from __future__ import annotations

from urllib.parse import urlparse

try:
    from backend.models.acquisition import JsAnalyzeRequest, JsAnalyzeResponse
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint
except ModuleNotFoundError:  # pragma: no cover
    from models.acquisition import JsAnalyzeRequest, JsAnalyzeResponse
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint


class JsAnalysisService:
    def analyze(self, request: JsAnalyzeRequest) -> JsAnalyzeResponse:
        discovered = list(dict.fromkeys(list(request.discovered_urls or []) + list(request.script_urls or [])))
        candidate_paths = self._candidate_paths(discovered)[: max(1, request.max_requests)]
        candidate_auth_endpoints = [path for path in candidate_paths if any(token in path.lower() for token in ("login", "register", "auth", "user", "admin"))]
        normalized_surface = NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(path=path, method="GET", sources=["js_analysis"], source_confidence=0.5)
                for path in candidate_paths
            ]
        )
        return JsAnalyzeResponse(
            js_summary=f"JS analysis synthesized {len(candidate_paths)} candidate paths from {len(discovered)} discovered assets.",
            normalized_surface=normalized_surface,
            candidate_paths=candidate_paths,
            candidate_auth_endpoints=candidate_auth_endpoints,
            raw_metadata={
                "source": "js_analysis",
                "asset_total": len(discovered),
                "candidate_path_total": len(candidate_paths),
            },
        )

    def _candidate_paths(self, urls: list[str]) -> list[str]:
        paths: list[str] = []
        for url in urls:
            parsed = urlparse(str(url or "").strip())
            path = parsed.path or "/"
            if path.endswith(".js"):
                for candidate in ("/api", "/v1", "/v2", "/auth/login", "/auth/register", "/identity/api/v2/user/videos", "/workshop/api/shop/orders"):
                    if candidate not in paths:
                        paths.append(candidate)
                continue
            if path not in paths:
                paths.append(path)
        return paths or ["/api"]
