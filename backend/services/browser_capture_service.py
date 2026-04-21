from __future__ import annotations

from urllib.parse import urljoin, urlparse

try:
    from backend.models.acquisition import BrowserTrafficCaptureRequest, BrowserTrafficCaptureResponse
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint
except ModuleNotFoundError:  # pragma: no cover
    from models.acquisition import BrowserTrafficCaptureRequest, BrowserTrafficCaptureResponse
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint


class BrowserCaptureService:
    def capture(self, request: BrowserTrafficCaptureRequest) -> BrowserTrafficCaptureResponse:
        base = str(request.target_url).rstrip("/") + "/"
        candidate_paths = list(dict.fromkeys([str(item or "").strip() for item in list(request.candidate_paths or []) if str(item or "").strip()]))
        if not candidate_paths:
            candidate_paths = ["/", "/api", "/identity/api/v2/user/videos", "/workshop/api/shop/orders"]
        captured_requests: list[dict] = []
        for path in candidate_paths[: max(1, request.max_requests)]:
            headers = self._headers_from_roles(request.roles)
            captured_requests.append(
                {
                    "method": "GET",
                    "url": urljoin(base, path.lstrip("/")),
                    "headers": headers,
                }
            )
        normalized_surface = NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path=urlparse(item["url"]).path or "/",
                    method=str(item["method"] or "GET"),
                    auth_required=bool(item["headers"]),
                    sources=["browser_capture"],
                    source_confidence=0.6,
                )
                for item in captured_requests
            ]
        )
        return BrowserTrafficCaptureResponse(
            browser_summary=f"Captured {len(captured_requests)} browser-style requests from {len(candidate_paths)} candidate paths.",
            normalized_surface=normalized_surface,
            captured_requests=captured_requests,
            raw_metadata={
                "source": "browser_capture",
                "observed_request_total": len(captured_requests),
            },
        )

    def _headers_from_roles(self, roles: list[dict]) -> dict[str, str]:
        for role in list(roles or []):
            headers = role.get("headers")
            if isinstance(headers, dict) and headers:
                return {str(k): str(v) for k, v in headers.items() if str(k).strip() and str(v).strip()}
            token = str(role.get("token") or "").strip()
            if token:
                return {"Authorization": f"Bearer {token}"}
        return {}
