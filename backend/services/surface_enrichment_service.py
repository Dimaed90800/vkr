from __future__ import annotations

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class SurfaceEnrichmentService:
    def enrich(self, surface: NormalizedApiSurface) -> NormalizedApiSurface:
        for endpoint in surface.endpoints:
            path = str(endpoint.path or "").lower()
            if not endpoint.tags:
                inferred: list[str] = []
                if "auth" in path or "login" in path or "register" in path:
                    inferred.append("auth")
                if "order" in path:
                    inferred.append("order")
                if "video" in path:
                    inferred.append("video")
                endpoint.tags = inferred
            if not endpoint.object_param_name:
                for name in endpoint.path_params + endpoint.query_params + endpoint.body_fields:
                    lowered = str(name or "").lower()
                    if lowered.endswith("id") or lowered in {"id", "video_id", "order_id", "vehicleid", "vehicle_id"}:
                        endpoint.object_param_name = str(name)
                        break
            endpoint.resource_signals.has_object_id = endpoint.resource_signals.has_object_id or bool(endpoint.object_param_name)
        return surface
