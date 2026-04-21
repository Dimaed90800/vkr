from __future__ import annotations

from copy import deepcopy

try:
    from backend.models.api_surface import NormalizedApiSurface, NormalizedEndpoint
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface, NormalizedEndpoint


class SurfaceMergeService:
    def merge(self, surfaces: list[NormalizedApiSurface | dict]) -> NormalizedApiSurface:
        merged: dict[tuple[str, str], NormalizedEndpoint] = {}
        for surface in surfaces:
            if isinstance(surface, dict):
                endpoints = list((surface.get("endpoints") or []))
            else:
                endpoints = list(surface.endpoints or [])
            for item in endpoints:
                endpoint = item if isinstance(item, NormalizedEndpoint) else NormalizedEndpoint.model_validate(item)
                key = (endpoint.method.upper(), endpoint.path)
                current = merged.get(key)
                if current is None:
                    merged[key] = deepcopy(endpoint)
                    continue
                current.tags = sorted(set(current.tags + endpoint.tags))
                current.sources = sorted(set(current.sources + endpoint.sources))
                current.path_params = sorted(set(current.path_params + endpoint.path_params))
                current.query_params = sorted(set(current.query_params + endpoint.query_params))
                current.body_fields = sorted(set(current.body_fields + endpoint.body_fields))
                current.auth_required = current.auth_required or endpoint.auth_required
                current.source_confidence = max(float(current.source_confidence or 0.0), float(endpoint.source_confidence or 0.0))
        return NormalizedApiSurface(endpoints=list(merged.values()))
