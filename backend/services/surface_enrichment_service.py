try:
    from backend.models.api_surface import NormalizedApiSurface
    from backend.services.candidate_classifier import CandidateClassifier
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface
    from services.candidate_classifier import CandidateClassifier


class SurfaceEnrichmentService:
    def __init__(self) -> None:
        self.classifier = CandidateClassifier()

    def enrich(self, surface: NormalizedApiSurface | None) -> NormalizedApiSurface:
        if surface is None:
            return NormalizedApiSurface(endpoints=[])

        enriched = []
        for endpoint in surface.endpoints:
            item = endpoint.model_copy(deep=True)
            item.sources = self._merge_strings(item.sources, [])
            if item.auth_signals.has_auth_header or item.auth_signals.has_cookie_auth:
                item.auth_required = True
                item.security_schemes = self._merge_strings(item.security_schemes, ["observedAuth"])
            if not item.source_confidence:
                item.source_confidence = self._default_confidence(item.sources)
            enriched.append(self.classifier.classify(item))

        enriched.sort(key=lambda endpoint: (endpoint.path, endpoint.method))
        return NormalizedApiSurface(endpoints=enriched)

    def _default_confidence(self, sources: list[str]) -> float:
        normalized = {str(item or "").strip().lower() for item in sources or [] if str(item or "").strip()}
        if "traffic" in normalized:
            return 0.95
        if "discovery" in normalized or "zap" in normalized:
            return 0.75
        if "openapi" in normalized:
            return 0.9
        return 0.5

    def _merge_strings(self, left: list[str], right: list[str]) -> list[str]:
        seen: set[str] = set()
        values: list[str] = []
        for item in [*(left or []), *(right or [])]:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            values.append(value)
        return values
