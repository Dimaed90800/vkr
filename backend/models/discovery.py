from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class DiscoveryRequest(BaseModel):
    target_url: HttpUrl
    allowed_hosts: list[str] = Field(default_factory=list)
    roles: list[dict[str, Any]] = Field(default_factory=list)
    enable_discovery: bool = True
    discovery_mode: Literal["zap"] = "zap"
    zap_base_url: str = "http://zap:8080"
    discovery_seeds: list[str] = Field(default_factory=list)
    use_authenticated_discovery: bool = False
    use_spider: bool = True
    use_ajax_spider: bool = False
    max_depth: int = 2
    max_children: int = 50
    max_duration_sec: int = 120


class DiscoveryResponse(BaseModel):
    target_url: HttpUrl
    discovery_summary: str
    raw_urls: list[str] = Field(default_factory=list)
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
