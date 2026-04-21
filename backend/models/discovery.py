from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

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

    @field_validator("discovery_mode", mode="before")
    @classmethod
    def normalize_discovery_mode(cls, value: Any) -> str:
        normalized = str(value or "").strip().lower()
        if normalized in {"", "true", "1", "yes", "on", "zap"}:
            return "zap"
        return normalized


class DiscoveryResponse(BaseModel):
    target_url: HttpUrl
    discovery_summary: str
    raw_urls: list[str] = Field(default_factory=list)
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class ZapHealthCheckRequest(BaseModel):
    target_url: HttpUrl
    zap_base_url: str = "http://zap:8080"
    allowed_hosts: list[str] = Field(default_factory=list)
    max_duration_sec: int = 15


class ZapHealthCheckResponse(BaseModel):
    zap_reachable: bool = False
    zap_version: str | None = None
    target_reachable_from_backend: bool = False
    target_reachable_from_zap: bool = False
    spider_completed: bool = False
    urls_discovered: int = 0
    api_like_urls: int = 0
    diagnosis: str = ""
    recommendation: str = ""
    stage: str = ""
    error: str = ""
    raw_urls: list[str] = Field(default_factory=list)
    spider_status: str = ""
    only_static_content_detected: bool = False
    zap_base_url: str = ""
    target_url: str = ""
