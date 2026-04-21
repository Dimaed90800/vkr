from typing import Any

from pydantic import BaseModel, Field, HttpUrl

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class ObservedHttpRequest(BaseModel):
    method: str = "GET"
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    json_body: dict[str, Any] | list[Any] | None = None


class TrafficDiscoveryRequest(BaseModel):
    requests: list[ObservedHttpRequest] = Field(default_factory=list)
    target_url: HttpUrl | None = None
    allowed_hosts: list[str] = Field(default_factory=list)
    roles: list[dict[str, Any]] = Field(default_factory=list)
    max_duration_sec: int = 30
    max_requests: int = 20
    user_prompt: str = ""


class TrafficDiscoveryResponse(BaseModel):
    traffic_summary: str
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
