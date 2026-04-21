from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field, HttpUrl

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class PassiveDiscoveryRequest(BaseModel):
    target_url: HttpUrl
    allowed_hosts: list[str] = Field(default_factory=list)
    max_requests: int = 20
    max_duration_sec: int = 30


class PassiveDiscoveryResponse(BaseModel):
    passive_summary: str
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    discovered_urls: list[str] = Field(default_factory=list)
    script_urls: list[str] = Field(default_factory=list)
    doc_urls: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class JsAnalyzeRequest(BaseModel):
    target_url: HttpUrl
    allowed_hosts: list[str] = Field(default_factory=list)
    script_urls: list[str] = Field(default_factory=list)
    discovered_urls: list[str] = Field(default_factory=list)
    max_requests: int = 20
    max_duration_sec: int = 30


class JsAnalyzeResponse(BaseModel):
    js_summary: str
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    candidate_paths: list[str] = Field(default_factory=list)
    candidate_auth_endpoints: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)


class BrowserTrafficCaptureRequest(BaseModel):
    target_url: HttpUrl
    allowed_hosts: list[str] = Field(default_factory=list)
    roles: list[dict[str, Any]] = Field(default_factory=list)
    candidate_paths: list[str] = Field(default_factory=list)
    max_requests: int = 20
    max_duration_sec: int = 30
    user_prompt: str = ""


class BrowserTrafficCaptureResponse(BaseModel):
    browser_summary: str
    normalized_surface: NormalizedApiSurface = Field(default_factory=NormalizedApiSurface)
    captured_requests: list[dict[str, Any]] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
