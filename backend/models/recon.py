from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


PlannerMode = Literal["surface_only", "hybrid", "auto_tasks", "mvp_openapi"]


class OpenAPIReconRequest(BaseModel):
    target_url: HttpUrl
    openapi_url: str = ""
    openapi_spec_text: str = ""
    roles: list[dict[str, Any]] = Field(default_factory=list)
    planner_mode: PlannerMode = "hybrid"


class OpenAPIReconResponse(BaseModel):
    target_url: HttpUrl
    openapi_url: str = ""
    title: str = ""
    version: str = ""
    endpoints: list[dict[str, Any]] = Field(default_factory=list)
    normalized_surface: NormalizedApiSurface | None = None
    generated_tasks: list[dict[str, Any]] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
