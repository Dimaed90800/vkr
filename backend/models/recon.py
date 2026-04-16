from typing import Any, Literal

from pydantic import BaseModel, Field, HttpUrl, field_validator

try:
    from backend.models.api_surface import NormalizedApiSurface
except ModuleNotFoundError:  # pragma: no cover
    from models.api_surface import NormalizedApiSurface


class EndpointSurface(BaseModel):
    path: str
    methods: list[str] = Field(default_factory=list)
    auth_required: bool = False
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    body_fields: list[str] = Field(default_factory=list)
    auth_hints: list[str] = Field(default_factory=list)


class OpenAPIReconRequest(BaseModel):
    target_url: HttpUrl
    openapi_url: HttpUrl | None = None
    openapi_spec_text: str | None = None
    roles: list[dict[str, Any]] = Field(default_factory=list)
    planner_mode: Literal["surface_only", "auto_tasks", "hybrid"] = "hybrid"

    @field_validator("openapi_url", mode="before")
    @classmethod
    def normalize_optional_url(cls, value):
        if value is None:
            return None
        if isinstance(value, str) and not value.strip():
            return None
        return value

    @field_validator("openapi_spec_text")
    @classmethod
    def validate_source(cls, value: str | None) -> str | None:
        if value is not None and len(value) > 2_000_000:
            raise ValueError("openapi_spec_text is too large")
        return value


class OpenAPIReconResponse(BaseModel):
    target_url: HttpUrl
    surface_summary: str
    endpoints: list[EndpointSurface]
    auth_schemes: list[str] = Field(default_factory=list)
    schemas: list[str] = Field(default_factory=list)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)
    normalized_surface: NormalizedApiSurface | None = None
    generated_tasks: list[dict[str, Any]] = Field(default_factory=list)
