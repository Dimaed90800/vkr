from typing import Any

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(..., examples=["ok"])
    message: str = Field(..., examples=["healthy"])
    details: dict[str, Any] | None = None
