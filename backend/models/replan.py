from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ControlledReplanResult(BaseModel):
    reason: str = ""
    should_replan: bool = False
    next_actions: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
