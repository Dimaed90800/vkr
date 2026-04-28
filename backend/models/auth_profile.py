from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class AuthProfile(BaseModel):
    auth_profile_id: str = ""
    campaign_id: str = ""
    role_hint: str = "unknown"
    user_label: str = ""
    auth_type: str = "unknown"
    token_ref: str = ""
    created_by: str = ""
    created_at: str = ""
    expires_at: str = "not_available"
    metadata: dict[str, Any] = Field(default_factory=dict)
