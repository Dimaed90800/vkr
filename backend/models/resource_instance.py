from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class ResourceInstance(BaseModel):
    object_ref_id: str
    campaign_id: str
    resource_type: str = "unknown"
    object_id_field: str = ""
    object_id_ref: str = ""
    source_operation_id: str = ""
    source_path: str = ""
    source_auth_profile_id: str = ""
    source_role_hint: str = "unknown"
    confidence: str = "low"
    created_by: str = ""
    created_at: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)
