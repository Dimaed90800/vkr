from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class BolaObjectPair(BaseModel):
    object_pair_id: str
    campaign_id: str
    resource_type: str = "unknown"
    object_ref_id: str = ""
    object_id_ref: str = ""
    owner_auth_profile_id: str = ""
    attacker_auth_profile_id: str = ""
    target_operation_id: str = ""
    target_path_template: str = ""
    target_method: str = "GET"
    path_param_name: str = ""
    confidence: str = "low"
    created_by: str = "bola_object_pair_builder"
    created_at: str = ""
    reason_codes: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
