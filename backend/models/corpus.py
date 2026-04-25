from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class StatusClassification(str, Enum):
    successful_seed = "successful_seed"
    auth_baseline = "auth_baseline"
    negative_object = "negative_object"
    validation_signal = "validation_signal"
    rate_limit_signal = "rate_limit_signal"
    server_error_candidate = "server_error_candidate"


class RequestCorpusItem(BaseModel):
    request_id: str
    campaign_id: str
    operation_id: str = ""
    source: str = ""
    source_tool_run_id: str = ""
    method: str = "GET"
    url: str = ""
    path_template: str = ""
    auth_profile: str = ""
    headers_redacted: dict[str, Any] = Field(default_factory=dict)
    body_redacted: Any = None
    status_code: int = 0
    response_body_redacted: Any = None
    response_content_type: str = ""
    classification: StatusClassification = StatusClassification.successful_seed
    extracted_ids: dict[str, list[str]] = Field(default_factory=dict)
    sensitive_fields: list[str] = Field(default_factory=list)
    created_at: str = ""


class ResourceInstance(BaseModel):
    resource_instance_id: str
    campaign_id: str
    resource_type: str = ""
    object_id: str = ""
    owner_role: str = ""
    owner_confidence: float = 0.0
    source_request_id: str = ""
    source_operation_id: str = ""
    observed_by_roles: list[str] = Field(default_factory=list)


class CorpusAddRequest(BaseModel):
    campaign_id: str
    method: str = "GET"
    url: str = ""
    path_template: str = ""
    auth_profile: str = ""
    headers: dict[str, Any] = Field(default_factory=dict)
    body: Any = None
    status_code: int = 0
    response_body: Any = None
    response_content_type: str = ""
    source: str = "manual"
    source_tool_run_id: str = ""
    operation_id: str = ""


class CorpusAddResponse(BaseModel):
    request_id: str
    campaign_id: str
    classification: StatusClassification
    extracted_ids: dict[str, list[str]] = Field(default_factory=dict)
    resource_instances_created: int = 0
