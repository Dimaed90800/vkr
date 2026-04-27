"""Phase 3 — API Graph / Dependency Graph data contracts.

Defines persistent, campaign-scoped graph nodes and edges:
Operation, ResourceType, Parameter, AuthProfile, RequestExample,
ResponseExample, ResourceInstanceRef, GraphEdge, ApiGraph.

The new graph is fully separate from the per-execution
graph_state_service to avoid coupling. Node ID conventions are
distinct (e.g. AuthProfile uses "auth:<role>" without the
":context" suffix used in graph_state_service).
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class Operation(BaseModel):
    operation_id: str
    operation_id_from_spec: str = ""
    method: str = "GET"
    path_template: str = ""
    summary: str = ""
    tags: list[str] = Field(default_factory=list)
    auth_required: bool = False
    security: list[str] = Field(default_factory=list)
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    body_fields: list[str] = Field(default_factory=list)
    response_fields: list[str] = Field(default_factory=list)
    resource_type: str = ""
    risk_hints: list[str] = Field(default_factory=list)
    owasp_candidates: list[str] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    observed_status_codes: list[int] = Field(default_factory=list)
    observed_roles: list[str] = Field(default_factory=list)
    successful_seed_request_ids: list[str] = Field(default_factory=list)
    auth_baseline_request_ids: list[str] = Field(default_factory=list)


class ResourceType(BaseModel):
    resource_type: str
    operations_producing: list[str] = Field(default_factory=list)
    operations_consuming: list[str] = Field(default_factory=list)
    instance_count: int = 0


class Parameter(BaseModel):
    parameter_id: str
    operation_id: str
    name: str
    location: str = ""
    object_id_hint: bool = False
    resource_type_hint: str = ""


class AuthProfile(BaseModel):
    auth_profile_id: str
    role_name: str
    has_credentials: bool = False
    operations_observed: list[str] = Field(default_factory=list)


class RequestExample(BaseModel):
    example_id: str
    operation_id: str
    request_id: str
    auth_profile: str = ""
    status_code: int = 0
    classification: str = ""


class ResponseExample(BaseModel):
    example_id: str
    operation_id: str
    request_id: str
    status_code: int = 0
    response_fields_seen: list[str] = Field(default_factory=list)
    extracted_id_keys: list[str] = Field(default_factory=list)


class ResourceInstanceRef(BaseModel):
    resource_instance_id: str
    resource_type: str
    object_id: str
    owner_role: str = ""
    observed_by_roles: list[str] = Field(default_factory=list)
    cross_role_observed: bool = False


class GraphEdge(BaseModel):
    edge_id: str
    type: str
    from_node: str
    to_node: str
    confidence: float = 1.0
    sources: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)


class ApiGraph(BaseModel):
    schema_version: str = "api-graph/v1"
    campaign_id: str
    operations: list[Operation] = Field(default_factory=list)
    resource_types: list[ResourceType] = Field(default_factory=list)
    parameters: list[Parameter] = Field(default_factory=list)
    auth_profiles: list[AuthProfile] = Field(default_factory=list)
    request_examples: list[RequestExample] = Field(default_factory=list)
    response_examples: list[ResponseExample] = Field(default_factory=list)
    resource_instances: list[ResourceInstanceRef] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)
    built_at: str = ""
    last_corpus_ingest_at: str = ""


class GraphSummary(BaseModel):
    campaign_id: str
    operations_total: int = 0
    operations_with_seed: int = 0
    operations_auth_required: int = 0
    operations_undocumented: int = 0
    high_risk_operations: list[str] = Field(default_factory=list)
    object_id_operations: list[str] = Field(default_factory=list)
    bola_candidates: list[str] = Field(default_factory=list)
    bfla_candidates: list[str] = Field(default_factory=list)
    bopla_candidates: list[str] = Field(default_factory=list)
    cross_role_signal_operations: list[str] = Field(default_factory=list)
    resource_types: list[str] = Field(default_factory=list)
    seeded_operations_by_role: dict[str, list[str]] = Field(default_factory=dict)


class GraphBuildRequest(BaseModel):
    openapi_spec_text: str = ""
    openapi_url: str = ""


class GraphBuildResponse(BaseModel):
    campaign_id: str
    status: str = "built"
    operations_count: int = 0
    edges_count: int = 0
    resource_types_count: int = 0
    parameters_count: int = 0
    auth_profiles_count: int = 0
    sources_used: list[str] = Field(default_factory=list)
