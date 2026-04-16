from pydantic import BaseModel, Field


class ResourceSignals(BaseModel):
    has_object_id: bool = False
    has_role_fields: bool = False
    has_sensitive_keywords: bool = False


class CandidateScores(BaseModel):
    authorization: float = 0.0
    injection: float = 0.0
    business_logic: float = 0.0


class AuthSignals(BaseModel):
    has_auth_header: bool = False
    has_cookie_auth: bool = False
    header_names: list[str] = Field(default_factory=list)
    cookie_names: list[str] = Field(default_factory=list)


class ObservedExample(BaseModel):
    source: str = ""
    method: str = ""
    url: str = ""


class NormalizedEndpoint(BaseModel):
    path: str
    method: str
    operation_id: str = ""
    summary: str = ""
    path_params: list[str] = Field(default_factory=list)
    query_params: list[str] = Field(default_factory=list)
    body_fields: list[str] = Field(default_factory=list)
    auth_required: bool = False
    security_schemes: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    object_param_name: str = ""
    object_id_candidates: list[str] = Field(default_factory=list)
    resource_signals: ResourceSignals = Field(default_factory=ResourceSignals)
    auth_signals: AuthSignals = Field(default_factory=AuthSignals)
    observed_examples: list[ObservedExample] = Field(default_factory=list)
    sources: list[str] = Field(default_factory=list)
    source_confidence: float = 0.0
    candidate_scores: CandidateScores = Field(default_factory=CandidateScores)
    candidate_classes: list[str] = Field(default_factory=list)


class NormalizedApiSurface(BaseModel):
    endpoints: list[NormalizedEndpoint] = Field(default_factory=list)
