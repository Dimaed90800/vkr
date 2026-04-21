from typing import Literal

from pydantic import BaseModel, Field


SecurityClassName = Literal["authorization", "injection", "business_logic"]


class AuthorizationBootstrapHints(BaseModel):
    register: list[str] = Field(default_factory=list)
    login: list[str] = Field(default_factory=list)
    profile: list[str] = Field(default_factory=list)
    create_resource: list[str] = Field(default_factory=list)


class InjectionBootstrapHints(BaseModel):
    shape_probe: list[str] = Field(default_factory=list)
    reflection_probe: list[str] = Field(default_factory=list)
    path_probe: list[str] = Field(default_factory=list)


class BusinessLogicBootstrapHints(BaseModel):
    workflow_roots: list[str] = Field(default_factory=list)
    create: list[str] = Field(default_factory=list)
    transition: list[str] = Field(default_factory=list)


class SecurityClassSynthesis(BaseModel):
    candidate_targets: list[str] = Field(default_factory=list)
    likely_subtypes: list[str] = Field(default_factory=list)
    missing_prerequisites: list[str] = Field(default_factory=list)
    preparation_suggestions: list[str] = Field(default_factory=list)
    priority_hint: float = 0.0
    confidence: float = 0.0


class AuthorizationSynthesis(SecurityClassSynthesis):
    candidate_bootstrap_endpoints: AuthorizationBootstrapHints = Field(default_factory=AuthorizationBootstrapHints)


class InjectionSynthesis(SecurityClassSynthesis):
    candidate_bootstrap_endpoints: InjectionBootstrapHints = Field(default_factory=InjectionBootstrapHints)


class BusinessLogicSynthesis(SecurityClassSynthesis):
    candidate_bootstrap_endpoints: BusinessLogicBootstrapHints = Field(default_factory=BusinessLogicBootstrapHints)


class SynthesizedSecurityContext(BaseModel):
    authorization: AuthorizationSynthesis = Field(default_factory=AuthorizationSynthesis)
    injection: InjectionSynthesis = Field(default_factory=InjectionSynthesis)
    business_logic: BusinessLogicSynthesis = Field(default_factory=BusinessLogicSynthesis)
    global_notes: list[str] = Field(default_factory=list)
    global_priority_order: list[str] = Field(default_factory=list)
