from pydantic import BaseModel
from typing import Optional, Dict, Any


class CreateSessionRequest(BaseModel):
    target_name: str
    target_url: str


class SessionResponse(BaseModel):
    id: int
    target_name: str
    target_url: str
    status: str

    class Config:
        from_attributes = True


class RunSpiderRequest(BaseModel):
    session_id: int


class ParseOpenAPIRequest(BaseModel):
    session_id: int
    openapi_url: str


class ProbeRequest(BaseModel):
    session_id: int
    endpoint: str
    method: str = "GET"
    role_name: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    params: Optional[Dict[str, Any]] = None
    json_body: Optional[Dict[str, Any]] = None
    use_role_token: bool = False


class GenerateHypothesesRequest(BaseModel):
    session_id: int


class JudgeSelectRequest(BaseModel):
    session_id: int


class CampaignStepRequest(BaseModel):
    session_id: int
    judge_mode: str = "rule_based"  # или "dify"


class CreateRoleRequest(BaseModel):
    session_id: int
    role_name: str


class RegisterRoleRequest(BaseModel):
    session_id: int
    role_name: str


class LoginRoleRequest(BaseModel):
    session_id: int
    role_name: str