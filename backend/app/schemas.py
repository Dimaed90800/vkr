from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class CreateSessionRequest(BaseModel):
    target_name: str
    target_url: str
    budget_requests_total: Optional[int] = 200
    budget_time_total: Optional[int] = 1800
    max_rounds: Optional[int] = 10
    allowed_test_classes: Optional[List[str]] = ["discovery", "bola", "bopla", "auth"]
    enabled_agents: Optional[List[str]] = None
    strategy_config: Optional[Dict[str, Any]] = None


class SessionResponse(BaseModel):
    id: int
    target_name: str
    target_url: str
    status: str
    budget_requests_total: Optional[int] = None
    budget_requests_used: int = 0
    budget_time_total: Optional[int] = None
    budget_time_used: int = 0
    max_rounds: Optional[int] = None
    rounds_completed: int = 0
    allowed_test_classes_json: Optional[str] = None
    last_strategy_json: Optional[str] = None
    stop_reason: Optional[str] = None

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
    judge_mode: str = "rule_based"  # rule_based | dify | unified


class CampaignRunRequest(BaseModel):
    target_name: str
    target_url: str
    judge_mode: str = "rule_based"  # rule_based | dify | unified
    budget_requests_total: Optional[int] = 200
    budget_time_total: Optional[int] = 1800
    max_rounds: Optional[int] = 10
    allowed_test_classes: Optional[List[str]] = ["discovery", "bola", "bopla", "auth"]
    enabled_agents: Optional[List[str]] = None
    strategy_config: Optional[Dict[str, Any]] = None


class CreateRoleRequest(BaseModel):
    session_id: int
    role_name: str


class RegisterRoleRequest(BaseModel):
    session_id: int
    role_name: str


class LoginRoleRequest(BaseModel):
    session_id: int
    role_name: str
