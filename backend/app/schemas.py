from pydantic import BaseModel
from typing import Optional, Dict, Any, List


class CreateSessionRequest(BaseModel):
    target_name: str
    target_url: str
    user_prompt: Optional[str] = None
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
    judge_mode: str = "agentic"  # agentic | dify | rule_based | unified
    user_prompt: Optional[str] = None


class AgenticRunRoundRequest(BaseModel):
    user_prompt: Optional[str] = None


class AgenticToolCommandRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any]


class AgenticPrepareAuthRequest(BaseModel):
    max_steps: Optional[int] = 6


class AgenticPrepareProbeRequest(BaseModel):
    max_steps: Optional[int] = 4


class AgenticWorkerResultRequest(BaseModel):
    worker_type: str
    tool_name: str
    result: Dict[str, Any]
    task_id: Optional[str] = None
    vulnerability_class: Optional[str] = None


class AgenticJudgeVerdictRequest(BaseModel):
    finding_id: int
    status: str
    reason: Optional[str] = None
    finding_type: Optional[str] = None
    next_action: Optional[str] = None


class AgenticWorkerTaskResponse(BaseModel):
    task_id: str
    session_id: int
    worker_type: str
    vulnerability_class: str
    goal: str
    inputs: Dict[str, Any]
    allowed_tools: List[str]
    limits: Dict[str, Any]


class CampaignRunRequest(BaseModel):
    target_name: str
    target_url: str
    user_prompt: Optional[str] = None
    judge_mode: str = "agentic"  # agentic | dify | rule_based | unified
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
