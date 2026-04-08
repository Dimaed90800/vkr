from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey
from sqlalchemy.sql import func
from .db import Base
from datetime import datetime


class TestSession(Base):
    __tablename__ = "test_sessions"

    id = Column(Integer, primary_key=True, index=True)
    target_name = Column(String(128), nullable=False)
    target_url = Column(String(512), nullable=False)
    status = Column(String(64), default="created")
    budget_requests_total = Column(Integer, nullable=True, default=200)
    budget_requests_used = Column(Integer, nullable=False, default=0)
    budget_time_total = Column(Integer, nullable=True, default=1800)
    budget_time_used = Column(Integer, nullable=False, default=0)
    max_rounds = Column(Integer, nullable=True, default=10)
    rounds_completed = Column(Integer, nullable=False, default=0)
    allowed_test_classes_json = Column(Text, nullable=True)
    last_strategy_json = Column(Text, nullable=True)
    stop_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class SurfaceInventory(Base):
    __tablename__ = "surface_inventory"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    path = Column(String(512), nullable=False)
    method = Column(String(16), nullable=True)

    source_type = Column(String(64), nullable=False)
    asset_type = Column(String(64), nullable=True)

    confidence = Column(Float, default=0.5)

    content_type = Column(String(128), nullable=True)
    auth_hint = Column(String(128), nullable=True)
    parameters_json = Column(Text, nullable=True)
    raw_json = Column(Text, nullable=True)


class Observation(Base):
    __tablename__ = "observations"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    endpoint = Column(String(512), nullable=False)
    method = Column(String(16), nullable=False)

    role_name = Column(String(64), nullable=True)

    request_headers = Column(Text, nullable=True)
    request_params = Column(Text, nullable=True)
    request_body = Column(Text, nullable=True)

    status_code = Column(Integer, nullable=True)
    response_headers = Column(Text, nullable=True)
    body_preview = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Hypothesis(Base):
    __tablename__ = "hypotheses"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    agent_name = Column(String(64), nullable=False, default="rule_based_agent")
    hypothesis_type = Column(String(64), nullable=False)
    target_endpoint = Column(String(512), nullable=True)
    http_method = Column(String(16), nullable=True)

    description = Column(Text, nullable=False)
    payload_json = Column(Text, nullable=True)

    confidence = Column(Float, default=0.5)
    estimated_cost = Column(Float, default=1.0)
    false_positive_risk = Column(Float, default=0.5)
    coverage_gain = Column(Float, default=0.5)
    evidence_readiness = Column(Float, default=0.5)

    status = Column(String(32), default="candidate")
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class JudgeDecision(Base):
    __tablename__ = "judge_decisions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)
    round_no = Column(Integer, nullable=False, default=1)
    judge_mode = Column(String(32), nullable=True, default="rule_based")

    selected_hypothesis_id = Column(Integer, nullable=True)
    decision_type = Column(String(64), nullable=False)
    priority_score = Column(Float, nullable=True)
    raw_selected_key = Column(Text, nullable=True)
    raw_score = Column(Float, nullable=True)
    raw_reason = Column(Text, nullable=True)
    resolution_mode = Column(String(64), nullable=True)

    reasoning_summary = Column(Text, nullable=True)
    required_evidence_json = Column(Text, nullable=True)
    stop_condition_json = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())


class RoleCredential(Base):
    __tablename__ = "role_credentials"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    role_name = Column(String(64), nullable=False)
    email = Column(String(255), nullable=True)
    password = Column(String(255), nullable=True)
    phone_number = Column(String(64), nullable=True)

    access_token = Column(Text, nullable=True)
    refresh_token = Column(Text, nullable=True)
    token_type = Column(String(64), nullable=True)

    status = Column(String(32), default="created")  # created / registered / authenticated / failed
    last_auth_status = Column(Integer, nullable=True)
    notes = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    finding_type = Column(String(64), nullable=False)  # possible_bola / possible_bopla / access_control_difference
    severity = Column(String(32), nullable=True)  # low / medium / high
    endpoint = Column(String(512), nullable=True)

    related_hypothesis_id = Column(Integer, nullable=True)
    related_observation_ids = Column(Text, nullable=True)

    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    evidence_json = Column(Text, nullable=True)

    verification_status = Column(String(32), default="candidate")  # candidate / confirmed / rejected
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class ExperimentRun(Base):
    __tablename__ = "experiment_runs"

    id = Column(Integer, primary_key=True, index=True)
    target_name = Column(String)
    target_url = Column(String)
    judge_mode = Column(String)  # rule_based | dify | unified
    profile = Column(String, default="mixed")  # bola | bopla | mixed
    max_rounds = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)


class ExperimentResult(Base):
    __tablename__ = "experiment_results"

    id = Column(Integer, primary_key=True, index=True)
    experiment_id = Column(Integer, ForeignKey("experiment_runs.id"))

    total_rounds = Column(Integer)
    findings_total = Column(Integer)
    bola_findings = Column(Integer)
    bopla_findings = Column(Integer)

    judge_decisions = Column(Integer)
    fallback_count = Column(Integer)

    confirmed_findings = Column(Integer)
    confirmed_bola = Column(Integer)
    confirmed_bopla = Column(Integer)

    avg_score = Column(Float)
    created_at = Column(DateTime, default=datetime.utcnow)


class AgentStrategyMemory(Base):
    __tablename__ = "agent_strategy_memory"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)

    agent_name = Column(String(64), nullable=False, index=True)
    context_signature = Column(String(128), nullable=False, index=True)
    pattern_type = Column(String(128), nullable=False, index=True)

    attempts = Column(Integer, nullable=False, default=0)
    selected_count = Column(Integer, nullable=False, default=0)
    confirmed_count = Column(Integer, nullable=False, default=0)
    rejected_count = Column(Integer, nullable=False, default=0)

    avg_cost = Column(Float, nullable=False, default=0.0)
    last_result = Column(String(32), nullable=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class AgentJudgeFeedback(Base):
    __tablename__ = "agent_judge_feedback"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, nullable=False, index=True)
    round_no = Column(Integer, nullable=False, index=True)

    agent_name = Column(String(64), nullable=False, index=True)
    hypothesis_id = Column(Integer, nullable=True, index=True)
    hypothesis_type = Column(String(64), nullable=True)

    was_selected = Column(Integer, nullable=False, default=0)
    judge_mode = Column(String(32), nullable=True)
    priority_score = Column(Float, nullable=True)
    decision_reason = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class AutomationJob(Base):
    __tablename__ = "automation_jobs"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(String(64), nullable=False, unique=True, index=True)
    job_type = Column(String(64), nullable=False, default="batch_experiments")
    status = Column(String(32), nullable=False, default="queued")  # queued / running / finished / failed

    payload_json = Column(Text, nullable=True)
    result_json = Column(Text, nullable=True)
    artifact_dir = Column(String(512), nullable=True)
    error_text = Column(Text, nullable=True)

    created_at = Column(DateTime(timezone=True), server_default=func.now())
    started_at = Column(DateTime(timezone=True), nullable=True)
    finished_at = Column(DateTime(timezone=True), nullable=True)
