"""Tests for LlmCandidateAdvisor (safe summaries, optional LLM)."""
from __future__ import annotations

import json

from backend.models.api_graph import Operation
from backend.services.llm_candidate_advisor import (
    LlmCandidateAdvisor,
    SYSTEM_PROMPT,
    build_data_exposure_ranking_user_json,
)


def _summaries() -> list[dict]:
    return [
        {
            "operation_id": "op_GET_/api/v1/me",
            "method": "GET",
            "path_template": "/api/v1/me",
            "has_path_params": False,
            "auth_required": True,
            "resource_type": "user",
            "request_field_names": [],
            "response_field_names": ["id", "email"],
            "tags": ["profile"],
            "summary": "Current user",
            "deterministic_score": 50.0,
        },
        {
            "operation_id": "op_GET_/api/v1/orders/{orderId}",
            "method": "GET",
            "path_template": "/api/v1/orders/{orderId}",
            "has_path_params": True,
            "auth_required": True,
            "resource_type": "order",
            "request_field_names": [],
            "response_field_names": ["id"],
            "tags": [],
            "summary": "One order",
            "deterministic_score": 40.0,
        },
    ]


def test_rank_parses_valid_llm_json() -> None:
    payload = {
        "ranked_candidates": [
            {
                "operation_id": "op_GET_/api/v1/me",
                "recommended": True,
                "priority": 0,
                "requires_seed": False,
                "requires_auth": True,
                "reason": "profile endpoint",
            },
            {
                "operation_id": "op_GET_/api/v1/orders/{orderId}",
                "recommended": True,
                "priority": 1,
                "requires_seed": True,
                "requires_auth": True,
                "reason": "resource",
            },
        ],
        "warnings": [],
    }

    def llm(_sys: str, _user: str) -> str:
        return json.dumps(payload)

    adv = LlmCandidateAdvisor(llm_complete=llm)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), max_candidates=10, enable_llm=True)
    assert out["advisor_available"] is True
    assert out["ranked_candidates"][0]["operation_id"] == "op_GET_/api/v1/me"
    assert out["ranked_candidates"][0]["priority"] == 0


def test_rank_invalid_json_falls_back() -> None:
    def llm(_sys: str, _user: str) -> str:
        return "not json {"

    adv = LlmCandidateAdvisor(llm_complete=llm)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), enable_llm=True)
    assert out["advisor_available"] is False
    assert len(out["ranked_candidates"]) == 2
    assert any("llm_candidate_advisor_error" in w for w in out["warnings"])


def test_rank_timeout_or_exception_falls_back() -> None:
    def llm(_sys: str, _user: str) -> str:
        raise TimeoutError("upstream")

    adv = LlmCandidateAdvisor(llm_complete=llm)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), enable_llm=True)
    assert out["advisor_available"] is False
    assert len(out["ranked_candidates"]) == 2


def test_rank_llm_disabled_falls_back() -> None:
    def llm(_sys: str, _user: str) -> str:
        raise AssertionError("should not be called")

    adv = LlmCandidateAdvisor(llm_complete=llm)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), enable_llm=False)
    assert out["advisor_available"] is False
    assert "llm_candidate_advisor_disabled" in " ".join(out["warnings"])


def test_rank_unconfigured_no_llm_callable() -> None:
    adv = LlmCandidateAdvisor(llm_complete=None)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), enable_llm=True)
    assert out["advisor_available"] is False


def test_user_prompt_excludes_raw_data_markers() -> None:
    user = build_data_exposure_ranking_user_json("cmp1", _summaries())
    lowered = user.lower()
    for bad in ("authorization", "bearer ", "set-cookie", "response_body", "request_body", "raw_http"):
        assert bad not in lowered
    assert "op_GET_/api/v1/me" in user
    assert SYSTEM_PROMPT
    assert "vulnerability" in SYSTEM_PROMPT.lower() or "Do not call anything a vulnerability" in SYSTEM_PROMPT


def test_rank_ignores_unknown_operation_id_from_llm() -> None:
    payload = {
        "ranked_candidates": [
            {
                "operation_id": "op_GET_/phantom",
                "recommended": True,
                "priority": 0,
                "requires_seed": False,
                "requires_auth": False,
                "reason": "invented",
            },
            {
                "operation_id": "op_GET_/api/v1/me",
                "recommended": True,
                "priority": 1,
                "requires_seed": False,
                "requires_auth": False,
                "reason": "ok",
            },
        ],
        "warnings": [],
    }

    def llm(_sys: str, _user: str) -> str:
        return json.dumps(payload)

    adv = LlmCandidateAdvisor(llm_complete=llm)
    out = adv.rank_data_exposure_candidates("cmp", _summaries(), max_candidates=10, enable_llm=True)
    assert out["advisor_available"] is True
    ids = [r["operation_id"] for r in out["ranked_candidates"]]
    assert "op_GET_/phantom" not in ids
    assert any("ignored_unknown" in w for w in out["warnings"])


def test_operation_to_safe_summary_shape() -> None:
    op = Operation(
        operation_id="op_GET_/x",
        method="GET",
        path_template="/x",
        summary="s",
        tags=["t"],
        auth_required=False,
        path_params=[],
        body_fields=["a"],
        response_fields=["b"],
        resource_type="user",
    )
    s = LlmCandidateAdvisor.operation_to_safe_summary(op, deterministic_score=12.5)
    assert s["operation_id"] == "op_GET_/x"
    assert s["deterministic_score"] == 12.5
    assert "Authorization" not in json.dumps(s)
