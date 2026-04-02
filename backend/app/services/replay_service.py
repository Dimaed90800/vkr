from __future__ import annotations

from collections import defaultdict

from .judge_service import serialize_hypothesis
from .judge_trace_service import classify_dify_issue
from .unified_judge_service import choose_unified_candidate


def _decision_dify_response(decision) -> dict | None:
    raw_selected_key = getattr(decision, "raw_selected_key", None)
    raw_score = getattr(decision, "raw_score", None)
    raw_reason = getattr(decision, "raw_reason", None)

    if raw_selected_key is None and raw_score is None and not raw_reason:
        return None

    response = {}
    if raw_selected_key is not None:
        response["selected_key"] = raw_selected_key
    if raw_score is not None:
        response["score"] = raw_score
    if raw_reason:
        response["reason"] = raw_reason
    return response or None


def _observations_for_round(observations, decision):
    decision_created_at = getattr(decision, "created_at", None)
    if decision_created_at is None:
        return list(observations or [])

    filtered = []
    for obs in observations or []:
        obs_created_at = getattr(obs, "created_at", None)
        if obs_created_at is None or obs_created_at <= decision_created_at:
            filtered.append(obs)
    return filtered


def _group_hypotheses_by_round(agent_judge_feedback_rows, hypotheses_by_id):
    grouped = defaultdict(list)
    seen = set()

    for row in agent_judge_feedback_rows or []:
        hypothesis_id = getattr(row, "hypothesis_id", None)
        round_no = getattr(row, "round_no", None)
        if hypothesis_id is None or round_no is None:
            continue
        hypothesis = hypotheses_by_id.get(hypothesis_id)
        if hypothesis is None:
            continue

        key = (round_no, hypothesis_id)
        if key in seen:
            continue
        seen.add(key)
        grouped[round_no].append(hypothesis)

    for round_no in grouped:
        grouped[round_no].sort(key=lambda item: getattr(item, "id", 0))
    return grouped


def replay_unified_for_session(
    *,
    session_obj,
    judge_decisions,
    observations,
    hypotheses,
    agent_judge_feedback_rows,
):
    hypotheses_by_id = {item.id: item for item in hypotheses or []}
    hypotheses_by_round = _group_hypotheses_by_round(agent_judge_feedback_rows, hypotheses_by_id)

    rounds = []
    match_count = 0
    changed_count = 0
    fallback_count = 0
    rule_based_override_count = 0
    direct_match_count = 0
    recovery_count = 0

    for decision in judge_decisions or []:
        round_no = getattr(decision, "round_no", None)
        candidates = hypotheses_by_round.get(round_no, [])
        if not candidates:
            continue

        hypotheses_json = [serialize_hypothesis(item) for item in candidates]
        dify_response = _decision_dify_response(decision)
        replay_selected, replay_score, resolution_mode, reasoning_summary = choose_unified_candidate(
            candidates,
            hypotheses_json,
            dify_response,
            recent_observations=_observations_for_round(observations, decision),
            recent_selected_keys=[
                getattr(item, "raw_selected_key", None)
                for item in (judge_decisions or [])
                if getattr(item, "round_no", 0) < (round_no or 0) and getattr(item, "raw_selected_key", None)
            ],
            recent_selected_hypothesis_types=[
                getattr(hypotheses_by_id.get(getattr(item, "selected_hypothesis_id", None)), "hypothesis_type", None)
                for item in (judge_decisions or [])
                if getattr(item, "round_no", 0) < (round_no or 0)
                and getattr(hypotheses_by_id.get(getattr(item, "selected_hypothesis_id", None)), "hypothesis_type", None)
            ],
        )

        original_selected_id = getattr(decision, "selected_hypothesis_id", None)
        original_selected = hypotheses_by_id.get(original_selected_id)
        same_selection = getattr(replay_selected, "id", None) == original_selected_id

        if same_selection:
            match_count += 1
        else:
            changed_count += 1

        issue_type = classify_dify_issue(
            resolution_mode,
            raw_reason=(dify_response or {}).get("reason"),
            reasoning_summary=reasoning_summary,
        )
        if issue_type == "direct_match":
            direct_match_count += 1
        elif issue_type == "semantic_recovery":
            recovery_count += 1
        elif issue_type == "rule_based_override":
            rule_based_override_count += 1
        elif issue_type in {
            "provider_credit_limit",
            "empty_outputs",
            "invalid_candidate_key",
            "provider_timeout",
            "provider_error",
            "exception_fallback_other",
            "fallback_other",
        }:
            fallback_count += 1

        rounds.append(
            {
                "round_no": round_no,
                "candidate_count": len(candidates),
                "original_selected_hypothesis_id": original_selected_id,
                "original_selected_hypothesis_type": getattr(original_selected, "hypothesis_type", None),
                "original_selected_agent_name": getattr(original_selected, "agent_name", None),
                "original_resolution_mode": getattr(decision, "resolution_mode", None),
                "replay_selected_hypothesis_id": getattr(replay_selected, "id", None),
                "replay_selected_hypothesis_type": getattr(replay_selected, "hypothesis_type", None),
                "replay_selected_agent_name": getattr(replay_selected, "agent_name", None),
                "replay_priority_score": replay_score,
                "replay_resolution_mode": resolution_mode,
                "replay_reasoning_summary": reasoning_summary,
                "same_selection": same_selection,
                "dify_selected_key": (dify_response or {}).get("selected_key"),
                "dify_score": (dify_response or {}).get("score"),
                "dify_reason": (dify_response or {}).get("reason"),
            }
        )

    total_rounds = len(rounds)
    return {
        "session": {
            "id": getattr(session_obj, "id", None),
            "target_name": getattr(session_obj, "target_name", None),
            "target_url": getattr(session_obj, "target_url", None),
            "status": getattr(session_obj, "status", None),
        },
        "summary": {
            "replayed_rounds": total_rounds,
            "selection_matches": match_count,
            "selection_changes": changed_count,
            "match_rate": round(match_count / total_rounds, 4) if total_rounds else 0.0,
            "fallback_count": fallback_count,
            "rule_based_override_count": rule_based_override_count,
            "direct_match_count": direct_match_count,
            "recovery_count": recovery_count,
        },
        "rounds": rounds,
    }
