from __future__ import annotations

from ..models import AgentJudgeFeedback


def record_judge_feedback(
    db,
    *,
    session_id: int,
    round_no: int,
    judge_mode: str,
    candidates,
    selected_hypothesis,
    selected_score: float | None,
    reasoning_summary: str | None,
):
    rows = []
    selected_id = getattr(selected_hypothesis, "id", None)

    for candidate in candidates:
        row = AgentJudgeFeedback(
            session_id=session_id,
            round_no=round_no,
            agent_name=getattr(candidate, "agent_name", "unknown_agent"),
            hypothesis_id=getattr(candidate, "id", None),
            hypothesis_type=getattr(candidate, "hypothesis_type", None),
            was_selected=1 if getattr(candidate, "id", None) == selected_id else 0,
            judge_mode=judge_mode,
            priority_score=selected_score if getattr(candidate, "id", None) == selected_id else None,
            decision_reason=reasoning_summary if getattr(candidate, "id", None) == selected_id else None,
        )
        db.add(row)
        rows.append(row)

    return rows


def build_agent_judge_feedback_summary(feedback_rows):
    if not feedback_rows:
        return {
            "agents_total": 0,
            "agents": [],
        }

    grouped = {}
    total_rounds = len({(row.session_id, row.round_no) for row in feedback_rows})
    for row in feedback_rows:
        item = grouped.setdefault(
            row.agent_name,
            {
                "agent_name": row.agent_name,
                "proposals_seen_by_judge": 0,
                "selected_by_judge": 0,
            },
        )
        item["proposals_seen_by_judge"] += 1
        item["selected_by_judge"] += int(row.was_selected or 0)

    agents = []
    for item in sorted(grouped.values(), key=lambda x: x["agent_name"]):
        proposals = max(item["proposals_seen_by_judge"], 1)
        agents.append(
            {
                **item,
                "judge_selection_rate": round(item["selected_by_judge"] / proposals, 4),
                "judge_round_coverage": round(item["selected_by_judge"] / max(total_rounds, 1), 4),
            }
        )

    return {
        "agents_total": len(agents),
        "rounds_with_feedback": total_rounds,
        "agents": agents,
    }


def list_agent_judge_feedback_rows(db, session_id: int) -> list[AgentJudgeFeedback]:
    if db is None:
        return []
    return db.query(AgentJudgeFeedback).filter(
        AgentJudgeFeedback.session_id == session_id
    ).all()


def build_agent_judge_feedback_index(feedback_rows) -> dict:
    grouped = {}
    for row in feedback_rows or []:
        key = (row.agent_name, row.hypothesis_type)
        item = grouped.setdefault(
            key,
            {
                "proposals_seen_by_judge": 0,
                "selected_by_judge": 0,
            },
        )
        item["proposals_seen_by_judge"] += 1
        item["selected_by_judge"] += int(row.was_selected or 0)

    for item in grouped.values():
        proposals = max(item["proposals_seen_by_judge"], 1)
        item["judge_selection_rate"] = round(item["selected_by_judge"] / proposals, 4)
    return grouped


def compute_judge_feedback_adjustment(stats: dict | None) -> float:
    if not stats:
        return 0.0

    proposals_seen = int(stats.get("proposals_seen_by_judge", 0) or 0)
    if proposals_seen < 2:
        return 0.0

    selection_rate = float(stats.get("judge_selection_rate", 0.0) or 0.0)
    adjustment = (selection_rate - 0.15) * 0.18
    return round(max(min(adjustment, 0.08), -0.06), 4)


def apply_judge_feedback_to_hypotheses(db, session_id: int, hypotheses: list[dict]) -> list[dict]:
    feedback_index = build_agent_judge_feedback_index(
        list_agent_judge_feedback_rows(db, session_id)
    )
    adjusted = []

    for item in hypotheses:
        key = (item.get("agent_name"), item.get("hypothesis_type"))
        stats = feedback_index.get(key)
        adjustment = compute_judge_feedback_adjustment(stats)
        payload = dict(item.get("payload", {}))
        if stats:
            payload["judge_feedback_stats"] = stats
        payload["judge_feedback_adjustment"] = adjustment

        adjusted.append(
            {
                **item,
                "payload": payload,
            }
        )

    return adjusted
