from __future__ import annotations

import json
from typing import Any

from fastapi import HTTPException

from ..models import Finding, Observation, TestSession
from .finding_dedup_service import (
    matching_bola_finding,
    matching_bopla_finding,
    merge_related_observation_ids,
)
from .session_state_service import deserialize_strategy_state, serialize_strategy_state


def _safe_json_load(value: str | None) -> dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _serialize_finding(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.id,
        "type": finding.finding_type,
        "title": finding.title,
        "endpoint": finding.endpoint,
        "severity": finding.severity,
        "verification_status": finding.verification_status,
        "description": finding.description,
    }


def _infer_worker_family(*, worker_type: str | None, vulnerability_class: str | None, tool_name: str | None) -> str | None:
    normalized_class = str(vulnerability_class or "").strip().upper()
    normalized_worker = str(worker_type or "").strip().lower()
    normalized_tool = str(tool_name or "").strip().lower()

    if normalized_class == "BOLA" or normalized_tool == "probe_same_object_across_roles":
        return "bola"
    if normalized_class == "BOPLA" or normalized_tool == "infer_bopla":
        return "bopla"
    if normalized_class == "AUTH_SETUP" or normalized_worker == "auth_worker":
        return "auth"
    if normalized_class == "PROBE_SEED":
        return "probe"
    if normalized_class == "DISCOVERY" or normalized_worker == "discovery_agent":
        return "discovery"
    if normalized_class == "DAST" or normalized_worker == "dast_agent":
        return "dast"
    return None


def _mark_task_completed(session_obj: TestSession, *, worker_family: str | None, task_id: str | None) -> None:
    if not worker_family or not task_id:
        return

    strategy_state = deserialize_strategy_state(getattr(session_obj, "last_strategy_json", None))
    completed = strategy_state.get("completed_worker_tasks") or {}
    family_items = completed.get(worker_family) or []
    if not isinstance(family_items, list):
        family_items = []

    normalized_task_id = str(task_id).strip()
    if normalized_task_id and normalized_task_id not in family_items:
        family_items.append(normalized_task_id)
    completed[worker_family] = family_items
    strategy_state["completed_worker_tasks"] = completed
    session_obj.last_strategy_json = serialize_strategy_state(strategy_state)


def ingest_worker_result(
    db,
    *,
    session_id: int,
    worker_type: str,
    tool_name: str,
    result: dict[str, Any],
    task_id: str | None = None,
    vulnerability_class: str | None = None,
) -> dict[str, Any]:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")

    _mark_task_completed(
        session_obj,
        worker_family=_infer_worker_family(
            worker_type=worker_type,
            vulnerability_class=vulnerability_class,
            tool_name=tool_name,
        ),
        task_id=task_id,
    )

    finding = None
    evidence_summary: dict[str, Any] = {}

    if tool_name == "probe_same_object_across_roles":
        analysis = dict(result.get("analysis") or {})
        owner_observation = dict(result.get("owner_observation") or {})
        other_observation = dict(result.get("other_observation") or {})
        endpoint = owner_observation.get("endpoint") or other_observation.get("endpoint")
        if analysis.get("inference") == "possible_bola":
            existing_findings = db.query(Finding).filter(
                Finding.session_id == session_id,
                Finding.finding_type == "possible_bola",
                Finding.endpoint == endpoint,
                Finding.verification_status.in_(["candidate", "confirmed"]),
            ).all()
            finding = matching_bola_finding(existing_findings, endpoint, analysis)
            observation_ids = [
                owner_observation.get("id"),
                other_observation.get("id"),
            ]
            description = (
                f"Cross-role access to the same object endpoint was observed for "
                f"{analysis.get('owner_role')} and {analysis.get('other_role')}."
            )
            if finding:
                finding.related_observation_ids = merge_related_observation_ids(
                    finding.related_observation_ids,
                    observation_ids,
                )
                finding.description = description
                finding.evidence_json = json.dumps(analysis, ensure_ascii=False)
            else:
                finding = Finding(
                    session_id=session_id,
                    finding_type="possible_bola",
                    severity="high",
                    endpoint=endpoint,
                    related_hypothesis_id=None,
                    related_observation_ids=json.dumps(observation_ids, ensure_ascii=False),
                    title="Possible Broken Object Level Authorization",
                    description=description,
                    evidence_json=json.dumps(analysis, ensure_ascii=False),
                    verification_status="candidate",
                )
                db.add(finding)
            evidence_summary = {
                "owner_observation_id": owner_observation.get("id"),
                "other_observation_id": other_observation.get("id"),
                "owner_status_code": owner_observation.get("status_code"),
                "other_status_code": other_observation.get("status_code"),
                "analysis": analysis,
            }

    if tool_name == "infer_bopla":
        analysis = dict(result.get("analysis") or {})
        observation = dict(result.get("observation") or {})
        endpoint = observation.get("endpoint") or analysis.get("endpoint")
        if analysis.get("inference") == "possible_bopla":
            existing_findings = db.query(Finding).filter(
                Finding.session_id == session_id,
                Finding.finding_type == "possible_bopla",
                Finding.endpoint == endpoint,
                Finding.verification_status.in_(["candidate", "confirmed"]),
            ).all()
            finding = matching_bopla_finding(existing_findings, endpoint, analysis)
            observation_ids = [observation.get("id") or analysis.get("observation_id")]
            description = (
                f"Response on {endpoint} exposes potentially sensitive fields: "
                f"{', '.join(analysis.get('exposed_fields', []))}"
            )
            if finding:
                finding.related_observation_ids = merge_related_observation_ids(
                    finding.related_observation_ids,
                    observation_ids,
                )
                finding.description = description
                finding.evidence_json = json.dumps(analysis, ensure_ascii=False)
            else:
                finding = Finding(
                    session_id=session_id,
                    finding_type="possible_bopla",
                    severity="medium",
                    endpoint=endpoint,
                    related_hypothesis_id=None,
                    related_observation_ids=json.dumps(observation_ids, ensure_ascii=False),
                    title="Possible Broken Object Property Level Authorization / Excessive Data Exposure",
                    description=description,
                    evidence_json=json.dumps(analysis, ensure_ascii=False),
                    verification_status="candidate",
                )
                db.add(finding)
            evidence_summary = {
                "observation_id": observation.get("id") or analysis.get("observation_id"),
                "status_code": observation.get("status_code") or analysis.get("status_code"),
                "analysis": analysis,
            }

    db.commit()
    if finding is not None:
        db.refresh(finding)

    return {
        "session_id": session_id,
        "task_id": task_id,
        "worker_type": worker_type,
        "tool_name": tool_name,
        "vulnerability_class": vulnerability_class,
        "candidate_finding": _serialize_finding(finding) if finding else None,
        "evidence_summary": evidence_summary,
    }


def build_judge_package(db, *, session_id: int, finding_id: int) -> dict[str, Any]:
    session_obj = db.query(TestSession).filter(TestSession.id == session_id).first()
    if not session_obj:
        raise HTTPException(status_code=404, detail="Session not found")

    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.session_id == session_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    evidence = _safe_json_load(finding.evidence_json)
    observation_ids = []
    try:
        parsed_ids = json.loads(finding.related_observation_ids or "[]")
        if isinstance(parsed_ids, list):
            observation_ids = [int(item) for item in parsed_ids if str(item).strip().isdigit()]
    except Exception:
        observation_ids = []

    observations = []
    if observation_ids:
        rows = db.query(Observation).filter(Observation.id.in_(observation_ids)).all()
        rows_by_id = {item.id: item for item in rows}
        for item_id in observation_ids:
            obs = rows_by_id.get(item_id)
            if not obs:
                continue
            observations.append(
                {
                    "id": obs.id,
                    "endpoint": obs.endpoint,
                    "method": obs.method,
                    "role_name": obs.role_name,
                    "status_code": obs.status_code,
                    "body_preview": (obs.body_preview or "")[:1000],
                }
            )

    return {
        "session": {
            "id": session_obj.id,
            "target_name": session_obj.target_name,
            "target_url": session_obj.target_url,
        },
        "candidate_finding": _serialize_finding(finding),
        "evidence": {
            "observation_ids": observation_ids,
            "observations": observations,
            "analysis": evidence,
        },
        "judge_instructions": {
            "task": "Evaluate only the evidence. Confirm the vulnerability only if the evidence directly proves exploitation.",
            "allowed_statuses": ["confirmed", "needs_retry", "rejected", "progress"],
        },
    }


def apply_judge_verdict(
    db,
    *,
    session_id: int,
    finding_id: int,
    status: str,
    reason: str | None = None,
    finding_type: str | None = None,
    next_action: str | None = None,
) -> dict[str, Any]:
    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.session_id == session_id,
    ).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    normalized_status = str(status or "").strip().lower()
    if normalized_status == "confirmed":
        finding.verification_status = "confirmed"
    elif normalized_status == "rejected":
        finding.verification_status = "rejected"
    else:
        finding.verification_status = "candidate"

    evidence = _safe_json_load(finding.evidence_json)
    evidence["judge_verdict"] = {
        "status": normalized_status,
        "reason": reason,
        "finding_type": finding_type,
        "next_action": next_action,
    }
    finding.evidence_json = json.dumps(evidence, ensure_ascii=False)
    db.commit()
    db.refresh(finding)

    return {
        "finding": _serialize_finding(finding),
        "judge_verdict": evidence["judge_verdict"],
    }
