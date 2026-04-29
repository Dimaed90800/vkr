from __future__ import annotations

from typing import Any

try:
    from backend.models.evidence_pack import EvidencePack, EvidencePackStatus
    from backend.models.judge import (
        FindingCandidatePayload,
        JudgeApplyRequest,
        JudgeVerdictKind,
        JudgeVerdictPayload,
    )
    from backend.services.judge_apply_service import JudgeApplyService
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.evidence_pack import EvidencePack, EvidencePackStatus
    from models.judge import (
        FindingCandidatePayload,
        JudgeApplyRequest,
        JudgeVerdictKind,
        JudgeVerdictPayload,
    )
    from services.judge_apply_service import JudgeApplyService
    from storage.memory_store import memory_store


def _has_signal(signals: list[str], expected: str) -> bool:
    needle = str(expected or "").strip().lower()
    return any(str(item or "").strip().lower() == needle for item in signals)


def _has_any_signal_prefix(signals: list[str], prefix: str, allowed_values: set[str]) -> bool:
    pfx = str(prefix or "").strip().lower()
    for item in signals:
        raw = str(item or "").strip().lower()
        if not raw.startswith(pfx):
            continue
        value = raw[len(pfx):].strip()
        if value in allowed_values:
            return True
    return False


def _is_api7_ssrf_callback_proof_eligible(pack: EvidencePack) -> tuple[bool, str]:
    if str(pack.owasp_category or "") != "API7_SERVER_SIDE_REQUEST_FORGERY":
        return False, "owasp_category_mismatch"
    if str(pack.vulnerability_class or "") != "server_side_request_forgery":
        return False, "vulnerability_class_mismatch"
    if pack.status != EvidencePackStatus.ready_for_judge or not pack.judge_ready:
        return False, "not_judge_ready"

    signals = [str(s) for s in (pack.derived_signals or [])]
    has_effective = (
        _has_signal(signals, "callback_received_effective:true")
        or _has_signal(signals, "callback_received:true")
    )
    has_store = _has_signal(signals, "callback_store_received:true")
    has_controlled = _has_signal(signals, "controlled_callback_received")
    has_corr = _has_signal(signals, "callback_correlation_matched")
    has_strength = _has_any_signal_prefix(signals, "evidence_strength:", {"high", "medium"})
    if not has_effective:
        return False, "missing_callback_received_effective"
    if not has_store:
        return False, "missing_callback_store_received"
    if not has_controlled:
        return False, "missing_controlled_callback_signal"
    if not has_corr:
        return False, "missing_correlation_match_signal"
    if not has_strength:
        return False, "missing_evidence_strength_medium_high"
    return True, "eligible"


def _is_api1_bola_replay_eligible(pack: EvidencePack) -> tuple[bool, str]:
    if str(pack.owasp_category or "") != "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION":
        return False, "owasp_category_mismatch"
    if str(pack.vulnerability_class or "") not in {"bola", "broken_object_level_authorization"}:
        return False, "vulnerability_class_mismatch"
    if pack.status != EvidencePackStatus.ready_for_judge or not pack.judge_ready:
        return False, "not_judge_ready"
    signals = [str(s) for s in (pack.derived_signals or [])]
    has_owner_valid = _has_signal(signals, "owner_baseline_valid:true")
    has_access_granted = (
        _has_signal(signals, "access_granted:true")
        or _has_signal(signals, "result:attacker_access_granted")
    )
    has_owner_2xx = _has_any_signal_prefix(signals, "owner_status_code:", {"200", "201", "202", "203", "204", "205", "206", "207", "208", "226"})
    has_attacker_2xx = _has_any_signal_prefix(signals, "attacker_status_code:", {"200", "201", "202", "203", "204", "205", "206", "207", "208", "226"})
    has_strength = _has_any_signal_prefix(signals, "evidence_strength:", {"high", "medium"})
    has_pair = any(str(s).startswith("object_pair_id:") and str(s).split(":", 1)[1].strip() for s in signals)
    if not has_owner_valid:
        return False, "missing_owner_baseline_valid"
    if not has_access_granted:
        return False, "missing_attacker_access_granted"
    if not has_owner_2xx:
        return False, "missing_owner_2xx"
    if not has_attacker_2xx:
        return False, "missing_attacker_2xx"
    if not has_strength:
        return False, "missing_evidence_strength_medium_high"
    if not has_pair:
        return False, "missing_object_pair_id"
    return True, "eligible"


def apply_judge_for_ready_evidence_in_campaign(
    campaign_id: str,
    owasp_category: str | None = None,
    vulnerability_class: str | None = None,
    source: str = "auto_reconciliation",
) -> dict[str, Any]:
    cid = str(campaign_id or "").strip()
    category_filter = str(owasp_category or "").strip()
    vuln_filter = str(vulnerability_class or "").strip()
    if not cid:
        return {
            "campaign_id": cid,
            "applied_count": 0,
            "confirmed_count": 0,
            "skipped_count": 0,
            "decision_ids": [],
            "finding_ids": [],
            "skipped": [],
        }

    service = JudgeApplyService()
    packs_raw = memory_store.list_evidence_packs_by_campaign(cid)
    decisions = memory_store.list_judge_decisions_by_campaign(cid)
    findings = memory_store.list_confirmed_findings_by_campaign(cid)
    judged_evidence_ids = {str(d.get("evidence_id") or "") for d in decisions if isinstance(d, dict)}
    confirmed_evidence_ids = {str(f.get("evidence_id") or "") for f in findings if isinstance(f, dict)}

    summary: dict[str, Any] = {
        "campaign_id": cid,
        "applied_count": 0,
        "confirmed_count": 0,
        "skipped_count": 0,
        "decision_ids": [],
        "finding_ids": [],
        "skipped": [],
    }

    for raw in packs_raw:
        if not isinstance(raw, dict):
            continue
        pack = EvidencePack.model_validate(raw)
        if category_filter and str(pack.owasp_category or "") != category_filter:
            continue
        if vuln_filter and str(pack.vulnerability_class or "") != vuln_filter:
            continue
        if pack.status != EvidencePackStatus.ready_for_judge or not pack.judge_ready:
            summary["skipped_count"] += 1
            summary["skipped"].append({"evidence_id": pack.evidence_id, "reason": "not_judge_ready"})
            continue
        if pack.evidence_id in judged_evidence_ids:
            summary["skipped_count"] += 1
            summary["skipped"].append({"evidence_id": pack.evidence_id, "reason": "already_judged"})
            continue
        if pack.evidence_id in confirmed_evidence_ids:
            summary["skipped_count"] += 1
            summary["skipped"].append({"evidence_id": pack.evidence_id, "reason": "already_confirmed"})
            continue

        if str(pack.owasp_category or "") == "API7_SERVER_SIDE_REQUEST_FORGERY":
            eligible, reason = _is_api7_ssrf_callback_proof_eligible(pack)
        elif str(pack.owasp_category or "") == "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION":
            eligible, reason = _is_api1_bola_replay_eligible(pack)
        else:
            eligible, reason = False, "unsupported_category_for_auto_judge"
        if not eligible:
            summary["skipped_count"] += 1
            summary["skipped"].append({"evidence_id": pack.evidence_id, "reason": reason})
            continue

        candidate_class = "server_side_request_forgery"
        verdict_reason = "Controlled SSRF callback proof was observed for the selected URL-like field."
        verdict_confidence = 0.95
        verdict_source = "deterministic_ssrf_callback_proof"
        if str(pack.owasp_category or "") == "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION":
            candidate_class = "broken_object_level_authorization"
            verdict_reason = "Owner baseline succeeded and attacker replay also succeeded for the same object pair, indicating broken object-level authorization."
            verdict_confidence = 0.9
            verdict_source = "deterministic_bola_replay_proof"

        req = JudgeApplyRequest(
            campaign_id=cid,
            evidence_id=pack.evidence_id,
            verdict=JudgeVerdictPayload(
                schema_version="judge-verdict/v1",
                verdict=JudgeVerdictKind.confirmed,
                confidence=verdict_confidence,
                severity="high",
                reason=verdict_reason,
                finding_candidate=FindingCandidatePayload(
                    vulnerability_class=candidate_class,
                ),
                judge_source=verdict_source,
                judge_model="deterministic",
            ),
            create_rework_on_inconclusive=False,
        )
        result, error = service.apply(req)
        if error is not None or result is None:
            summary["skipped_count"] += 1
            summary["skipped"].append({
                "evidence_id": pack.evidence_id,
                "reason": f"judge_apply_error:{getattr(error, 'code', 'unknown')}",
            })
            continue
        summary["applied_count"] += 1
        if str(result.decision_id or "").strip():
            summary["decision_ids"].append(str(result.decision_id))
        if str(result.finding_id or "").strip():
            summary["finding_ids"].append(str(result.finding_id))
            summary["confirmed_count"] += 1

    return summary
