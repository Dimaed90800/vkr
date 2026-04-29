from __future__ import annotations

from typing import Any

try:
    from backend.services.auto_judge_service import apply_judge_for_ready_evidence_in_campaign
    from backend.models.observation import ObservationType
    from backend.services.evidence_pack_builder import EvidencePackBuilder
    from backend.services.ssrf_callback_store import get_effective_ssrf_callback_state
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from services.auto_judge_service import apply_judge_for_ready_evidence_in_campaign
    from models.observation import ObservationType
    from services.evidence_pack_builder import EvidencePackBuilder
    from services.ssrf_callback_store import get_effective_ssrf_callback_state
    from storage.memory_store import memory_store


def reconcile_and_build_ssrf_evidence_for_campaign(campaign_id: str) -> dict[str, Any]:
    cid = str(campaign_id or "").strip()
    if not cid:
        return {"campaign_id": cid, "processed": 0, "built_or_refreshed": 0}

    rows = memory_store.list_observations_by_campaign(cid)
    builder = EvidencePackBuilder()
    processed = 0
    built_or_refreshed = 0
    errors: list[str] = []

    for row in rows:
        if not isinstance(row, dict):
            continue
        if str(row.get("type") or row.get("observation_type") or "") != ObservationType.ssrf_probe_result.value:
            continue
        processed += 1
        details = row.get("details") if isinstance(row.get("details"), dict) else {}
        effective = get_effective_ssrf_callback_state({"details": details})
        if not bool(effective.get("callback_received_effective")):
            continue
        obs_id = str(row.get("observation_id") or "").strip()
        if not obs_id:
            continue
        pack, error, _existing = builder.build_from_observation(obs_id, campaign_id_hint=cid)
        if error is not None:
            errors.append(str(getattr(error, "code", "build_error")))
            continue
        if pack is not None:
            built_or_refreshed += 1

    judge_summary = apply_judge_for_ready_evidence_in_campaign(
        campaign_id=cid,
        owasp_category="API7_SERVER_SIDE_REQUEST_FORGERY",
        vulnerability_class="server_side_request_forgery",
        source="ssrf_late_callback_reconciliation",
    )

    return {
        "campaign_id": cid,
        "processed": processed,
        "built_or_refreshed": built_or_refreshed,
        "errors": errors[:10],
        "judge_auto_apply": judge_summary,
    }
