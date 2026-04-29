from __future__ import annotations

from typing import Any

try:
    from backend.storage.memory_store import memory_store as primary_memory_store
except ModuleNotFoundError:  # pragma: no cover
    from storage.memory_store import memory_store as primary_memory_store


def _candidate_stores() -> list[tuple[str, Any]]:
    stores: list[tuple[str, Any]] = [("backend.storage.memory_store", primary_memory_store)]
    try:  # pragma: no cover - defensive alias bridge
        from storage.memory_store import memory_store as alt_memory_store  # type: ignore
    except Exception:
        alt_memory_store = None
    if alt_memory_store is not None and alt_memory_store is not primary_memory_store:
        stores.append(("storage.memory_store", alt_memory_store))
    return stores


def _normalize_observation(raw: dict[str, Any], observation_id: str) -> dict[str, Any]:
    out = dict(raw)
    out.setdefault("observation_id", str(out.get("observation_id") or observation_id))
    out.setdefault("campaign_id", str(out.get("campaign_id") or ""))
    out.setdefault("type", str(out.get("type") or out.get("observation_type") or ""))
    out.setdefault("operation_id", str(out.get("operation_id") or ""))
    out.setdefault("details", out.get("details") if isinstance(out.get("details"), dict) else {})
    out.setdefault("tool_run_id", str(out.get("tool_run_id") or ""))
    out.setdefault("task_id", str(out.get("task_id") or ""))
    out.setdefault("command_id", str(out.get("command_id") or ""))
    out.setdefault("created_at", str(out.get("created_at") or ""))
    return out


def resolve_observation_for_evidence(
    observation_id: str,
    campaign_id: str | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    obs_id = str(observation_id or "").strip()
    campaign_hint = str(campaign_id or "").strip()
    searched: list[str] = []

    if not obs_id:
        return None, {
            "error": "observation_not_found",
            "searched_stores": searched,
            "observation_id": obs_id,
            "campaign_id_hint": campaign_hint,
        }

    for store_name, store in _candidate_stores():
        if store is None:
            continue
        searched.append(f"{store_name}:direct_get")
        raw = store.get_observation(obs_id)
        if isinstance(raw, dict):
            normalized = _normalize_observation(raw, obs_id)
            row_campaign = str(normalized.get("campaign_id") or "")
            if campaign_hint and row_campaign and row_campaign != campaign_hint:
                continue
            return normalized, None

    if campaign_hint:
        for store_name, store in _candidate_stores():
            searched.append(f"{store_name}:campaign_list")
            for row in store.list_observations_by_campaign(campaign_hint):
                if not isinstance(row, dict):
                    continue
                if str(row.get("observation_id") or "") == obs_id:
                    return _normalize_observation(row, obs_id), None

    for store_name, store in _candidate_stores():
        campaigns = list(getattr(store, "observations_by_campaign", {}).keys())
        for cid in campaigns:
            searched.append(f"{store_name}:campaign_scan:{cid}")
            for row in store.list_observations_by_campaign(str(cid)):
                if not isinstance(row, dict):
                    continue
                if str(row.get("observation_id") or "") == obs_id:
                    normalized = _normalize_observation(row, obs_id)
                    if campaign_hint and str(normalized.get("campaign_id") or "") not in {"", campaign_hint}:
                        continue
                    return normalized, None

    return None, {
        "error": "observation_not_found",
        "searched_stores": searched,
        "observation_id": obs_id,
        "campaign_id_hint": campaign_hint,
    }

