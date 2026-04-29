from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Mapping
from typing import Any

try:
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from storage.memory_store import memory_store


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_ip(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _sanitize_user_agent(value: str | None) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    # Keep a short, printable prefix only.
    raw = "".join(ch for ch in raw if 32 <= ord(ch) <= 126)
    return raw[:120]


class SsrfCallbackStore:
    """Runtime SSRF callback proof store (safe metadata only)."""

    def register_probe(
        self,
        *,
        campaign_id: str,
        operation_id: str,
        field_name: str,
        field_path: str,
        correlation_id: str,
        auth_mode: str = "unauthenticated",
        auth_profile_id: str = "",
        role_hint: str = "",
    ) -> dict[str, Any]:
        record = {
            "correlation_id": str(correlation_id or "").strip(),
            "campaign_id": str(campaign_id or "").strip(),
            "operation_id": str(operation_id or "").strip(),
            "field_name": str(field_name or "").strip(),
            "field_path": str(field_path or "").strip(),
            "auth_mode": str(auth_mode or "unauthenticated").strip(),
            "auth_profile_id": str(auth_profile_id or "").strip(),
            "role_hint": str(role_hint or "").strip(),
            "received": False,
            "received_at": "",
            "callback_method": "",
            "callback_path": "",
            "source_ip_hash": "",
            "user_agent_sanitized": "",
            "headers_count": 0,
            "created_at": _now_iso(),
        }
        memory_store.store_runtime_ssrf_callback(record["correlation_id"], record["campaign_id"], record)
        return dict(record)

    def record_callback(
        self,
        *,
        correlation_id: str,
        method: str,
        path: str,
        user_agent: str | None = None,
        source_ip: str | None = None,
        headers_count: int = 0,
    ) -> dict[str, Any]:
        cid = str(correlation_id or "").strip()
        existing = memory_store.get_runtime_ssrf_callback(cid) or {}
        campaign_id = str(existing.get("campaign_id") or "").strip()
        record = dict(existing) if existing else {
            "correlation_id": cid,
            "campaign_id": campaign_id,
            "operation_id": "",
            "field_name": "",
            "field_path": "",
            "auth_mode": "unauthenticated",
            "auth_profile_id": "",
            "role_hint": "",
            "created_at": _now_iso(),
        }
        record.update({
            "received": True,
            "received_at": _now_iso(),
            "callback_method": str(method or "").strip().upper()[:8],
            "callback_path": str(path or "").strip()[:256],
            "source_ip_hash": _hash_ip(str(source_ip or "")),
            "user_agent_sanitized": _sanitize_user_agent(user_agent),
            "headers_count": int(headers_count or 0),
        })
        # If this callback came before probe registration, keep it indexed under an empty campaign.
        memory_store.store_runtime_ssrf_callback(cid, campaign_id, record)
        return dict(record)

    def get_status(self, correlation_id: str) -> dict[str, Any]:
        cid = str(correlation_id or "").strip()
        existing = memory_store.get_runtime_ssrf_callback(cid) or {}
        if not existing:
            return {
                "correlation_id": cid,
                "received": False,
                "campaign_id": "",
                "operation_id": "",
                "field_name": "",
                "field_path": "",
                "auth_mode": "",
                "auth_profile_id": "",
                "role_hint": "",
                "callback_method": "",
                "headers_count": 0,
            }
        return {
            "correlation_id": cid,
            "received": bool(existing.get("received")),
            "campaign_id": str(existing.get("campaign_id") or ""),
            "operation_id": str(existing.get("operation_id") or ""),
            "field_name": str(existing.get("field_name") or ""),
            "field_path": str(existing.get("field_path") or ""),
            "auth_mode": str(existing.get("auth_mode") or ""),
            "auth_profile_id": str(existing.get("auth_profile_id") or ""),
            "role_hint": str(existing.get("role_hint") or ""),
            "callback_method": str(existing.get("callback_method") or ""),
            "headers_count": int(existing.get("headers_count") or 0),
        }

    def list_by_campaign(self, campaign_id: str) -> list[dict[str, Any]]:
        cid = str(campaign_id or "").strip()
        rows = memory_store.list_runtime_ssrf_callbacks_by_campaign(cid)
        # Return safe records only (no raw headers/body stored anyway).
        return [dict(r) for r in rows if isinstance(r, dict)]


def get_effective_ssrf_callback_state(observation_or_result: Mapping[str, Any] | None) -> dict[str, Any]:
    """Resolve effective SSRF callback proof state from observation + callback store.

    Safe metadata only. Never returns raw callback query/header values.
    """
    raw = observation_or_result if isinstance(observation_or_result, Mapping) else {}
    details = raw.get("details") if isinstance(raw.get("details"), Mapping) else raw
    details = details if isinstance(details, Mapping) else {}

    correlation_id = str(
        details.get("callback_correlation_id")
        or details.get("correlation_id")
        or raw.get("callback_correlation_id")
        or raw.get("correlation_id")
        or ""
    ).strip()
    observed_callback_received = bool(
        details.get("callback_received")
        if "callback_received" in details
        else raw.get("callback_received")
    )

    store_status = SsrfCallbackStore().get_status(correlation_id) if correlation_id else {}
    callback_store_received = bool(store_status.get("received")) if isinstance(store_status, dict) else False
    callback_received_effective = bool(observed_callback_received or callback_store_received)
    late_callback_reconciled = bool(callback_store_received and not observed_callback_received)

    callback_method = ""
    callback_headers_count = None
    if isinstance(store_status, dict):
        callback_method = str(store_status.get("callback_method") or "").strip().upper()
        try:
            callback_headers_count = int(store_status.get("headers_count"))
        except Exception:
            callback_headers_count = None

    reason_codes: list[str] = []
    if callback_received_effective:
        reason_codes.append("controlled_callback_received")
    if correlation_id and callback_received_effective:
        reason_codes.append("callback_correlation_matched")
    if late_callback_reconciled:
        reason_codes.append("late_callback_reconciled")

    return {
        "callback_received_effective": callback_received_effective,
        "late_callback_reconciled": late_callback_reconciled,
        "callback_correlation_id": correlation_id,
        "callback_method": callback_method or None,
        "callback_headers_count": callback_headers_count,
        "callback_store_received": callback_store_received,
        "reason_codes": reason_codes,
    }
