from __future__ import annotations

import time
from typing import Any

from .openapi_service import find_openapi_document
from .zap_service import (
    import_openapi_url,
    list_alerts,
    number_of_messages,
    run_active_scan_and_wait,
    run_ajax_spider_and_wait,
    run_spider_and_wait,
)


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _dedupe_alerts(alert_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str, str]] = set()
    unique_rows: list[dict[str, Any]] = []

    for row in alert_rows or []:
        if not isinstance(row, dict):
            continue
        key = (
            str(row.get("pluginId") or ""),
            str(row.get("url") or ""),
            str(row.get("param") or ""),
            str(row.get("alertRef") or row.get("name") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(row)

    return unique_rows


def _risk_counts(alert_rows: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for row in alert_rows or []:
        risk = str(row.get("risk") or row.get("riskdesc") or "").lower()
        if risk.startswith("high"):
            counts["high"] += 1
        elif risk.startswith("medium"):
            counts["medium"] += 1
        elif risk.startswith("low"):
            counts["low"] += 1
        else:
            counts["informational"] += 1
    return counts


def run_zap_baseline(
    *,
    target_name: str,
    target_url: str,
    profile: str = "mixed",
    max_spider_sec: int = 120,
    max_active_sec: int = 300,
    use_ajax_spider: bool = False,
    import_openapi: bool = True,
) -> dict[str, Any]:
    started_at = time.time()
    requests_before = _safe_int((number_of_messages() or {}).get("numberOfMessages"))

    openapi_url = None
    openapi_imported = False
    if import_openapi:
        try:
            openapi_url, spec = find_openapi_document(target_url)
            if openapi_url and spec:
                import_openapi_url(openapi_url, target=target_url)
                openapi_imported = True
        except Exception:
            openapi_url = None
            openapi_imported = False

    run_spider_and_wait(target_url, max_wait_sec=max_spider_sec)
    if use_ajax_spider:
        run_ajax_spider_and_wait(target_url, max_wait_sec=max_spider_sec)
    run_active_scan_and_wait(target_url, max_wait_sec=max_active_sec)

    alert_rows = _dedupe_alerts((list_alerts(target_url) or {}).get("alerts") or [])
    requests_after = _safe_int((number_of_messages() or {}).get("numberOfMessages"))
    requests_used = max(0, requests_after - requests_before)
    time_used = int(max(0, round(time.time() - started_at)))
    risk_counts = _risk_counts(alert_rows)

    # Classical ZAP is used here as a generic DAST baseline. Raw alerts are tracked
    # separately from confirmed logical API findings such as BOLA/BOPLA/auth.
    return {
        "name": "OWASP ZAP Baseline",
        "tool": "zap",
        "profile": profile,
        "target_name": target_name,
        "findings_total": len(alert_rows),
        "confirmed_findings": 0,
        "confirmed_bola": 0,
        "confirmed_bopla": 0,
        "confirmed_auth_findings": 0,
        "fallback_count": 0,
        "avg_score": 0.0,
        "requests_used": requests_used,
        "time_used": time_used,
        "notes": {
            "alerts_total": len(alert_rows),
            "risk_counts": risk_counts,
            "openapi_imported": openapi_imported,
            "openapi_url": openapi_url,
            "use_ajax_spider": bool(use_ajax_spider),
        },
    }
