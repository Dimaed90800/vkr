"""Phase 11A — injectable ZAP discovery/passive client.

This client is intentionally separate from the legacy ZAP helpers. It only
uses discovery/passive endpoints and is injectable so tests can run with a
mocked transport and no real network I/O.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from time import monotonic, sleep
from typing import Any

import httpx


@dataclass
class ZapPassiveClientError(Exception):
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


@dataclass
class ZapPassiveResult:
    version: str = ""
    discovered_urls: list[str] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ZapPassiveClient:
    def __init__(
        self,
        base_url: str | None = None,
        *,
        timeout_sec: float = 10,
        transport: httpx.BaseTransport | None = None,
        sleep_func=sleep,
    ) -> None:
        self.base_url = str(base_url or os.getenv("ZAP_BASE_URL") or "http://zap:8080").rstrip("/")
        self.timeout_sec = float(timeout_sec or 10)
        self._transport = transport
        self._sleep = sleep_func

    def version(self) -> str:
        data = self._get_json("/JSON/core/view/version/")
        return str(data.get("version") or "")

    def spider_scan(self, target_url: str, *, max_children: int = 50) -> str:
        data = self._get_json(
            "/JSON/spider/action/scan/",
            params={
                "url": target_url,
                "maxChildren": max(1, int(max_children or 1)),
                "recurse": "true",
            },
        )
        scan_id = str(data.get("scan") or "")
        if not scan_id:
            raise ZapPassiveClientError(
                code="zap_api_error",
                message="ZAP spider did not return a scan id.",
                details={"endpoint": "spider/action/scan"},
            )
        return scan_id

    def spider_status(self, scan_id: str) -> int:
        data = self._get_json("/JSON/spider/view/status/", params={"scanId": scan_id})
        try:
            return int(str(data.get("status") or "0"))
        except ValueError:
            return 0

    def core_urls(self, base_url: str) -> list[str]:
        data = self._get_json("/JSON/core/view/urls/", params={"baseurl": base_url})
        return _string_list(data.get("urls") or [])

    def passive_records_to_scan(self) -> int:
        data = self._get_json("/JSON/pscan/view/recordsToScan/")
        try:
            return int(str(data.get("recordsToScan") or "0"))
        except ValueError:
            return 0

    def alerts(self, base_url: str, *, start: int = 0, count: int = 100) -> list[dict[str, Any]]:
        data = self._get_json(
            "/JSON/alert/view/alerts/",
            params={
                "baseurl": base_url,
                "start": max(0, int(start or 0)),
                "count": max(1, int(count or 1)),
            },
        )
        rows = data.get("alerts") or []
        return [dict(row) for row in rows if isinstance(row, dict)]

    def run_discovery_passive(
        self,
        *,
        target_url: str,
        seed_urls: list[str] | None = None,
        use_spider: bool = True,
        max_children: int = 50,
        max_duration_sec: int = 30,
        max_discovered_urls: int = 100,
        max_alerts: int = 100,
    ) -> ZapPassiveResult:
        metadata: dict[str, Any] = {
            "zap_base_url": self.base_url,
            "use_spider": bool(use_spider),
            "seed_url_total": len(seed_urls or []),
        }
        version = self.version()
        metadata["version"] = version

        discovered: list[str] = []
        targets = _dedupe([target_url, *(seed_urls or [])])
        deadline = monotonic() + max(1, int(max_duration_sec or 1))
        if use_spider:
            for url in targets:
                if monotonic() >= deadline:
                    raise ZapPassiveClientError(
                        code="zap_spider_timeout",
                        message="ZAP spider timed out before all seed URLs completed.",
                        details={"target_url": target_url},
                    )
                scan_id = self.spider_scan(url, max_children=max_children)
                last_status = 0
                while monotonic() < deadline:
                    last_status = self.spider_status(scan_id)
                    if last_status >= 100:
                        break
                    self._sleep(0.25)
                if last_status < 100:
                    raise ZapPassiveClientError(
                        code="zap_spider_timeout",
                        message="ZAP spider did not complete within max_duration_sec.",
                        details={"scan_id": scan_id, "status": last_status},
                    )
                discovered.extend(self.core_urls(url))
        else:
            for url in targets:
                discovered.extend(self.core_urls(url))

        passive_last = self.passive_records_to_scan()
        while passive_last > 0 and monotonic() < deadline:
            self._sleep(0.25)
            passive_last = self.passive_records_to_scan()
        if passive_last > 0:
            raise ZapPassiveClientError(
                code="zap_passive_timeout",
                message="ZAP passive scan queue did not drain within max_duration_sec.",
                details={"records_to_scan": passive_last},
            )

        discovered = _dedupe(discovered)[:max(1, int(max_discovered_urls or 1))]
        alerts = self.alerts(target_url, count=max(1, int(max_alerts or 1)))
        metadata["discovered_url_total"] = len(discovered)
        metadata["alert_total"] = len(alerts)
        return ZapPassiveResult(
            version=version,
            discovered_urls=discovered,
            alerts=alerts,
            metadata=metadata,
        )

    def _get_json(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            with httpx.Client(
                transport=self._transport,
                timeout=self.timeout_sec,
                follow_redirects=False,
            ) as client:
                response = client.get(f"{self.base_url}{path}", params=params or None)
                response.raise_for_status()
                data = response.json()
        except httpx.ConnectError as exc:
            raise ZapPassiveClientError(
                code="zap_unreachable",
                message="ZAP API is unreachable.",
                details={"error": str(exc), "base_url": self.base_url},
            ) from exc
        except httpx.TimeoutException as exc:
            raise ZapPassiveClientError(
                code="zap_unreachable",
                message="ZAP API request timed out.",
                details={"error": str(exc), "base_url": self.base_url},
            ) from exc
        except httpx.HTTPError as exc:
            raise ZapPassiveClientError(
                code="zap_api_error",
                message="ZAP API request failed.",
                details={"error": str(exc), "base_url": self.base_url, "path": path},
            ) from exc
        except ValueError as exc:
            raise ZapPassiveClientError(
                code="zap_api_error",
                message="ZAP API returned invalid JSON.",
                details={"error": str(exc), "base_url": self.base_url, "path": path},
            ) from exc
        if not isinstance(data, dict):
            raise ZapPassiveClientError(
                code="zap_api_error",
                message="ZAP API returned an unexpected JSON shape.",
                details={"base_url": self.base_url, "path": path},
            )
        return data


def _string_list(values: Any) -> list[str]:
    if not isinstance(values, list):
        return []
    return [str(value) for value in values if str(value or "").strip()]


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        item = str(value or "").strip()
        if not item or item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out
