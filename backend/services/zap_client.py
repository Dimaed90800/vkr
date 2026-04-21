from __future__ import annotations

from collections.abc import Sequence
import logging
from time import monotonic, sleep
from urllib.parse import urljoin

import httpx


logger = logging.getLogger(__name__)


class ZapClient:
    def __init__(self, base_url: str, timeout_sec: int = 10) -> None:
        self.base_url = str(base_url or "").rstrip("/")
        self.timeout_sec = timeout_sec

    def discover_urls(
        self,
        target_url: str,
        *,
        seed_urls: Sequence[str] | None = None,
        use_spider: bool = True,
        use_ajax_spider: bool = False,
        max_children: int = 50,
        max_duration_sec: int = 120,
    ) -> tuple[list[str], dict[str, object]]:
        urls: list[str] = []
        start_urls = self._dedupe([target_url, *(seed_urls or [])])
        metadata = {
            "source": "zap",
            "zap_base_url": self.base_url,
            "connection_attempted": True,
            "connection_ok": False,
            "spider_used": bool(use_spider),
            "ajax_spider_used": bool(use_ajax_spider),
            "seed_url_total": len(start_urls),
        }
        with httpx.Client(timeout=self.timeout_sec) as client:
            version_response = client.get(f"{self.base_url}/JSON/core/view/version/")
            version_response.raise_for_status()
            metadata["connection_ok"] = True
            metadata["version"] = str((version_response.json() or {}).get("version") or "")
            if use_spider:
                spider_urls = []
                for start_url in start_urls:
                    spider_urls.extend(
                        self._run_spider(
                            client,
                            target_url=start_url,
                            max_children=max_children,
                            max_duration_sec=max_duration_sec,
                        )
                    )
                urls.extend(spider_urls)
                metadata["spider_url_total"] = len(spider_urls)
            if use_ajax_spider:
                ajax_urls = []
                for start_url in start_urls:
                    ajax_urls.extend(
                        self._run_ajax_spider(
                            client,
                            target_url=start_url,
                            max_duration_sec=max_duration_sec,
                        )
                    )
                urls.extend(ajax_urls)
                metadata["ajax_url_total"] = len(ajax_urls)
            access_urls = []
            for start_url in start_urls:
                access_urls.extend(self._access_url(client, start_url))
            urls.extend(access_urls)
            metadata["access_url_total"] = len(access_urls)
        return self._dedupe([*start_urls, *urls]), metadata

    def health_check(
        self,
        *,
        target_url: str,
        max_duration_sec: int = 15,
    ) -> dict[str, object]:
        diagnostics: dict[str, object] = {
            "zap_reachable": False,
            "zap_version": None,
            "target_reachable_from_zap": False,
            "spider_completed": False,
            "urls_discovered": 0,
            "api_like_urls": 0,
            "diagnosis": "",
            "recommendation": "",
            "stage": "connect_zap",
            "error": "",
            "raw_urls": [],
            "spider_status": "",
            "only_static_content_detected": False,
            "zap_base_url": self.base_url,
            "target_url": target_url,
        }
        with httpx.Client(timeout=self.timeout_sec) as client:
            logger.info("ZAP health check connect zap_base_url=%s target_url=%s", self.base_url, target_url)
            try:
                version_response = client.get(f"{self.base_url}/JSON/core/view/version/")
                version_response.raise_for_status()
            except Exception as exc:
                logger.warning("ZAP health check failed stage=connect_zap zap_base_url=%s error=%s", self.base_url, exc)
                diagnostics["error"] = str(exc)
                diagnostics["stage"] = "connect_zap"
                return diagnostics

            diagnostics["zap_reachable"] = True
            diagnostics["zap_version"] = str((version_response.json() or {}).get("version") or "")

            try:
                access_response = client.get(
                    f"{self.base_url}/JSON/core/action/accessUrl/",
                    params={"url": target_url, "followRedirects": "true"},
                )
                access_response.raise_for_status()
                diagnostics["target_reachable_from_zap"] = True
            except Exception as exc:
                logger.warning("ZAP health check failed stage=reach_target_from_zap target_url=%s error=%s", target_url, exc)
                diagnostics["error"] = str(exc)
                diagnostics["stage"] = "reach_target_from_zap"
                return diagnostics

            try:
                scan_response = client.get(
                    f"{self.base_url}/JSON/spider/action/scan/",
                    params={"url": target_url, "maxChildren": 10, "recurse": "true"},
                )
                scan_response.raise_for_status()
                scan_id = str((scan_response.json() or {}).get("scan") or "")
                if not scan_id:
                    diagnostics["stage"] = "spider_scan"
                    diagnostics["error"] = "missing_scan_id"
                    return diagnostics

                deadline = monotonic() + max_duration_sec
                last_status = "0"
                while monotonic() < deadline:
                    status_response = client.get(
                        f"{self.base_url}/JSON/spider/view/status/",
                        params={"scanId": scan_id},
                    )
                    status_response.raise_for_status()
                    last_status = str((status_response.json() or {}).get("status") or "0")
                    diagnostics["spider_status"] = last_status
                    logger.info("ZAP spider status target_url=%s status=%s", target_url, last_status)
                    if int(last_status) >= 100:
                        diagnostics["spider_completed"] = True
                        break
                    sleep(1)
                if not diagnostics["spider_completed"]:
                    diagnostics["stage"] = "spider_scan"
                    diagnostics["error"] = f"spider_timeout_status_{last_status}"
                    return diagnostics

                urls_response = client.get(
                    f"{self.base_url}/JSON/core/view/urls/",
                    params={"baseurl": target_url},
                )
                urls_response.raise_for_status()
                urls = [str(item) for item in ((urls_response.json() or {}).get("urls") or []) if str(item).strip()]
                diagnostics["raw_urls"] = urls
                diagnostics["urls_discovered"] = len(urls)
                api_like_urls = [item for item in urls if self._is_api_like_url(item)]
                diagnostics["api_like_urls"] = len(api_like_urls)

                if not urls:
                    diagnostics["stage"] = "collect_urls"
                    diagnostics["diagnosis"] = "no_urls_discovered"
                    diagnostics["recommendation"] = "verify_target_routing_or_try_browser_capture"
                    diagnostics["error"] = "spider_returned_no_urls"
                    return diagnostics
                if self._only_static_content(urls):
                    diagnostics["diagnosis"] = "only_static_content_detected"
                    diagnostics["recommendation"] = "use_browser_capture_or_authenticated_discovery"
                    diagnostics["only_static_content_detected"] = True
                    return diagnostics
                if diagnostics["api_like_urls"] == 0:
                    diagnostics["diagnosis"] = "spa_detected_no_api_via_spider"
                    diagnostics["recommendation"] = "use_browser_capture_or_authenticated_discovery"
                    return diagnostics

                diagnostics["diagnosis"] = "ok"
                diagnostics["recommendation"] = "proceed_with_discovery"
                diagnostics["stage"] = "completed"
                return diagnostics
            except Exception as exc:
                diagnostics["error"] = str(exc)
                diagnostics["stage"] = diagnostics.get("stage") or "spider_scan"
                return diagnostics

    def _run_spider(
        self,
        client: httpx.Client,
        *,
        target_url: str,
        max_children: int,
        max_duration_sec: int,
    ) -> list[str]:
        response = client.get(
            f"{self.base_url}/JSON/spider/action/scan/",
            params={
                "url": target_url,
                "maxChildren": max_children,
                "recurse": "true",
            },
        )
        response.raise_for_status()
        scan_id = str((response.json() or {}).get("scan") or "")
        if not scan_id:
            return []

        deadline = monotonic() + max_duration_sec
        while monotonic() < deadline:
            status_response = client.get(
                f"{self.base_url}/JSON/spider/view/status/",
                params={"scanId": scan_id},
            )
            status_response.raise_for_status()
            status_value = int(str((status_response.json() or {}).get("status") or "0"))
            if status_value >= 100:
                break
            sleep(1)

        results_response = client.get(
            f"{self.base_url}/JSON/spider/view/results/",
            params={"scanId": scan_id},
        )
        results_response.raise_for_status()
        results = (results_response.json() or {}).get("results") or []
        return [str(item) for item in results if str(item).strip()]

    def _run_ajax_spider(
        self,
        client: httpx.Client,
        *,
        target_url: str,
        max_duration_sec: int,
    ) -> list[str]:
        response = client.get(
            f"{self.base_url}/JSON/ajaxSpider/action/scan/",
            params={"url": target_url},
        )
        response.raise_for_status()

        deadline = monotonic() + max_duration_sec
        while monotonic() < deadline:
            status_response = client.get(f"{self.base_url}/JSON/ajaxSpider/view/status/")
            status_response.raise_for_status()
            status_value = str((status_response.json() or {}).get("status") or "").lower()
            if status_value == "stopped":
                break
            sleep(1)

        results_response = client.get(f"{self.base_url}/JSON/ajaxSpider/view/results/")
        results_response.raise_for_status()
        results = (results_response.json() or {}).get("results") or []
        return [str(item) for item in results if str(item).strip()]

    def _access_url(self, client: httpx.Client, target_url: str) -> list[str]:
        response = client.get(
            f"{self.base_url}/JSON/core/action/accessUrl/",
            params={
                "url": target_url,
                "followRedirects": "true",
            },
        )
        response.raise_for_status()
        response_url = client.get(
            f"{self.base_url}/JSON/core/view/urls/",
            params={"baseurl": target_url},
        )
        response_url.raise_for_status()
        results = (response_url.json() or {}).get("urls") or []
        absolute_results = [urljoin(target_url, str(item)) for item in results if str(item).strip()]
        return [target_url, *absolute_results]

    def _dedupe(self, values: Sequence[str]) -> list[str]:
        seen: set[str] = set()
        deduped: list[str] = []
        for item in values:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            seen.add(value)
            deduped.append(value)
        return deduped

    def _is_api_like_url(self, raw_url: str) -> bool:
        path = str(httpx.URL(raw_url).path or "").lower()
        return any(
            path == prefix or path.startswith(prefix + "/")
            for prefix in (
                "/api",
                "/v1",
                "/v2",
                "/v3",
                "/auth",
                "/login",
                "/register",
                "/identity",
                "/community",
                "/workshop",
                "/user",
                "/account",
                "/profile",
                "/orders",
            )
        )

    def _only_static_content(self, urls: Sequence[str]) -> bool:
        filtered = []
        for item in urls:
            path = str(httpx.URL(str(item)).path or "").lower()
            if not path:
                continue
            filtered.append(path)
        if not filtered:
            return False
        return all(
            path == "/"
            or path.startswith("/static/")
            or path.startswith("/images/")
            or path.startswith("/assets/")
            for path in filtered
        )
