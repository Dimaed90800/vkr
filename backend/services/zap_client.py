from __future__ import annotations

from collections.abc import Sequence
from time import monotonic, sleep
from urllib.parse import urljoin

import httpx


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
            "spider_used": bool(use_spider),
            "ajax_spider_used": bool(use_ajax_spider),
            "seed_url_total": len(start_urls),
        }
        with httpx.Client(timeout=self.timeout_sec) as client:
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
