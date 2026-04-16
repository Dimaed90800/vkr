import json
import logging
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode

import httpx


logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SEC = 8.0
DEFAULT_MAX_RESPONSE_BYTES = 32768


@dataclass
class HttpExecutionResult:
    method: str
    url: str
    status_code: int | None
    headers: dict[str, str]
    body_text: str
    elapsed_ms: float | None
    error: str | None = None

    def json_body(self) -> Any | None:
        try:
            return json.loads(self.body_text)
        except Exception:
            return None


class HttpClient:
    def __init__(
        self,
        timeout_sec: float = DEFAULT_TIMEOUT_SEC,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.max_response_bytes = max_response_bytes

    async def execute(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        query_params: dict[str, Any] | None = None,
        json_body: Any | None = None,
    ) -> HttpExecutionResult:
        headers = dict(headers or {})
        query_params = dict(query_params or {})
        request_url = self._build_url(url, query_params)
        method_norm = str(method or "GET").upper()

        logger.info(
            "Executing HTTP request method=%s url=%s timeout=%ss",
            method_norm,
            request_url,
            self.timeout_sec,
        )

        try:
            async with httpx.AsyncClient(timeout=self.timeout_sec, follow_redirects=True) as client:
                response = await client.request(
                    method_norm,
                    request_url,
                    headers=headers,
                    json=json_body,
                )
        except httpx.RequestError as exc:
            logger.warning("HTTP request failed method=%s url=%s error=%s", method_norm, request_url, exc)
            return HttpExecutionResult(
                method=method_norm,
                url=request_url,
                status_code=None,
                headers={},
                body_text="",
                elapsed_ms=None,
                error=str(exc),
            )

        body_bytes = response.content[: self.max_response_bytes]
        try:
            body_text = body_bytes.decode(response.encoding or "utf-8", errors="replace")
        except Exception:
            body_text = body_bytes.decode("utf-8", errors="replace")

        elapsed_ms = response.elapsed.total_seconds() * 1000 if response.elapsed else None
        header_map = {k.lower(): v for k, v in response.headers.items()}

        logger.info(
            "HTTP response method=%s url=%s status=%s elapsed_ms=%s",
            method_norm,
            request_url,
            response.status_code,
            round(elapsed_ms, 2) if elapsed_ms is not None else None,
        )

        return HttpExecutionResult(
            method=method_norm,
            url=request_url,
            status_code=response.status_code,
            headers=header_map,
            body_text=body_text,
            elapsed_ms=elapsed_ms,
            error=None,
        )

    def _build_url(self, base_url: str, query_params: dict[str, Any]) -> str:
        if not query_params:
            return base_url
        encoded = urlencode({k: "" if v is None else v for k, v in query_params.items()}, doseq=True)
        separator = "&" if "?" in base_url else "?"
        return f"{base_url}{separator}{encoded}"
