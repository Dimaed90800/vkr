"""Phase 9A — scoped HTTP replay client.

This client is intentionally small and injectable so tests can use a mocked
transport. It enforces campaign scope immediately before sending requests.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunsplit

import httpx

try:
    from backend.models.campaign import Campaign
    from backend.services.request_corpus_service import redact_sensitive_data
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from services.request_corpus_service import redact_sensitive_data


REDACTED_COOKIE_VALUE = "<redacted>"


def sanitize_url_for_storage(url: str) -> str:
    raw = str(url or "")
    parsed = urlparse(raw)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host
    if parsed.port is not None:
        netloc = f"{netloc}:{parsed.port}"
    redacted_pairs = [
        (key, "<redacted>")
        for key, _ in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    safe_query = urlencode(redacted_pairs, doseq=True)
    return urlunsplit((parsed.scheme, netloc, parsed.path, safe_query, parsed.fragment))


@dataclass
class SafeHttpError:
    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class SafeHttpResult:
    method: str
    url: str
    status_code: int = 0
    response_body: Any = None
    response_content_type: str = ""
    request_headers_redacted: dict[str, Any] = field(default_factory=dict)
    request_cookies_redacted: dict[str, Any] = field(default_factory=dict)
    request_body_redacted: Any = None
    response_headers_redacted: dict[str, Any] = field(default_factory=dict)
    cookie_summaries: list[dict[str, Any]] = field(default_factory=list)
    error: SafeHttpError | None = None
    _raw_response_body: Any = field(default=None, repr=False)
    _raw_response_cookies: dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def ok(self) -> bool:
        return self.error is None and self.status_code > 0

    def get_raw_response_body(self) -> Any:
        return self._raw_response_body

    def get_raw_response_cookies(self) -> dict[str, Any]:
        return dict(self._raw_response_cookies)


class SafeHttpClient:
    def __init__(
        self,
        *,
        transport: httpx.BaseTransport | None = None,
        max_response_bytes: int = 1024 * 1024,
        follow_redirects: bool = False,
    ) -> None:
        self._transport = transport
        self._max_response_bytes = max(1, int(max_response_bytes or 1))
        self._follow_redirects = follow_redirects

    def request(
        self,
        campaign: Campaign,
        *,
        method: str,
        url: str,
        query: dict[str, Any] | None = None,
        headers: dict[str, Any] | None = None,
        cookies: dict[str, Any] | None = None,
        body: Any = None,
        timeout_sec: float = 10,
        max_response_bytes: int | None = None,
        follow_redirects: bool | None = None,
    ) -> SafeHttpResult:
        method = (method or "GET").upper()
        resolved_url = self._resolve_url(campaign, url)
        storage_url = sanitize_url_for_storage(resolved_url)
        headers = dict(headers or {})
        cookies = dict(cookies or {})
        request_headers_redacted, request_body_redacted = redact_sensitive_data(headers, body)
        request_cookies_redacted = {
            str(k): REDACTED_COOKIE_VALUE for k in cookies
        }

        base_result = SafeHttpResult(
            method=method,
            url=storage_url,
            request_headers_redacted=request_headers_redacted,
            request_cookies_redacted=request_cookies_redacted,
            request_body_redacted=request_body_redacted,
        )

        scope_error = self._scope_error(campaign, resolved_url)
        if scope_error is not None:
            base_result.error = scope_error
            return base_result

        max_bytes = max(1, int(max_response_bytes or self._max_response_bytes))
        allow_redirects = self._follow_redirects if follow_redirects is None else follow_redirects
        if allow_redirects:
            base_result.error = SafeHttpError(
                code="redirect_not_supported",
                message="follow_redirects=true is not supported in Phase 9A.",
                details={"url": storage_url},
            )
            return base_result

        try:
            with httpx.Client(
                transport=self._transport,
                timeout=timeout_sec,
                follow_redirects=False,
                cookies=cookies or None,
            ) as client:
                response = client.request(
                    method,
                    resolved_url,
                    params=query or None,
                    headers=headers or None,
                    json=body if isinstance(body, (dict, list)) else None,
                    content=body if isinstance(body, (str, bytes)) else None,
                )
        except httpx.TimeoutException as exc:
            base_result.error = SafeHttpError(
                code="timeout",
                message="HTTP replay timed out.",
                details={"url": storage_url, "error": str(exc)},
            )
            return base_result
        except httpx.RequestError as exc:
            base_result.error = SafeHttpError(
                code="network_error",
                message="HTTP replay failed before a response was received.",
                details={"url": storage_url, "error": str(exc)},
            )
            return base_result

        base_result.status_code = response.status_code
        base_result.response_content_type = response.headers.get("content-type", "")
        base_result.cookie_summaries = _parse_set_cookie_summaries(
            response.headers.get_list("set-cookie"),
            campaign_id=campaign.campaign_id,
            is_https=urlparse(resolved_url).scheme.lower() == "https",
        )
        base_result._raw_response_cookies = dict(response.cookies.items())
        base_result.response_headers_redacted, _ = redact_sensitive_data(dict(response.headers), None)

        location = response.headers.get("location")
        if 300 <= response.status_code <= 399 and location:
            redirect_url = urljoin(resolved_url, location)
            redirect_error = self._scope_error(campaign, redirect_url)
            if redirect_error is not None:
                redirect_error.code = "redirect_host_not_allowed"
                redirect_error.message = "Redirect target is outside campaign allowed_hosts."
                base_result.error = redirect_error
                return base_result
            if not allow_redirects:
                base_result.error = SafeHttpError(
                    code="redirect_not_allowed",
                    message="Redirect response was not followed because redirects are disabled.",
                    details={"url": storage_url, "location": location},
                )
                return base_result

        content = response.content or b""
        if len(content) > max_bytes:
            base_result.error = SafeHttpError(
                code="response_too_large",
                message="HTTP response exceeded max_response_bytes.",
                details={
                    "url": storage_url,
                    "size_bytes": len(content),
                    "max_response_bytes": max_bytes,
                },
            )
            return base_result

        parsed_body = self._parse_response_body(content, base_result.response_content_type)
        base_result._raw_response_body = parsed_body
        _, redacted_response = redact_sensitive_data(None, parsed_body)
        base_result.response_body = redacted_response
        return base_result

    def _resolve_url(self, campaign: Campaign, url: str) -> str:
        raw = str(url or "")
        parsed = urlparse(raw)
        if parsed.scheme:
            return raw
        return urljoin(campaign.target_url.rstrip("/") + "/", raw.lstrip("/"))

    def _scope_error(self, campaign: Campaign, url: str) -> SafeHttpError | None:
        storage_url = sanitize_url_for_storage(url)
        parsed = urlparse(url)
        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"}:
            return SafeHttpError(
                code="invalid_scheme",
                message=f"URL scheme '{scheme}' is not allowed.",
                details={"url": storage_url, "scheme": scheme},
            )

        host = (parsed.hostname or "").lower()
        port = parsed.port
        host_port = f"{host}:{port}" if port is not None else host
        allowed = {str(h).lower() for h in campaign.allowed_hosts}
        if not allowed:
            return SafeHttpError(
                code="allowed_hosts_not_configured",
                message="Campaign allowed_hosts is empty; outbound replay is blocked.",
                details={"url": storage_url},
            )
        if host not in allowed and host_port not in allowed:
            return SafeHttpError(
                code="host_not_allowed",
                message=f"Host '{host_port}' is not in campaign allowed_hosts.",
                details={
                    "url": storage_url,
                    "host": host,
                    "host_port": host_port,
                    "allowed_hosts": campaign.allowed_hosts,
                },
            )
        return None

    @staticmethod
    def _parse_response_body(content: bytes, content_type: str) -> Any:
        if not content:
            return None
        lowered = (content_type or "").lower()
        text = content.decode("utf-8", errors="replace")
        if "json" in lowered:
            try:
                return json.loads(text)
            except json.JSONDecodeError:
                return text
        return text


def _parse_set_cookie_summaries(
    header_values: list[str],
    *,
    campaign_id: str,
    is_https: bool,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for raw_header in header_values or []:
        if not isinstance(raw_header, str):
            continue
        line = raw_header.strip()
        if not line:
            continue
        segments = [segment.strip() for segment in line.split(";") if segment.strip()]
        if not segments:
            continue
        name_value = segments[0]
        if "=" not in name_value:
            continue
        cookie_name = name_value.split("=", 1)[0].strip().lower()
        if not cookie_name:
            continue

        has_httponly = False
        has_secure = False
        samesite_state = "missing"
        for attr in segments[1:]:
            attr_name, _, attr_value = attr.partition("=")
            normalized_name = attr_name.strip().lower()
            normalized_value = attr_value.strip().lower()
            if normalized_name == "httponly":
                has_httponly = True
            elif normalized_name == "secure":
                has_secure = True
            elif normalized_name == "samesite":
                if normalized_value in {"none", "lax", "strict"}:
                    samesite_state = normalized_value
                elif normalized_value:
                    samesite_state = "unknown"

        name_hash = hashlib.sha256(
            f"{campaign_id}|{cookie_name}".encode("utf-8")
        ).hexdigest()[:16]
        summaries.append({
            "cookie_name_hash": name_hash,
            "has_httponly": has_httponly,
            "has_secure": has_secure,
            "samesite_state": samesite_state,
            "is_https": is_https,
        })
    return summaries
