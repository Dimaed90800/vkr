"""Helpers for matching runtime-discovered paths against the OpenAPI graph."""
from __future__ import annotations

import re
from urllib.parse import urlparse

try:
    from backend.services.api_graph_service import ApiGraphService
except ModuleNotFoundError:  # pragma: no cover
    from services.api_graph_service import ApiGraphService


_STATIC_PREFIXES = (
    "/static/",
    "/images/",
)
_STATIC_EXACT = {
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
}
_STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".map",
)


def normalize_api_path(path_or_url: str) -> str:
    raw = str(path_or_url or "").strip()
    if not raw:
        return "/"
    parsed = urlparse(raw)
    path = parsed.path if parsed.scheme or parsed.netloc else raw.split("?", 1)[0].split("#", 1)[0]
    path = str(path or "/").strip() or "/"
    if not path.startswith("/"):
        path = f"/{path}"
    if len(path) > 1:
        path = path.rstrip("/") or "/"
    return path


def is_static_or_service_asset(path: str) -> bool:
    normalized = normalize_api_path(path).lower()
    if normalized in _STATIC_EXACT:
        return True
    if any(normalized.startswith(prefix) for prefix in _STATIC_PREFIXES):
        return True
    return any(normalized.endswith(suffix) for suffix in _STATIC_SUFFIXES)


def template_matches(template: str, path: str) -> bool:
    normalized_template = normalize_api_path(template)
    normalized_path = normalize_api_path(path)
    if normalized_template == normalized_path:
        return True
    template_parts = [part for part in normalized_template.split("/") if part]
    path_parts = [part for part in normalized_path.split("/") if part]
    if len(template_parts) != len(path_parts):
        return False
    for template_part, path_part in zip(template_parts, path_parts, strict=True):
        if template_part.startswith("{") and template_part.endswith("}") and len(template_part) > 2:
            continue
        if template_part != path_part:
            return False
    return True


_ROUTE_FRAGMENT_SUFFIX_CACHE: dict[tuple[str, int], dict[str, list[dict[str, str]]]] = {}


def clear_route_fragment_suffix_cache() -> None:
    """Invalidate suffix indexes (tests / graph reload)."""
    _ROUTE_FRAGMENT_SUFFIX_CACHE.clear()


def _graph_operations_count(campaign_id: str) -> int:
    return len(ApiGraphService().list_operations(campaign_id))


def _operation_suffix_entries(path_template: str) -> list[tuple[str, str]]:
    """Tails with >=2 segments: (lookup_key_lower, matched_suffix_display)."""
    normalized = normalize_api_path(path_template)
    parts = [p for p in normalized.strip("/").split("/") if p]
    n = len(parts)
    if n < 2:
        return []
    out: list[tuple[str, str]] = []
    for i in range(0, n - 1):
        tail = parts[i:]
        display = "/".join(tail)
        out.append((display.lower(), display))
    return out


def _build_route_fragment_suffix_index(campaign_id: str) -> dict[str, list[dict[str, str]]]:
    index: dict[str, list[dict[str, str]]] = {}
    graph = ApiGraphService()
    for operation in graph.list_operations(campaign_id):
        path_t = str(operation.path_template or "").strip()
        if not path_t:
            continue
        method_u = str(operation.method or "GET").strip().upper() or "GET"
        oid = str(operation.operation_id or "")
        normalized_path = normalize_api_path(path_t)
        for key_lower, matched_suffix in _operation_suffix_entries(path_t):
            index.setdefault(key_lower, []).append({
                "operation_id": oid,
                "method": method_u,
                "path_template": normalized_path,
                "matched_suffix": matched_suffix,
            })
    return index


def _get_route_fragment_suffix_index(campaign_id: str) -> dict[str, list[dict[str, str]]]:
    cache_key = (campaign_id, _graph_operations_count(campaign_id))
    if cache_key not in _ROUTE_FRAGMENT_SUFFIX_CACHE:
        _ROUTE_FRAGMENT_SUFFIX_CACHE[cache_key] = _build_route_fragment_suffix_index(campaign_id)
    return _ROUTE_FRAGMENT_SUFFIX_CACHE[cache_key]


def normalize_route_fragment_for_match(fragment: str) -> str:
    """Strip quotes/backticks, query/fragment; collapse slashes; strip leading slash."""
    t = str(fragment or "").strip().strip('`"\'')
    if not t or t.startswith("//"):
        return ""
    if "://" in t:
        parsed = urlparse(t)
        t = parsed.path or ""
    else:
        t = t.split("?", 1)[0].split("#", 1)[0]
    t = str(t).replace("\\/", "/")
    t = re.sub(r"/+", "/", t.strip())
    t = t.lstrip("/")
    t = re.sub(r"<([^>/]+)>", r"{\1}", t)
    return t.strip("/")


def match_route_fragment(
    campaign_id: str,
    fragment: str,
    method: str | None = None,
    limit: int = 3,
) -> list[dict[str, str]]:
    normalized = normalize_route_fragment_for_match(fragment)
    if not normalized:
        return []
    key_lower = normalized.lower()
    index = _get_route_fragment_suffix_index(campaign_id)
    if not index:
        return []
    candidates = list(index.get(key_lower, []))
    if method is not None:
        m_u = str(method).strip().upper()
        candidates = [c for c in candidates if str(c.get("method", "")).strip().upper() == m_u]
    seen: set[tuple[str, str, str, str]] = set()
    out: list[dict[str, str]] = []
    lim = max(1, int(limit))
    for c in candidates:
        tup = (
            str(c.get("operation_id", "")),
            str(c.get("method", "")),
            str(c.get("path_template", "")),
            str(c.get("matched_suffix", "")),
        )
        if tup in seen:
            continue
        seen.add(tup)
        out.append(dict(c))
        if len(out) >= lim:
            break
    return out


def find_openapi_operation_match(campaign_id: str, method: str, path: str) -> str:
    normalized_method = str(method or "").strip().upper()
    if not normalized_method:
        return ""
    normalized_path = normalize_api_path(path)
    graph = ApiGraphService()
    for operation in graph.list_operations(campaign_id):
        if str(operation.method or "").strip().upper() != normalized_method:
            continue
        if template_matches(str(operation.path_template or ""), normalized_path):
            return str(operation.operation_id or "")
    return ""
