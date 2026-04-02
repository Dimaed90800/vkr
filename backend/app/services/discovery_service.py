import json
import re
from urllib.parse import urljoin, urlparse

import requests

from ..models import SurfaceInventory


def classify_asset(url_or_path: str) -> str:
    value = (url_or_path or "").lower()

    static_suffixes = (
        ".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
        ".ico", ".woff", ".woff2", ".ttf", ".map", ".txt", ".xml"
    )

    if value.endswith(static_suffixes):
        return "static"

    if "/api/" in value or value.endswith("/api"):
        return "api"

    if any(x in value for x in ["/static", "/images", "/assets", "/fonts"]):
        return "static"

    parsed = urlparse(value)
    path = parsed.path if parsed.scheme else value

    if path in ("", "/"):
        return "frontend"

    if any(x in path for x in ["/chatbot", "/genai", "/graphql", "/rpc"]):
        return "api"

    return "unknown"


def filter_urls_in_scope(target_url: str, urls: list[str]) -> list[str]:
    target = urlparse(target_url)
    target_host = target.netloc.lower()

    filtered = []
    seen = set()
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc and parsed.netloc.lower() != target_host:
            continue
        normalized = url.rstrip("/")
        if normalized in seen:
            continue
        seen.add(normalized)
        filtered.append(url)
    return filtered


def build_crapi_seed_urls(target_url: str) -> list[str]:
    base = target_url.rstrip("/")
    return [
        f"{base}/identity/api/auth/login",
        f"{base}/identity/api/auth/signup",
        f"{base}/identity/api/v2/vehicle/vehicles",
        f"{base}/identity/api/v2/vehicle/add_vehicle",
        f"{base}/community/api/v2/community/posts/recent",
        f"{base}/community/api/v2/community/posts",
        f"{base}/workshop/api/shop/products",
        f"{base}/workshop/api/mechanic/mechanics",
        f"{base}/workshop/api/merchant/contact_mechanic",
    ]


def _extract_candidate_api_paths_from_text(text: str) -> list[str]:
    patterns = re.findall(r'["\'](\/[^"\']*(?:api|identity|workshop|community)[^"\']*)["\']', text or "")
    results = []
    seen = set()
    for item in patterns:
        cleaned = item.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            results.append(cleaned)
    return results


def discover_api_paths_from_javascript(target_url: str, urls: list[str]) -> list[str]:
    discovered = []
    seen = set()

    for url in urls:
        if not url.lower().endswith(".js"):
            continue
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code != 200:
                continue
        except Exception:
            continue

        for path in _extract_candidate_api_paths_from_text(resp.text):
            full_url = urljoin(target_url.rstrip("/") + "/", path.lstrip("/"))
            if full_url not in seen:
                seen.add(full_url)
                discovered.append(full_url)

    return discovered


def save_inventory_urls(db, session_id: int, urls: list[str], source_type: str, confidence: float) -> int:
    saved = 0
    existing = {
        (item.path, item.method or "GET")
        for item in db.query(SurfaceInventory).filter(SurfaceInventory.session_id == session_id).all()
    }

    for url in urls:
        key = (url, "GET")
        if key in existing:
            continue

        item = SurfaceInventory(
            session_id=session_id,
            path=url,
            method="GET",
            source_type=source_type,
            asset_type=classify_asset(url),
            confidence=confidence,
            raw_json=url
        )
        db.add(item)
        existing.add(key)
        saved += 1

    return saved


def save_openapi_endpoints(db, session_id: int, endpoints: list[dict], source_type: str = "openapi") -> int:
    saved = 0
    existing = {
        (item.path, (item.method or "GET").upper())
        for item in db.query(SurfaceInventory).filter(SurfaceInventory.session_id == session_id).all()
    }

    for ep in endpoints:
        path = ep.get("path")
        method = (ep.get("method") or "GET").upper()
        key = (path, method)
        if not path or key in existing:
            continue

        item = SurfaceInventory(
            session_id=session_id,
            path=path,
            method=method,
            source_type=source_type,
            asset_type="api",
            confidence=0.95,
            content_type=ep.get("content_type"),
            auth_hint=ep.get("auth_hint"),
            parameters_json=json.dumps(ep.get("parameters", []), ensure_ascii=False),
            raw_json=json.dumps(ep.get("raw", {}), ensure_ascii=False),
        )
        db.add(item)
        existing.add(key)
        saved += 1

    return saved


def persist_discovery_results(db, session_obj, urls: list[str], source_type: str, confidence: float) -> dict:
    seed_urls = build_crapi_seed_urls(session_obj.target_url)
    scoped_urls = filter_urls_in_scope(session_obj.target_url, urls + seed_urls)
    js_discovered = discover_api_paths_from_javascript(session_obj.target_url, scoped_urls)

    saved = save_inventory_urls(db, session_obj.id, scoped_urls, source_type=source_type, confidence=confidence)
    saved += save_inventory_urls(
        db,
        session_obj.id,
        js_discovered,
        source_type=f"{source_type}_js_extract",
        confidence=min(confidence + 0.1, 0.95),
    )

    session_obj.status = "discovered"
    db.commit()

    api_urls = [url for url in scoped_urls + js_discovered if classify_asset(url) == "api"]
    return {
        "saved_urls": saved,
        "scoped_urls": scoped_urls,
        "api_urls": api_urls,
        "js_discovered_urls": js_discovered,
    }
