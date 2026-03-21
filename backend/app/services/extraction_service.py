import json
import re


UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}\b"
)


def _try_parse_json(text: str):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def _walk(value, results: list):
    if isinstance(value, dict):
        for key, val in value.items():
            lowered = str(key).lower()
            if lowered in {"vehicleid", "vehicle_id"} and isinstance(val, str):
                results.append(val)
            _walk(val, results)
    elif isinstance(value, list):
        for item in value:
            _walk(item, results)


def extract_vehicle_ids_from_text(body_text: str) -> list[str]:
    found = []

    data = _try_parse_json(body_text)
    if data is not None:
        _walk(data, found)

    # fallback regex по сырому тексту
    regex_hits = UUID_RE.findall(body_text or "")
    for hit in regex_hits:
        if hit not in found:
            found.append(hit)

    # preserve order + unique
    unique = []
    for item in found:
        if item not in unique:
            unique.append(item)
    return unique