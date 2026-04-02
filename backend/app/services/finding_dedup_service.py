import json


def normalize_field_list(values) -> list[str]:
    if not isinstance(values, list):
        return []
    normalized = []
    for value in values:
        item = str(value or "").strip()
        if item and item not in normalized:
            normalized.append(item)
    return sorted(normalized)


def load_related_observation_ids(value) -> list[int]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except Exception:
        return []
    if not isinstance(parsed, list):
        return []

    result = []
    for item in parsed:
        try:
            normalized = int(item)
        except (TypeError, ValueError):
            continue
        if normalized not in result:
            result.append(normalized)
    return result


def merge_related_observation_ids(existing_value, new_ids: list[int]) -> str:
    merged = load_related_observation_ids(existing_value)
    for item in new_ids:
        try:
            normalized = int(item)
        except (TypeError, ValueError):
            continue
        if normalized not in merged:
            merged.append(normalized)
    return json.dumps(merged, ensure_ascii=False)


def matching_bopla_finding(existing_findings, endpoint: str, analysis: dict):
    target_fields = normalize_field_list(analysis.get("exposed_fields"))
    for finding in existing_findings:
        if getattr(finding, "finding_type", None) != "possible_bopla":
            continue
        if getattr(finding, "endpoint", None) != endpoint:
            continue
        if getattr(finding, "verification_status", "candidate") not in {"candidate", "confirmed"}:
            continue

        evidence = {}
        raw_evidence = getattr(finding, "evidence_json", None)
        if raw_evidence:
            try:
                evidence = json.loads(raw_evidence)
            except Exception:
                evidence = {}
        existing_fields = normalize_field_list(evidence.get("exposed_fields"))
        if existing_fields == target_fields:
            return finding
    return None
