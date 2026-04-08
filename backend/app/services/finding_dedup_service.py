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


def _load_evidence_json(finding) -> dict:
    raw_evidence = getattr(finding, "evidence_json", None)
    if not raw_evidence:
        return {}
    try:
        parsed = json.loads(raw_evidence)
    except Exception:
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _normalize_role_pair(owner_role, other_role) -> tuple[str, str]:
    return (
        str(owner_role or "").strip(),
        str(other_role or "").strip(),
    )


def matching_bopla_finding(existing_findings, endpoint: str, analysis: dict):
    target_fields = normalize_field_list(analysis.get("exposed_fields"))
    for finding in existing_findings:
        if getattr(finding, "finding_type", None) != "possible_bopla":
            continue
        if getattr(finding, "endpoint", None) != endpoint:
            continue
        if getattr(finding, "verification_status", "candidate") not in {"candidate", "confirmed"}:
            continue

        evidence = _load_evidence_json(finding)
        existing_fields = normalize_field_list(evidence.get("exposed_fields"))
        if existing_fields == target_fields:
            return finding
    return None


def matching_bola_finding(existing_findings, endpoint: str, analysis: dict):
    target_owner_role, target_other_role = _normalize_role_pair(
        analysis.get("owner_role"),
        analysis.get("other_role"),
    )
    target_object_id = str(
        analysis.get("owner_object_id")
        or analysis.get("other_object_id")
        or ""
    ).strip()

    for finding in existing_findings:
        if getattr(finding, "finding_type", None) != "possible_bola":
            continue
        if getattr(finding, "endpoint", None) != endpoint:
            continue
        if getattr(finding, "verification_status", "candidate") not in {"candidate", "confirmed"}:
            continue

        evidence = _load_evidence_json(finding)
        existing_owner_role, existing_other_role = _normalize_role_pair(
            evidence.get("owner_role"),
            evidence.get("other_role"),
        )
        existing_object_id = str(
            evidence.get("owner_object_id")
            or evidence.get("other_object_id")
            or ""
        ).strip()

        if (existing_owner_role, existing_other_role) != (target_owner_role, target_other_role):
            continue

        if target_object_id and existing_object_id and target_object_id != existing_object_id:
            continue

        return finding
    return None
