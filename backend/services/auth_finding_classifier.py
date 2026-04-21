from __future__ import annotations

from collections.abc import Mapping
from typing import Any


OBJECT_ID_QUERY_KEYS = {
    "id",
    "user_id",
    "order_id",
    "vehicle_id",
    "account_id",
    "post_id",
    "report_id",
}

COLLECTION_KEYWORDS = (
    "all",
    "list",
    "vehicles",
    "users",
    "orders",
    "products",
)

PRIVILEGED_KEYWORDS = (
    "admin",
    "management",
    "internal",
    "moderation",
    "staff",
)

LOW_PRIVILEGE_ROLE_MARKERS = (
    "user",
    "guest",
    "customer",
    "viewer",
    "member",
    "anonymous",
)

HIGH_PRIVILEGE_ROLE_MARKERS = (
    "admin",
    "staff",
    "moderator",
    "manager",
    "support",
    "operator",
    "mechanic",
)


def classify_auth_finding(task: Any, evidence: Mapping[str, Any] | None) -> str:
    endpoint = _task_value(task, "endpoint")
    path_params = _task_params_list(task, "path_params")
    query_params = _task_params_list(task, "query_params")
    owner_role = _task_auth_value(task, "owner_role")
    other_role = _task_auth_value(task, "other_role")
    subtype = _task_value(task, "subtype").strip().lower()

    response_summary = dict((evidence or {}).get("response_summary") or {})
    similarity = _float_value(response_summary.get("similarity"))
    similarity_high = similarity > 0.8
    owner_summary = dict(response_summary.get("owner") or {})
    other_summary = dict(response_summary.get("other") or {})
    collection_analysis = dict(response_summary.get("collection_analysis") or {})
    object_id_present = bool(path_params) or any(_is_object_identity_query_param(item) for item in query_params)
    is_privileged_endpoint = _contains_keyword(endpoint, PRIVILEGED_KEYWORDS)
    is_collection_endpoint = not object_id_present and _contains_keyword(endpoint, COLLECTION_KEYWORDS)
    access_success_for_low_priv_user = _access_success_for_low_priv_user(
        owner_role=owner_role,
        other_role=other_role,
        response_summary=response_summary,
    )
    property_mutation = bool(response_summary.get("mutated_fields")) and bool(response_summary.get("accepted_fields"))
    same_success = _status_success(owner_summary.get("status_code")) and _status_success(other_summary.get("status_code"))
    shared_object_id_count = _int_value(collection_analysis.get("shared_object_id_count"))
    owner_only_object_id_count = _int_value(collection_analysis.get("owner_only_object_id_count"))
    other_only_object_id_count = _int_value(collection_analysis.get("other_only_object_id_count"))
    mismatch_hints = list(collection_analysis.get("tenant_user_mismatch_hints") or [])
    empty_collection = bool(collection_analysis.get("empty_collection"))
    privileged_endpoint_like = bool(collection_analysis.get("privileged_endpoint_like")) or is_privileged_endpoint
    owner_item_count = _int_or_none(collection_analysis.get("owner_item_count"))
    other_item_count = _int_or_none(collection_analysis.get("other_item_count"))
    non_empty_collection = (owner_item_count or 0) > 0 or (other_item_count or 0) > 0

    if property_mutation:
        return "property_level_authorization" if subtype == "property_level_authorization" else "mass_assignment"
    if object_id_present and similarity_high:
        return "bola"
    if subtype == "function_level_authorization" and access_success_for_low_priv_user:
        return "function_level_authorization"
    if empty_collection and same_success and shared_object_id_count == 0 and not mismatch_hints and similarity_high:
        return "weak_empty_collection_case"
    if privileged_endpoint_like and same_success and non_empty_collection and access_success_for_low_priv_user:
        return "vertical_privilege"
    if is_collection_endpoint and same_success and (
        shared_object_id_count > 0
        or owner_only_object_id_count > 0
        or other_only_object_id_count > 0
        or bool(mismatch_hints)
    ):
        return "collection_access_control"
    if is_collection_endpoint and similarity_high:
        return "generic_access_control"
    if similarity_high:
        return "horizontal_privilege"
    return "generic_access_control"


def finding_type_label(classification: str) -> str:
    normalized = str(classification or "").strip().lower()
    labels = {
        "bola": "BOLA",
        "horizontal_privilege": "HORIZONTAL_PRIVILEGE_ESCALATION",
        "vertical_privilege": "VERTICAL_PRIVILEGE_ESCALATION",
        "collection_access_control": "COLLECTION_ACCESS_CONTROL",
        "generic_access_control": "GENERIC_ACCESS_CONTROL",
        "weak_empty_collection_case": "WEAK_EMPTY_COLLECTION_CASE",
        "property_level_authorization": "PROPERTY_LEVEL_AUTHORIZATION",
        "mass_assignment": "MASS_ASSIGNMENT",
        "function_level_authorization": "FUNCTION_LEVEL_AUTHORIZATION",
    }
    return labels.get(normalized, "AUTHORIZATION")


def finding_title_label(classification: str) -> str:
    normalized = str(classification or "").strip().lower()
    titles = {
        "bola": "Broken Object Level Authorization",
        "horizontal_privilege": "Horizontal Privilege Escalation",
        "vertical_privilege": "Vertical Privilege Escalation",
        "collection_access_control": "Collection Access Control Weakness",
        "generic_access_control": "Generic Access Control Weakness",
        "weak_empty_collection_case": "Weak Empty Collection Case",
        "property_level_authorization": "Broken Object Property Level Authorization",
        "mass_assignment": "Mass Assignment",
        "function_level_authorization": "Broken Function Level Authorization",
    }
    return titles.get(normalized, "Authorization Weakness")


def _task_value(task: Any, name: str) -> str:
    if isinstance(task, Mapping):
        return str(task.get(name) or "")
    return str(getattr(task, name, "") or "")


def _task_params_list(task: Any, name: str) -> list[str]:
    params = {}
    if isinstance(task, Mapping):
        params = dict(task.get("params") or {})
    else:
        params = getattr(task, "params", None)
    if isinstance(params, Mapping):
        values = params.get(name) or []
    else:
        values = getattr(params, name, []) if params is not None else []
    return [str(item or "") for item in values if str(item or "").strip()]


def _task_auth_value(task: Any, name: str) -> str:
    auth_context = {}
    if isinstance(task, Mapping):
        auth_context = dict(task.get("auth_context") or {})
    else:
        auth_context = getattr(task, "auth_context", None)
    if isinstance(auth_context, Mapping):
        return str(auth_context.get(name) or "")
    return str(getattr(auth_context, name, "") or "") if auth_context is not None else ""


def _contains_keyword(endpoint: str, keywords: tuple[str, ...]) -> bool:
    path = str(endpoint or "").strip().lower()
    return any(keyword in path for keyword in keywords)


def _is_object_identity_query_param(name: str) -> bool:
    normalized = str(name or "").strip().lower()
    return normalized in OBJECT_ID_QUERY_KEYS or normalized.endswith("_id")


def _float_value(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _int_value(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _status_success(status_code: Any) -> bool:
    try:
        status = int(status_code)
    except (TypeError, ValueError):
        return False
    return status in {200, 201, 202, 204}


def _is_low_privilege_role(role_name: str) -> bool:
    normalized = str(role_name or "").strip().lower()
    if not normalized:
        return True
    if any(marker in normalized for marker in HIGH_PRIVILEGE_ROLE_MARKERS):
        return False
    if any(marker in normalized for marker in LOW_PRIVILEGE_ROLE_MARKERS):
        return True
    return True


def _access_success_for_low_priv_user(
    *,
    owner_role: str,
    other_role: str,
    response_summary: Mapping[str, Any],
) -> bool:
    owner = dict(response_summary.get("owner") or {})
    other = dict(response_summary.get("other") or {})
    if _is_low_privilege_role(owner_role) and _status_success(owner.get("status_code")):
        return True
    if _is_low_privilege_role(other_role) and _status_success(other.get("status_code")):
        return True
    return False
