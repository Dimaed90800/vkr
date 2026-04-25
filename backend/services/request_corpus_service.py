from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.corpus import (
        RequestCorpusItem,
        ResourceInstance,
        StatusClassification,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.corpus import (
        RequestCorpusItem,
        ResourceInstance,
        StatusClassification,
    )
    from storage.memory_store import memory_store


REDACTED_HEADERS: set[str] = {
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
}

REDACTED_BODY_KEYS: set[str] = {
    "api_key",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "client_secret",
    "token",
}

_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")
_PATH_SEGMENT_RE = re.compile(
    r"/(?:api/)?(?:v\d+/)?(\w+?)s?/(\d+|[0-9a-f\-]{8,})"
    r"(?:/|$)",
    re.IGNORECASE,
)


def classify_status(status_code: int) -> StatusClassification:
    if 200 <= status_code <= 399:
        return StatusClassification.successful_seed
    if status_code in (401, 403):
        return StatusClassification.auth_baseline
    if status_code == 404:
        return StatusClassification.negative_object
    if status_code in (409, 422):
        return StatusClassification.validation_signal
    if status_code == 429:
        return StatusClassification.rate_limit_signal
    if 500 <= status_code <= 599:
        return StatusClassification.server_error_candidate
    return StatusClassification.successful_seed


def redact_sensitive_data(
    headers: dict[str, Any] | None,
    body: Any,
) -> tuple[dict[str, Any], Any]:
    redacted_h: dict[str, Any] = {}
    for key, value in (headers or {}).items():
        if key.lower() in REDACTED_HEADERS:
            redacted_h[key] = "<redacted>"
        else:
            redacted_h[key] = value

    redacted_b = _redact_body(body)
    return redacted_h, redacted_b


def _redact_body(body: Any) -> Any:
    if isinstance(body, dict):
        return {
            k: "<redacted>" if k.lower() in REDACTED_BODY_KEYS else _redact_body(v)
            for k, v in body.items()
        }
    if isinstance(body, list):
        return [_redact_body(item) for item in body]
    return body


def extract_ids(
    url: str,
    path_template: str,
    response_body: Any,
) -> dict[str, list[str]]:
    ids: dict[str, list[str]] = {}

    if path_template:
        param_names = _PATH_PARAM_RE.findall(path_template)
        if param_names and url:
            tpl_parts = path_template.rstrip("/").split("/")
            url_parts = url.split("?")[0].rstrip("/").split("/")
            if len(url_parts) >= len(tpl_parts):
                offset = len(url_parts) - len(tpl_parts)
                for i, tpl_seg in enumerate(tpl_parts):
                    m = _PATH_PARAM_RE.fullmatch(tpl_seg)
                    if m:
                        param_name = m.group(1)
                        idx = offset + i
                        if idx < len(url_parts):
                            val = url_parts[idx]
                            if val and val != tpl_seg:
                                ids.setdefault(param_name, [])
                                if val not in ids[param_name]:
                                    ids[param_name].append(val)

    if not ids and url:
        for seg_match in _PATH_SEGMENT_RE.finditer(url.split("?")[0]):
            resource_hint = seg_match.group(1)
            obj_val = seg_match.group(2)
            param_name = f"{resource_hint}Id"
            ids.setdefault(param_name, [])
            if obj_val not in ids[param_name]:
                ids[param_name].append(obj_val)

    if isinstance(response_body, dict):
        for key in ("id", "Id", "ID"):
            val = response_body.get(key)
            if val is not None:
                str_val = str(val)
                ids.setdefault("responseId", [])
                if str_val not in ids["responseId"]:
                    ids["responseId"].append(str_val)

    return ids


class RequestCorpusService:
    def add_exchange(
        self,
        *,
        campaign_id: str,
        method: str,
        url: str,
        headers: dict[str, Any] | None = None,
        body: Any = None,
        status_code: int = 0,
        response_body: Any = None,
        response_content_type: str = "",
        auth_profile: str = "",
        source: str = "manual",
        source_tool_run_id: str = "",
        operation_id: str = "",
        path_template: str = "",
    ) -> RequestCorpusItem:
        request_id = f"req_{uuid4().hex[:16]}"
        now = datetime.now(timezone.utc).isoformat()

        headers_redacted, body_redacted = redact_sensitive_data(headers, body)
        _, response_body_redacted = redact_sensitive_data(None, response_body)

        classification = classify_status(status_code)
        extracted = extract_ids(url, path_template, response_body)

        sensitive_fields: list[str] = []
        for key in (headers or {}):
            if key.lower() in REDACTED_HEADERS:
                sensitive_fields.append(key)
        if isinstance(body, dict):
            for key in body:
                if key.lower() in REDACTED_BODY_KEYS:
                    sensitive_fields.append(key)

        item = RequestCorpusItem(
            request_id=request_id,
            campaign_id=campaign_id,
            operation_id=operation_id,
            source=source,
            source_tool_run_id=source_tool_run_id,
            method=method.upper(),
            url=url,
            path_template=path_template,
            auth_profile=auth_profile,
            headers_redacted=headers_redacted,
            body_redacted=body_redacted,
            status_code=status_code,
            response_body_redacted=response_body_redacted,
            response_content_type=response_content_type,
            classification=classification,
            extracted_ids=extracted,
            sensitive_fields=sensitive_fields,
            created_at=now,
        )

        memory_store.store_corpus_item(
            request_id, campaign_id, item.model_dump(mode="json")
        )

        self._maybe_create_resource_instances(item)

        return item

    add_from_manual_request = add_exchange

    def add_from_tool_result(
        self,
        campaign_id: str,
        tool_result: Any,
        role: str = "",
    ) -> list[RequestCorpusItem]:
        repro = getattr(tool_result, "reproduction", None)
        if repro is None:
            return []

        method = getattr(repro, "method", "GET") or "GET"
        url = getattr(repro, "url", "") or ""
        headers = getattr(repro, "headers", None)
        req_body = getattr(repro, "body", None)
        tool_name = getattr(tool_result, "tool_name", "")
        raw_status = (
            getattr(repro, "status_code", None)
            or getattr(tool_result, "status_code", None)
            or getattr(tool_result, "response_status_code", None)
        )
        try:
            status_code = int(raw_status)
        except (TypeError, ValueError):
            status_code = 0

        # Phase 2: do not pollute seeds with statusless tool reproductions.
        if status_code <= 0:
            return []

        item = self.add_exchange(
            campaign_id=campaign_id,
            method=method,
            url=url,
            headers=dict(headers) if headers else None,
            body=req_body,
            status_code=status_code,
            auth_profile=role or getattr(tool_result, "auth_context_name", "") or "",
            source=f"tool_wrapper:{tool_name}" if tool_name else "tool_wrapper",
            source_tool_run_id=getattr(tool_result, "tool_run_id", "") or "",
        )
        return [item]

    def get_request(self, request_id: str) -> RequestCorpusItem | None:
        data = memory_store.get_corpus_item(request_id)
        if data is None:
            return None
        return RequestCorpusItem.model_validate(data)

    def list_by_campaign(self, campaign_id: str) -> list[RequestCorpusItem]:
        return [
            RequestCorpusItem.model_validate(d)
            for d in memory_store.list_corpus_by_campaign(campaign_id)
        ]

    def find_successful_by_operation(
        self, campaign_id: str, operation_id: str
    ) -> list[RequestCorpusItem]:
        return [
            item
            for item in self.list_by_campaign(campaign_id)
            if item.operation_id == operation_id
            and item.classification == StatusClassification.successful_seed
        ]

    def find_replay_seed(
        self,
        campaign_id: str,
        method: str,
        path_template: str,
        auth_profile: str = "",
    ) -> RequestCorpusItem | None:
        best: RequestCorpusItem | None = None
        for item in self.list_by_campaign(campaign_id):
            if item.classification != StatusClassification.successful_seed:
                continue
            if item.method.upper() != method.upper():
                continue
            if item.path_template and item.path_template == path_template:
                if auth_profile and item.auth_profile == auth_profile:
                    return item
                best = item
            elif not item.path_template and path_template in item.url:
                if best is None:
                    best = item
        return best

    def find_cross_role_candidates(
        self, campaign_id: str
    ) -> list[dict[str, Any]]:
        items = self.list_by_campaign(campaign_id)
        seeds = [
            i for i in items
            if i.classification == StatusClassification.successful_seed
        ]

        groups: dict[str, list[RequestCorpusItem]] = {}
        for item in seeds:
            if item.operation_id:
                key = item.operation_id
            elif item.method and item.path_template:
                key = f"{item.method.upper()}:{item.path_template}"
            else:
                continue
            groups.setdefault(key, []).append(item)

        candidates: list[dict[str, Any]] = []
        for key, group in groups.items():
            roles: dict[str, list[RequestCorpusItem]] = {}
            for item in group:
                if not item.auth_profile:
                    continue
                roles.setdefault(item.auth_profile, []).append(item)

            role_names = list(roles.keys())
            if len(role_names) < 2:
                continue

            for i in range(len(role_names)):
                for j in range(i + 1, len(role_names)):
                    role_a, role_b = role_names[i], role_names[j]
                    items_a, items_b = roles[role_a], roles[role_b]

                    ids_a = self._all_object_ids(items_a)
                    ids_b = self._all_object_ids(items_b)
                    overlap = ids_a & ids_b

                    # Phase 2: require overlapping object IDs to reduce noise.
                    if not ids_a or not ids_b:
                        continue
                    if not overlap:
                        continue

                    candidates.append({
                        "operation_key": key,
                        "role_a": role_a,
                        "role_b": role_b,
                        "overlapping_ids": sorted(overlap),
                        "confidence": 0.9,
                        "sample_request_a": items_a[0].request_id,
                        "sample_request_b": items_b[0].request_id,
                    })

        return candidates

    def find_ids_by_resource_type(
        self, campaign_id: str, resource_type: str
    ) -> list[ResourceInstance]:
        return [
            ResourceInstance.model_validate(d)
            for d in memory_store.list_resources_by_campaign(campaign_id)
            if d.get("resource_type", "").lower() == resource_type.lower()
        ]

    def _maybe_create_resource_instances(self, item: RequestCorpusItem) -> None:
        for param_name, values in item.extracted_ids.items():
            for val in values:
                resource_type = param_name.replace("Id", "").replace("_id", "")
                res_id = f"res_{item.campaign_id}_{resource_type}_{val}"
                existing = memory_store.resource_instances.get(res_id)
                if existing:
                    roles = existing.get("observed_by_roles", [])
                    if item.auth_profile and item.auth_profile not in roles:
                        roles.append(item.auth_profile)
                    continue

                instance = ResourceInstance(
                    resource_instance_id=res_id,
                    campaign_id=item.campaign_id,
                    resource_type=resource_type,
                    object_id=val,
                    owner_role=item.auth_profile if item.auth_profile else "",
                    owner_confidence=0.5 if item.auth_profile else 0.0,
                    source_request_id=item.request_id,
                    source_operation_id=item.operation_id,
                    observed_by_roles=[item.auth_profile] if item.auth_profile else [],
                )
                memory_store.store_resource_instance(
                    res_id, item.campaign_id, instance.model_dump(mode="json")
                )

    @staticmethod
    def _all_object_ids(items: list[RequestCorpusItem]) -> set[str]:
        result: set[str] = set()
        for item in items:
            for vals in item.extracted_ids.values():
                result.update(vals)
        return result
