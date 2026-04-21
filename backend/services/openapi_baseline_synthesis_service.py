from __future__ import annotations

import json
import re
import uuid
from collections.abc import Mapping
from typing import Any

try:
    import yaml
except ModuleNotFoundError:  # pragma: no cover
    yaml = None

try:
    from backend.services.resource_family_inference_service import ResourceFamilyInferenceService
except ModuleNotFoundError:  # pragma: no cover
    from services.resource_family_inference_service import ResourceFamilyInferenceService


class OpenApiBaselineSynthesisService:
    MAX_SCHEMA_DEPTH = 6
    ID_KEYS = (
        "id",
        "uuid",
        "objectId",
        "object_id",
        "vehicleId",
        "vehicle_id",
        "videoId",
        "video_id",
        "postId",
        "post_id",
        "orderId",
        "order_id",
        "reportId",
        "report_id",
        "carId",
        "userId",
        "user_id",
    )

    def __init__(self) -> None:
        self.family_inference = ResourceFamilyInferenceService()
        self._document_cache: dict[str, dict[str, Any]] = {}

    def endpoint_support_summary(self, spec_text: str | None, endpoint_path: str, method: str) -> dict[str, Any]:
        operation = self.find_operation(spec_text, endpoint_path, method)
        family_hint = self.family_inference.infer(path=endpoint_path, method=method)
        if not operation:
            creators, lists = self.find_family_endpoints(spec_text, family=family_hint)
            baseline_valid = bool(creators or lists)
            return {
                "resource_family": family_hint,
                "has_spec_baseline": baseline_valid,
                "baseline_valid": baseline_valid,
                "baseline_source": "family_inference" if baseline_valid else "missing",
                "missing_required_fields": [],
                "spec_confidence": min(0.25 + (0.2 if creators else 0.0) + (0.15 if lists else 0.0), 0.65),
                "success_path_feasibility": min(0.2 + (0.2 if creators else 0.0) + (0.15 if lists else 0.0), 0.7),
                "creator_candidates": creators[:3],
                "list_candidates": lists[:3],
            }

        family = self.family_inference.infer(
            path=endpoint_path,
            method=method,
            tags=operation.get("tags") or [],
            operation_id=str(operation.get("operationId") or ""),
            summary=str(operation.get("summary") or operation.get("description") or ""),
            body_fields=list(self._schema_property_names(self._request_schema(operation, operation["_document"]))),
            query_params=[str(item.get("name") or "") for item in operation.get("_parameters") or [] if str(item.get("in") or "") == "query"],
            response_fields=list(self._response_schema_property_names(operation, operation["_document"])),
        )
        creators, lists = self.find_family_endpoints(spec_text, family=family)
        feasibility = 0.35
        if operation.get("_request_body_supported"):
            feasibility += 0.15
        if operation.get("_parameter_total"):
            feasibility += 0.1
        if self._response_schema_property_names(operation, operation["_document"]):
            feasibility += 0.1
        if creators:
            feasibility += 0.2
        if lists:
            feasibility += 0.15
        if self._path_looks_object_specific(endpoint_path):
            feasibility += 0.05
        if operation.get("summary") or operation.get("operationId"):
            feasibility += 0.05
        spec_confidence = 0.45
        if operation.get("_request_body_supported"):
            spec_confidence += 0.15
        if operation.get("_parameter_total"):
            spec_confidence += 0.1
        if self._response_schema_property_names(operation, operation["_document"]):
            spec_confidence += 0.1
        if creators:
            spec_confidence += 0.1
        if lists:
            spec_confidence += 0.05
        return {
            "resource_family": family,
            "has_spec_baseline": True,
            "baseline_valid": True,
            "baseline_source": "spec_operation",
            "missing_required_fields": [],
            "spec_confidence": min(spec_confidence, 0.98),
            "success_path_feasibility": min(feasibility, 0.98),
            "creator_candidates": creators[:3],
            "list_candidates": lists[:3],
        }

    def synthesize_request(
        self,
        *,
        spec_text: str | None,
        endpoint_path: str,
        method: str,
        known_values: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        operation = self.find_operation(spec_text, endpoint_path, method)
        if not operation:
            return {
                "baseline_body": {},
                "baseline_query": {},
                "baseline_path": {},
                "media_type": None,
                "resource_family": self.family_inference.infer(path=endpoint_path, method=method),
                "synthesis_metadata": {},
                "structured_failure_reason": "baseline_invalid_from_spec",
                "success_path_feasibility": 0.2,
            }

        document = operation["_document"]
        parameters = operation.get("_parameters") or []
        known = dict(known_values or {})
        baseline_path: dict[str, Any] = {}
        baseline_query: dict[str, Any] = {}
        synthesis_metadata: dict[str, str] = {}

        for parameter in parameters:
            if not isinstance(parameter, Mapping):
                continue
            location = str(parameter.get("in") or "").lower()
            name = str(parameter.get("name") or "").strip()
            if not name:
                continue
            schema = self._resolve_schema(parameter.get("schema") or {}, document=document, visited_refs=set(), depth=0)
            value, source = self._synthesize_value(name, schema, known)
            synthesis_metadata[f"{location}:{name}"] = source
            if location == "path":
                baseline_path[name] = value
            elif location == "query":
                baseline_query[name] = value

        media_type = None
        baseline_body: Any = {}
        schema = self._request_schema(operation, document)
        if schema:
            media_type = str(operation.get("_request_media_type") or "application/json")
            baseline_body = self._synthesize_from_schema(schema, document=document, known=known, metadata=synthesis_metadata, prefix="body")
            if baseline_body in (None, ""):
                baseline_body = {}

        family = self.family_inference.infer(
            path=endpoint_path,
            method=method,
            tags=operation.get("tags") or [],
            operation_id=str(operation.get("operationId") or ""),
            summary=str(operation.get("summary") or operation.get("description") or ""),
            body_fields=list((baseline_body or {}).keys()) if isinstance(baseline_body, dict) else [],
            query_params=list(baseline_query.keys()),
            response_fields=list(self._response_schema_property_names(operation, document)),
        )
        support = self.endpoint_support_summary(spec_text, endpoint_path, method)
        missing_required_fields = self._missing_required_fields(operation, document, baseline_body, baseline_query, baseline_path)
        synthesis_sources = list(synthesis_metadata.values())
        baseline_source = "heuristic"
        if any(source == "harvested" for source in synthesis_sources):
            baseline_source = "harvested"
        elif any(source == "example" for source in synthesis_sources):
            baseline_source = "example"
        elif any(source == "default" for source in synthesis_sources):
            baseline_source = "default"
        elif any(source == "enum" for source in synthesis_sources):
            baseline_source = "enum"
        baseline_valid = len(missing_required_fields) == 0
        return {
            "baseline_body": baseline_body if isinstance(baseline_body, dict) else {},
            "baseline_query": baseline_query,
            "baseline_path": baseline_path,
            "media_type": media_type,
            "resource_family": family,
            "synthesis_metadata": synthesis_metadata,
            "baseline_valid": baseline_valid,
            "baseline_source": baseline_source,
            "missing_required_fields": missing_required_fields,
            "spec_confidence": float(support.get("spec_confidence") or (0.8 if baseline_valid else 0.3)),
            "success_path_feasibility": support.get("success_path_feasibility", 0.2),
            "creator_candidates": support.get("creator_candidates", []),
            "list_candidates": support.get("list_candidates", []),
            "structured_failure_reason": None if baseline_valid else "baseline_invalid_from_spec",
        }

    def find_operation(self, spec_text: str | None, endpoint_path: str, method: str) -> dict[str, Any] | None:
        document = self._parse_spec_text(spec_text)
        paths = document.get("paths") or {}
        if not isinstance(paths, Mapping):
            return None
        normalized_target = self._normalize_path_template(endpoint_path)
        for path, path_item in paths.items():
            if not isinstance(path_item, Mapping):
                continue
            if self._normalize_path_template(str(path)) != normalized_target:
                continue
            operation = path_item.get(str(method or "").lower())
            if not isinstance(operation, Mapping):
                continue
            merged = dict(operation)
            parameters = []
            for item in [*(path_item.get("parameters") or []), *(operation.get("parameters") or [])]:
                if isinstance(item, Mapping):
                    parameters.append(item)
            merged["_parameters"] = parameters
            merged["_document"] = document
            merged["_path"] = str(path)
            schema, media_type = self._request_schema(operation, document, include_media=True)
            merged["_request_media_type"] = media_type
            merged["_request_body_supported"] = bool(schema)
            merged["_parameter_total"] = len(parameters)
            return merged
        return None

    def find_family_endpoints(self, spec_text: str | None, *, family: str) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
        document = self._parse_spec_text(spec_text)
        paths = document.get("paths") or {}
        creators: list[dict[str, str]] = []
        lists: list[dict[str, str]] = []
        if not isinstance(paths, Mapping):
            return creators, lists
        for path, path_item in paths.items():
            if not isinstance(path_item, Mapping):
                continue
            for method, operation in path_item.items():
                method_upper = str(method or "").upper()
                if method_upper not in {"GET", "POST", "PUT", "PATCH"}:
                    continue
                if not isinstance(operation, Mapping):
                    continue
                inferred = self.family_inference.infer(
                    path=str(path),
                    method=method_upper,
                    tags=operation.get("tags") or [],
                    operation_id=str(operation.get("operationId") or ""),
                    summary=str(operation.get("summary") or operation.get("description") or ""),
                    body_fields=list(self._schema_property_names(self._request_schema(operation, document))),
                    response_fields=list(self._response_schema_property_names(operation, document)),
                )
                family_score = self._family_similarity_score(family, inferred, str(path))
                if family_score <= 0:
                    continue
                lowered_path = str(path).lower()
                op_id = str(operation.get("operationId") or "").lower()
                summary = str(operation.get("summary") or operation.get("description") or "").lower()
                item = {"path": str(path), "method": method_upper}
                response_fields = self._response_schema_property_names(operation, document)
                if self._is_creator_candidate(
                    method_upper=method_upper,
                    lowered_path=lowered_path,
                    op_id=op_id,
                    summary=summary,
                    response_fields=response_fields,
                ):
                    creators.append(item)
                if self._is_list_candidate(
                    method_upper=method_upper,
                    lowered_path=lowered_path,
                    family=family,
                    response_fields=response_fields,
                ):
                    lists.append(item)
        return creators[:5], lists[:5]

    def harvest_response(self, response_json: Any, headers: Mapping[str, Any] | None = None) -> dict[str, Any]:
        ids = self._collect_ids(response_json)
        links = self._collect_links(response_json)
        location = str((headers or {}).get("location") or "").strip()
        if location:
            links.insert(0, location)
            location_tail = location.rstrip("/").split("/")[-1]
            if location_tail and location_tail not in ids:
                ids.insert(0, location_tail)
        return {
            "harvested_object_ids": ids[:10],
            "harvested_links": links[:10],
        }

    def _parse_spec_text(self, spec_text: str | None) -> dict[str, Any]:
        raw = str(spec_text or "")
        if not raw.strip():
            return {}
        cached = self._document_cache.get(raw)
        if cached is not None:
            return cached
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = yaml.safe_load(raw) if yaml is not None else {}
        if not isinstance(payload, Mapping):
            payload = {}
        document = dict(payload)
        self._document_cache[raw] = document
        return document

    def _normalize_path_template(self, path: str) -> str:
        value = str(path or "").strip()
        value = re.sub(r"/[^/]+(?=/|$)", lambda m: "/{id}" if self._looks_dynamic_segment(m.group(0).lstrip("/")) else m.group(0), value)
        return re.sub(r"\{[^}]+\}", "{id}", value)

    def _path_looks_object_specific(self, path: str) -> bool:
        value = str(path or "").strip().lower()
        return bool(re.search(r"\{[^}]+id[^}]*\}", value)) or value.endswith("/{id}")

    def _family_similarity_score(self, family: str, inferred: str, path: str) -> int:
        if inferred == family:
            return 2
        normalized_family = str(family or "").lower()
        lowered_path = str(path or "").lower()
        stem = normalized_family.split("_")[0]
        if stem and stem in lowered_path:
            return 1
        return 0

    def _is_creator_candidate(
        self,
        *,
        method_upper: str,
        lowered_path: str,
        op_id: str,
        summary: str,
        response_fields: list[str],
    ) -> bool:
        if method_upper != "POST" or "{" in lowered_path:
            return False
        text = f"{lowered_path} {op_id} {summary}"
        if any(token in text for token in ("create", "add", "new", "upload", "receive", "contact", "order")):
            return True
        return any(field.lower() in {item.lower() for item in self.ID_KEYS} for field in response_fields)

    def _is_list_candidate(
        self,
        *,
        method_upper: str,
        lowered_path: str,
        family: str,
        response_fields: list[str],
    ) -> bool:
        if method_upper != "GET" or "{" in lowered_path:
            return False
        family_stem = str(family or "").split("_")[0]
        if any(token in lowered_path for token in ("all", "list", "recent", "vehicles", "orders", "posts", "videos", "reports", "users")):
            return True
        if family_stem and family_stem in lowered_path:
            return True
        return any(field.lower() in {item.lower() for item in self.ID_KEYS} for field in response_fields)

    def _looks_dynamic_segment(self, segment: str) -> bool:
        value = str(segment or "").strip().lower()
        if not value:
            return False
        if re.fullmatch(r"[0-9]+", value):
            return True
        if re.fullmatch(r"[0-9a-f-]{8,}", value):
            return True
        return False

    def _request_schema(self, operation: Mapping[str, Any], document: Mapping[str, Any], include_media: bool = False):
        request_body = operation.get("requestBody") or {}
        if not isinstance(request_body, Mapping):
            return ({}, None) if include_media else {}
        content = request_body.get("content") or {}
        if not isinstance(content, Mapping):
            return ({}, None) if include_media else {}
        for media_type in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
            media = content.get(media_type) or {}
            if not isinstance(media, Mapping):
                continue
            schema = self._resolve_schema(media.get("schema") or {}, document=document, visited_refs=set(), depth=0)
            if include_media:
                return schema, media_type
            return schema
        return ({}, None) if include_media else {}

    def _response_schema_property_names(self, operation: Mapping[str, Any], document: Mapping[str, Any]) -> list[str]:
        responses = operation.get("responses") or {}
        if not isinstance(responses, Mapping):
            return []
        for status_code in ("200", "201", "202", "204", "default"):
            response = responses.get(status_code) or {}
            if not isinstance(response, Mapping):
                continue
            content = response.get("content") or {}
            if not isinstance(content, Mapping):
                continue
            for media in content.values():
                if not isinstance(media, Mapping):
                    continue
                schema = self._resolve_schema(media.get("schema") or {}, document=document, visited_refs=set(), depth=0)
                names = self._schema_property_names(schema)
                if names:
                    return names
        return []

    def _schema_property_names(self, schema: Mapping[str, Any] | None) -> list[str]:
        if not isinstance(schema, Mapping):
            return []
        properties = schema.get("properties") or {}
        if not isinstance(properties, Mapping):
            return []
        return [str(key) for key in properties.keys() if str(key).strip()]

    def _missing_required_fields(
        self,
        operation: Mapping[str, Any],
        document: Mapping[str, Any],
        baseline_body: Any,
        baseline_query: Mapping[str, Any],
        baseline_path: Mapping[str, Any],
    ) -> list[str]:
        missing: list[str] = []
        for parameter in operation.get("_parameters") or []:
            if not isinstance(parameter, Mapping) or not bool(parameter.get("required")):
                continue
            name = str(parameter.get("name") or "").strip()
            location = str(parameter.get("in") or "").lower()
            if not name:
                continue
            container = baseline_query if location == "query" else baseline_path if location == "path" else {}
            if name not in container or container.get(name) in (None, ""):
                missing.append(f"{location}:{name}")
        schema = self._request_schema(operation, document)
        required = schema.get("required") or [] if isinstance(schema, Mapping) else []
        body = baseline_body if isinstance(baseline_body, Mapping) else {}
        for item in required:
            name = str(item or "").strip()
            if name and body.get(name) in (None, ""):
                missing.append(f"body:{name}")
        return missing[:12]

    def _resolve_schema(
        self,
        schema: Mapping[str, Any],
        *,
        document: Mapping[str, Any],
        visited_refs: set[str],
        depth: int,
    ) -> dict[str, Any]:
        if not isinstance(schema, Mapping):
            return {}
        if depth >= self.MAX_SCHEMA_DEPTH:
            return dict(schema)
        ref = schema.get("$ref")
        if ref:
            ref_value = str(ref).strip()
            if ref_value in visited_refs:
                return {}
            target = self._resolve_local_ref(ref_value, document=document)
            if not isinstance(target, Mapping):
                return {}
            merged = dict(target)
            merged.update({key: value for key, value in schema.items() if key != "$ref"})
            return self._resolve_schema(merged, document=document, visited_refs={*visited_refs, ref_value}, depth=depth + 1)

        resolved = dict(schema)
        merged_properties: dict[str, Any] = {}
        for key in ("allOf", "oneOf", "anyOf"):
            variants = resolved.get(key)
            if not isinstance(variants, list):
                continue
            for item in variants:
                variant = self._resolve_schema(item if isinstance(item, Mapping) else {}, document=document, visited_refs=set(visited_refs), depth=depth + 1)
                properties = variant.get("properties") or {}
                if isinstance(properties, Mapping):
                    merged_properties.update(properties)
        properties = resolved.get("properties") or {}
        if isinstance(properties, Mapping):
            merged_properties.update(properties)
        if merged_properties:
            resolved["properties"] = merged_properties
        return resolved

    def _resolve_local_ref(self, ref: str, *, document: Mapping[str, Any]) -> Mapping[str, Any] | None:
        value = str(ref or "").strip()
        if not value.startswith("#/"):
            return None
        current: Any = document
        for segment in value[2:].split("/"):
            if not isinstance(current, Mapping):
                return None
            current = current.get(segment)
        return current if isinstance(current, Mapping) else None

    def _synthesize_from_schema(
        self,
        schema: Mapping[str, Any],
        *,
        document: Mapping[str, Any],
        known: Mapping[str, Any],
        metadata: dict[str, str],
        prefix: str,
        depth: int = 0,
    ) -> Any:
        if depth >= 3:
            return None
        resolved = self._resolve_schema(schema, document=document, visited_refs=set(), depth=0)
        schema_type = str(resolved.get("type") or "").lower()
        if schema_type == "array":
            item_schema = resolved.get("items") or {}
            item = self._synthesize_from_schema(item_schema if isinstance(item_schema, Mapping) else {}, document=document, known=known, metadata=metadata, prefix=f"{prefix}[]", depth=depth + 1)
            return [] if item in (None, "", {}) else [item]
        if schema_type == "object" or resolved.get("properties"):
            payload: dict[str, Any] = {}
            properties = resolved.get("properties") or {}
            required = resolved.get("required") or []
            if not isinstance(properties, Mapping):
                return payload
            ordered_names = [str(item) for item in required if str(item) in properties] + [str(name) for name in properties.keys() if str(name) not in required]
            for name in ordered_names[:12]:
                property_schema = properties.get(name) or {}
                if not isinstance(property_schema, Mapping):
                    continue
                value = self._synthesize_from_schema(property_schema, document=document, known=known, metadata=metadata, prefix=f"{prefix}.{name}", depth=depth + 1)
                if value in (None, "") and name not in required:
                    continue
                payload[name] = value if value not in (None, "") else self._fallback_for_field(name)
                if f"{prefix}.{name}" not in metadata:
                    _, source = self._synthesize_value(name, property_schema, known)
                    metadata[f"{prefix}.{name}"] = source
            return payload
        field_name = prefix.split(".")[-1]
        value, source = self._synthesize_value(field_name, resolved, known)
        metadata[prefix] = source
        return value

    def _synthesize_value(self, field_name: str, schema: Mapping[str, Any], known: Mapping[str, Any]) -> tuple[Any, str]:
        normalized_name = str(field_name or "").strip()
        lowered = normalized_name.lower()
        for key in (normalized_name, lowered, lowered.replace("-", "_")):
            if key in known and known[key] not in (None, ""):
                return known[key], "harvested"
        for key in ("example", "default"):
            value = schema.get(key)
            if value not in (None, ""):
                return value, key
        examples = schema.get("examples")
        if isinstance(examples, list):
            for item in examples:
                if item not in (None, ""):
                    return item, "examples"
        if isinstance(examples, Mapping):
            for item in examples.values():
                if isinstance(item, Mapping) and item.get("value") not in (None, ""):
                    return item.get("value"), "examples"
        enum_values = schema.get("enum")
        if isinstance(enum_values, list) and enum_values:
            return enum_values[0], "enum"
        schema_type = str(schema.get("type") or "").lower()
        schema_format = str(schema.get("format") or "").lower()
        pattern = str(schema.get("pattern") or "")
        if schema_format == "uuid" or lowered.endswith("uuid"):
            return str(uuid.UUID("12345678-1234-5678-1234-567812345678")), "heuristic"
        if lowered in {"email", "new_email", "old_email"} or schema_format == "email":
            return "safe_probe_user@example.test", "heuristic"
        if "password" in lowered:
            return "TestPass!123", "heuristic"
        if lowered in {"username", "user_name"}:
            return "safe_probe_user", "heuristic"
        if lowered in {"name", "full_name", "ownername", "owner_name"}:
            return "Safe Probe User", "heuristic"
        if lowered in {"number", "phone", "mobile"} or "phone" in lowered:
            return "5551234567", "heuristic"
        if "vin" in lowered:
            return "1G1OP124017231334", "heuristic"
        if "pincode" in lowered or lowered == "pin":
            if "{6}" in pattern or "6" in pattern:
                return "123456", "heuristic"
            return "1234", "heuristic"
        if lowered in {"limit"}:
            return 10, "heuristic"
        if lowered in {"offset", "page"}:
            return 0, "heuristic"
        if lowered in {"quantity", "amount"}:
            return 1, "heuristic"
        if lowered in {"status"}:
            return "pending", "heuristic"
        if lowered in {"role"}:
            return "ROLE_USER", "heuristic"
        if lowered.endswith("_url") or lowered == "url" or schema_format in {"uri", "url"}:
            return "http://example.test/resource", "heuristic"
        if lowered.endswith("_id") or lowered in {"id", "user_id", "owner_id", "account_id", "product_id", "order_id", "postid", "post_id", "video_id", "vehicle_id", "report_id"}:
            return 1 if schema_type in {"integer", "number"} else "obj-001", "heuristic"
        if schema_type == "boolean":
            return False, "heuristic"
        if schema_type in {"integer", "number"}:
            return 1, "heuristic"
        return self._fallback_for_field(normalized_name), "heuristic"

    def _fallback_for_field(self, field_name: str) -> str:
        lowered = str(field_name or "").strip().lower()
        if lowered in {"title", "name"}:
            return "safe title"
        if lowered in {"content", "description", "problem_details"}:
            return "safe probe content"
        return "safe"

    def _collect_ids(self, value: Any) -> list[str]:
        found: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                if str(key) in self.ID_KEYS and item not in (None, ""):
                    found.append(str(item))
                found.extend(self._collect_ids(item))
        elif isinstance(value, list):
            for item in value[:10]:
                found.extend(self._collect_ids(item))
        unique: list[str] = []
        seen: set[str] = set()
        for item in found:
            if item and item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def _collect_links(self, value: Any) -> list[str]:
        found: list[str] = []
        if isinstance(value, dict):
            for key, item in value.items():
                lowered = str(key).lower()
                if lowered.endswith("link") or lowered.endswith("url"):
                    if item not in (None, ""):
                        found.append(str(item))
                found.extend(self._collect_links(item))
        elif isinstance(value, list):
            for item in value[:10]:
                found.extend(self._collect_links(item))
        unique: list[str] = []
        seen: set[str] = set()
        for item in found:
            if item and item not in seen:
                seen.add(item)
                unique.append(item)
        return unique
