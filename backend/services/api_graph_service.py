"""Phase 3 — API Graph / Dependency Graph service.

Builds a persistent, campaign-scoped API graph from OpenAPI and
enriches it from the Phase 2 request corpus. The new graph is
fully separate from the per-execution graph_state_service to
avoid coupling. Phase 3 explicitly does NOT create confirmed
findings, observations, evidence packs, or judge inputs; it
only stores graph nodes/edges and exposes a compact summary.

Single service file by design (Phase 3 keeps the dependency
inference helpers internal to this module). A separate
dependency_graph_service.py can be split out in a later phase
if the file grows.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

try:
    from backend.models.api_graph import (
        ApiGraph,
        AuthProfile,
        GraphEdge,
        GraphSummary,
        Operation,
        Parameter,
        RequestExample,
        ResourceInstanceRef,
        ResourceType,
        ResponseExample,
    )
    from backend.models.corpus import RequestCorpusItem, StatusClassification
    from backend.services.openapi_baseline_synthesis_service import (
        OpenApiBaselineSynthesisService,
    )
    from backend.services.request_corpus_service import RequestCorpusService
    from backend.services.resource_family_inference_service import (
        ResourceFamilyInferenceService,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import (
        ApiGraph,
        AuthProfile,
        GraphEdge,
        GraphSummary,
        Operation,
        Parameter,
        RequestExample,
        ResourceInstanceRef,
        ResourceType,
        ResponseExample,
    )
    from models.corpus import RequestCorpusItem, StatusClassification
    from services.openapi_baseline_synthesis_service import (
        OpenApiBaselineSynthesisService,
    )
    from services.request_corpus_service import RequestCorpusService
    from services.resource_family_inference_service import (
        ResourceFamilyInferenceService,
    )
    from storage.memory_store import memory_store


_HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}

_ID_KEYS = {
    "id",
    "uuid",
    "objectid",
    "object_id",
    "vehicleid",
    "vehicle_id",
    "videoid",
    "video_id",
    "postid",
    "post_id",
    "orderid",
    "order_id",
    "reportid",
    "report_id",
    "carid",
    "userid",
    "user_id",
}

_BOPLA_BODY_HINTS = {
    "role",
    "roles",
    "is_admin",
    "isadmin",
    "permission",
    "permissions",
    "password",
    "email",
    "owner",
    "owner_id",
    "ownerid",
    "scope",
}


class GraphBuildError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _make_operation_id(method: str, path_template: str) -> str:
    return f"op_{method.upper()}_{path_template}"


def _looks_like_object_id(name: str) -> bool:
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    if lowered in _ID_KEYS:
        return True
    return lowered.endswith("id") or lowered.endswith("_id")


def _resource_type_hint(name: str, fallback_type: str) -> str:
    lowered = (name or "").strip().lower()
    if not lowered:
        return ""
    stem = fallback_type.lower()
    if stem and stem in lowered:
        return fallback_type
    if lowered.endswith("id") and not lowered.endswith("_id"):
        return lowered[:-2]
    if lowered.endswith("_id"):
        return lowered[:-3]
    return ""


class ApiGraphService:
    """Public facade for the campaign-scoped API graph.

    Internal responsibilities are split into private helper methods
    (_OpenApiIngester / _CorpusEnricher / _DependencyInferer style)
    but kept inside this single class for Phase 3 simplicity.
    """

    def __init__(self) -> None:
        self._family_inference = ResourceFamilyInferenceService()
        self._baseline_synth = OpenApiBaselineSynthesisService()
        self._corpus = RequestCorpusService()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def build_from_openapi(
        self, campaign_id: str, openapi_spec_text: str
    ) -> ApiGraph:
        if not memory_store.get_campaign(campaign_id):
            raise ValueError(f"campaign_not_found:{campaign_id}")
        if not str(openapi_spec_text or "").strip():
            raise GraphBuildError(
                "invalid_graph_build_request",
                "openapi_spec_text is required and cannot be empty.",
            )
        graph = ApiGraph(campaign_id=campaign_id)
        self._ingest_openapi(graph, openapi_spec_text)
        graph.built_at = datetime.now(timezone.utc).isoformat()
        self._enrich_from_corpus(graph)
        self._persist(graph)
        return graph

    def ingest_corpus(self, campaign_id: str) -> ApiGraph:
        if not memory_store.get_campaign(campaign_id):
            raise ValueError(f"campaign_not_found:{campaign_id}")
        graph = self.get_graph(campaign_id) or ApiGraph(campaign_id=campaign_id)
        self._enrich_from_corpus(graph)
        self._persist(graph)
        return graph

    def get_graph(self, campaign_id: str) -> ApiGraph | None:
        data = memory_store.get_graph_for_campaign(campaign_id)
        if data is None:
            return None
        blob = data.get("graph") if "graph" in data else data
        return ApiGraph.model_validate(blob)

    def list_operations(self, campaign_id: str) -> list[Operation]:
        graph = self.get_graph(campaign_id)
        if graph is None:
            return []
        return list(graph.operations)

    def summary_for_planner(self, campaign_id: str) -> GraphSummary:
        graph = self.get_graph(campaign_id)
        if graph is None:
            return GraphSummary(campaign_id=campaign_id)
        request_role_by_id: dict[str, str] = {}
        operation_id_by_request_id: dict[str, str] = {}
        for rex in graph.request_examples:
            if rex.classification != "successful_seed":
                continue
            if not rex.auth_profile:
                continue
            request_role_by_id[rex.request_id] = rex.auth_profile
            operation_id_by_request_id[rex.request_id] = rex.operation_id
        seeded_by_role: dict[str, list[str]] = {}
        bola: list[str] = []
        bfla: list[str] = []
        bopla: list[str] = []
        cross_role: list[str] = []
        object_id_ops: list[str] = []
        high_risk: list[str] = []
        seeded_total = 0
        auth_required_total = 0
        undocumented = 0
        for op in graph.operations:
            if "API1_BOLA" in op.owasp_candidates:
                bola.append(op.operation_id)
            if "API5_BFLA" in op.owasp_candidates:
                bfla.append(op.operation_id)
            if "API3_BOPLA" in op.owasp_candidates:
                bopla.append(op.operation_id)
            if "cross_role_signal" in op.risk_hints:
                cross_role.append(op.operation_id)
            if "object_id_in_path" in op.risk_hints:
                object_id_ops.append(op.operation_id)
            if op.owasp_candidates:
                high_risk.append(op.operation_id)
            if op.successful_seed_request_ids:
                seeded_total += 1
            if op.auth_required:
                auth_required_total += 1
            if op.sources == ["corpus_only"]:
                undocumented += 1
            for request_id in op.successful_seed_request_ids:
                role = request_role_by_id.get(request_id)
                if not role:
                    continue
                seeded_by_role.setdefault(role, [])
                operation_id = operation_id_by_request_id.get(request_id, op.operation_id)
                if operation_id not in seeded_by_role[role]:
                    seeded_by_role[role].append(operation_id)
        return GraphSummary(
            campaign_id=campaign_id,
            operations_total=len(graph.operations),
            operations_with_seed=seeded_total,
            operations_auth_required=auth_required_total,
            operations_undocumented=undocumented,
            high_risk_operations=high_risk,
            object_id_operations=object_id_ops,
            bola_candidates=bola,
            bfla_candidates=bfla,
            bopla_candidates=bopla,
            cross_role_signal_operations=cross_role,
            resource_types=[r.resource_type for r in graph.resource_types],
            seeded_operations_by_role=seeded_by_role,
        )

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist(self, graph: ApiGraph) -> None:
        memory_store.replace_graph_for_campaign(
            graph.campaign_id,
            {
                "graph": graph.model_dump(mode="json"),
                "operations_count": len(graph.operations),
            },
        )

    # ------------------------------------------------------------------
    # OpenAPI ingestion
    # ------------------------------------------------------------------
    def _ingest_openapi(self, graph: ApiGraph, openapi_spec_text: str) -> None:
        try:
            document = self._baseline_synth._parse_spec_text(openapi_spec_text)
        except Exception as exc:
            raise GraphBuildError(
                "invalid_openapi_spec",
                "openapi_spec_text could not be parsed as valid JSON/YAML OpenAPI.",
            ) from exc
        if not document:
            raise GraphBuildError(
                "invalid_openapi_spec",
                "openapi_spec_text must contain a valid OpenAPI document.",
            )
        document_security = document.get("security") or []
        document_security_names = self._security_scheme_names(document_security)
        paths = document.get("paths") or {}
        if not isinstance(paths, Mapping):
            raise GraphBuildError(
                "invalid_openapi_spec",
                "OpenAPI document must include a valid 'paths' object.",
            )
        for raw_path, path_item in paths.items():
            if not isinstance(path_item, Mapping):
                continue
            shared_parameters = [
                item for item in (path_item.get("parameters") or [])
                if isinstance(item, Mapping)
            ]
            for method_key, raw_op in path_item.items():
                method = str(method_key or "").upper()
                if method not in _HTTP_METHODS:
                    continue
                if not isinstance(raw_op, Mapping):
                    continue
                self._build_operation_from_spec(
                    graph=graph,
                    document=document,
                    path_template=str(raw_path),
                    method=method,
                    operation=raw_op,
                    shared_parameters=shared_parameters,
                    document_security_names=document_security_names,
                )
        self._infer_dependency_edges_from_spec(graph)
        self._add_owasp_edges(graph)

    def _security_scheme_names(self, security: Any) -> list[str]:
        names: list[str] = []
        if not isinstance(security, list):
            return names
        for entry in security:
            if isinstance(entry, Mapping):
                for key in entry.keys():
                    name = str(key or "")
                    if name and name not in names:
                        names.append(name)
        return names

    def _build_operation_from_spec(
        self,
        *,
        graph: ApiGraph,
        document: Mapping[str, Any],
        path_template: str,
        method: str,
        operation: Mapping[str, Any],
        shared_parameters: list[Mapping[str, Any]],
        document_security_names: list[str],
    ) -> None:
        parameters = list(shared_parameters) + [
            item for item in (operation.get("parameters") or [])
            if isinstance(item, Mapping)
        ]
        path_params = [
            str(p.get("name") or "")
            for p in parameters
            if str(p.get("in") or "").lower() == "path" and p.get("name")
        ]
        query_params = [
            str(p.get("name") or "")
            for p in parameters
            if str(p.get("in") or "").lower() == "query" and p.get("name")
        ]
        request_schema = self._baseline_synth._request_schema(operation, document)
        body_fields = list(self._baseline_synth._schema_property_names(request_schema))
        response_fields = list(
            self._baseline_synth._response_schema_property_names(operation, document)
        )
        op_security = operation.get("security")
        op_security_names = self._security_scheme_names(op_security)
        if op_security is None:
            security_names = list(document_security_names)
        else:
            security_names = op_security_names
        auth_required = bool(security_names)
        resource_type = self._family_inference.infer(
            path=path_template,
            method=method,
            tags=operation.get("tags") or [],
            operation_id=str(operation.get("operationId") or ""),
            summary=str(operation.get("summary") or operation.get("description") or ""),
            body_fields=body_fields,
            query_params=query_params,
            response_fields=response_fields,
        )
        operation_id = _make_operation_id(method, path_template)
        risk_hints: list[str] = []
        if any(_looks_like_object_id(name) for name in path_params):
            risk_hints.append("object_id_in_path")
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            risk_hints.append("writes_state")
        if "/admin" in path_template.lower():
            risk_hints.append("admin_path")
        owasp_candidates = self._classify_owasp_candidates(
            method=method,
            path_template=path_template,
            auth_required=auth_required,
            risk_hints=risk_hints,
            body_fields=body_fields,
            tags=[str(t or "") for t in (operation.get("tags") or [])],
        )
        op_node = Operation(
            operation_id=operation_id,
            operation_id_from_spec=str(operation.get("operationId") or ""),
            method=method,
            path_template=path_template,
            summary=str(operation.get("summary") or operation.get("description") or ""),
            tags=[str(t) for t in (operation.get("tags") or []) if str(t).strip()],
            auth_required=auth_required,
            security=security_names,
            path_params=path_params,
            query_params=query_params,
            body_fields=body_fields,
            response_fields=response_fields,
            resource_type=resource_type,
            risk_hints=risk_hints,
            owasp_candidates=owasp_candidates,
            sources=["openapi"],
        )
        graph.operations.append(op_node)
        self._add_parameters(graph, op_node, parameters, body_fields, resource_type)
        self._upsert_resource_type(graph, resource_type)
        self._add_requires_auth_edge(graph, op_node, security_names)

    def _add_parameters(
        self,
        graph: ApiGraph,
        op_node: Operation,
        parameters: list[Mapping[str, Any]],
        body_fields: list[str],
        resource_type: str,
    ) -> None:
        for param in parameters:
            location = str(param.get("in") or "").lower()
            name = str(param.get("name") or "").strip()
            if not name or location not in {"path", "query", "header", "cookie"}:
                continue
            param_id = f"param:{op_node.operation_id}:{location}:{name}"
            graph.parameters.append(
                Parameter(
                    parameter_id=param_id,
                    operation_id=op_node.operation_id,
                    name=name,
                    location=location,
                    object_id_hint=_looks_like_object_id(name),
                    resource_type_hint=_resource_type_hint(name, resource_type),
                )
            )
            graph.edges.append(
                GraphEdge(
                    edge_id=f"e_{uuid4().hex[:10]}",
                    type="HAS_PARAM",
                    from_node=op_node.operation_id,
                    to_node=param_id,
                    confidence=1.0,
                    sources=["openapi"],
                )
            )
        for field_name in body_fields:
            param_id = f"param:{op_node.operation_id}:body:{field_name}"
            graph.parameters.append(
                Parameter(
                    parameter_id=param_id,
                    operation_id=op_node.operation_id,
                    name=field_name,
                    location="body",
                    object_id_hint=_looks_like_object_id(field_name),
                    resource_type_hint=_resource_type_hint(field_name, resource_type),
                )
            )
            graph.edges.append(
                GraphEdge(
                    edge_id=f"e_{uuid4().hex[:10]}",
                    type="HAS_PARAM",
                    from_node=op_node.operation_id,
                    to_node=param_id,
                    confidence=1.0,
                    sources=["openapi"],
                )
            )

    def _upsert_resource_type(self, graph: ApiGraph, resource_type: str) -> ResourceType | None:
        if not resource_type:
            return None
        for rt in graph.resource_types:
            if rt.resource_type == resource_type:
                return rt
        rt = ResourceType(resource_type=resource_type)
        graph.resource_types.append(rt)
        return rt

    def _add_requires_auth_edge(
        self, graph: ApiGraph, op_node: Operation, security_names: list[str]
    ) -> None:
        if security_names:
            for scheme in security_names:
                graph.edges.append(
                    GraphEdge(
                        edge_id=f"e_{uuid4().hex[:10]}",
                        type="REQUIRES_AUTH",
                        from_node=op_node.operation_id,
                        to_node=f"auth:scheme:{scheme}",
                        confidence=1.0,
                        sources=["openapi"],
                    )
                )
        elif op_node.auth_required:
            graph.edges.append(
                GraphEdge(
                    edge_id=f"e_{uuid4().hex[:10]}",
                    type="REQUIRES_AUTH",
                    from_node=op_node.operation_id,
                    to_node="auth:any",
                    confidence=0.8,
                    sources=["openapi"],
                )
            )

    # ------------------------------------------------------------------
    # OWASP heuristics
    # ------------------------------------------------------------------
    def _classify_owasp_candidates(
        self,
        *,
        method: str,
        path_template: str,
        auth_required: bool,
        risk_hints: list[str],
        body_fields: list[str],
        tags: list[str],
    ) -> list[str]:
        candidates: list[str] = []
        path_lower = path_template.lower()
        admin_path = "/admin" in path_lower or any(
            tag.lower() == "admin" for tag in tags
        )
        if auth_required and "object_id_in_path" in risk_hints:
            candidates.append("API1_BOLA")
        if any(name.lower() in _BOPLA_BODY_HINTS for name in body_fields):
            candidates.append("API3_BOPLA")
        if admin_path and auth_required:
            candidates.append("API5_BFLA")
        if admin_path and not auth_required:
            candidates.append("API2_AUTH")
        return candidates

    # ------------------------------------------------------------------
    # Dependency inference (spec)
    # ------------------------------------------------------------------
    def _infer_dependency_edges_from_spec(self, graph: ApiGraph) -> None:
        for op in graph.operations:
            self._maybe_add_produces_edge(graph, op)
            self._maybe_add_consumes_edge(graph, op)

    def _maybe_add_produces_edge(self, graph: ApiGraph, op: Operation) -> None:
        if op.method.upper() != "POST":
            return
        if not op.resource_type:
            return
        if not any(_looks_like_object_id(field) for field in op.response_fields):
            return
        target = f"restype:{op.resource_type}"
        graph.edges.append(
            GraphEdge(
                edge_id=f"e_{uuid4().hex[:10]}",
                type="PRODUCES",
                from_node=op.operation_id,
                to_node=target,
                confidence=0.8,
                sources=["openapi"],
            )
        )
        rt = self._upsert_resource_type(graph, op.resource_type)
        if rt is not None and op.operation_id not in rt.operations_producing:
            rt.operations_producing.append(op.operation_id)

    def _maybe_add_consumes_edge(self, graph: ApiGraph, op: Operation) -> None:
        if not op.resource_type:
            return
        if not any(_looks_like_object_id(name) for name in op.path_params + op.query_params):
            return
        target = f"restype:{op.resource_type}"
        graph.edges.append(
            GraphEdge(
                edge_id=f"e_{uuid4().hex[:10]}",
                type="CONSUMES",
                from_node=op.operation_id,
                to_node=target,
                confidence=0.8,
                sources=["openapi"],
            )
        )
        rt = self._upsert_resource_type(graph, op.resource_type)
        if rt is not None and op.operation_id not in rt.operations_consuming:
            rt.operations_consuming.append(op.operation_id)

    def _add_owasp_edges(self, graph: ApiGraph) -> None:
        for op in graph.operations:
            for category in op.owasp_candidates:
                graph.edges.append(
                    GraphEdge(
                        edge_id=f"e_{uuid4().hex[:10]}",
                        type="MAY_TRIGGER_OWASP",
                        from_node=op.operation_id,
                        to_node=f"owasp:{category}",
                        confidence=0.7,
                        sources=["openapi"],
                    )
                )

    # ------------------------------------------------------------------
    # Corpus enrichment
    # ------------------------------------------------------------------
    def _enrich_from_corpus(self, graph: ApiGraph) -> None:
        items = self._corpus.list_by_campaign(graph.campaign_id)
        for item in items:
            op = self._match_operation(graph, item)
            if op is None:
                op = self._create_corpus_only_operation(graph, item)
            self._update_operation_from_corpus(op, item)
            if item.classification == StatusClassification.successful_seed:
                self._add_request_response_examples(graph, op, item)
                if item.request_id not in op.successful_seed_request_ids:
                    op.successful_seed_request_ids.append(item.request_id)
            elif item.classification == StatusClassification.auth_baseline:
                if item.request_id not in op.auth_baseline_request_ids:
                    op.auth_baseline_request_ids.append(item.request_id)
            self._upsert_auth_profile(graph, op, item)
        self._merge_resource_instances(graph)
        self._mark_cross_role_signals(graph)
        self._upgrade_dependency_edges_from_corpus(graph, items)
        graph.last_corpus_ingest_at = datetime.now(timezone.utc).isoformat()

    def _match_operation(
        self, graph: ApiGraph, item: RequestCorpusItem
    ) -> Operation | None:
        if not item.path_template:
            return None
        method = item.method.upper()
        for op in graph.operations:
            if op.method.upper() == method and op.path_template == item.path_template:
                return op
        return None

    def _create_corpus_only_operation(
        self, graph: ApiGraph, item: RequestCorpusItem
    ) -> Operation:
        path_template = item.path_template or item.url
        method = item.method.upper()
        op = Operation(
            operation_id=_make_operation_id(method, path_template),
            method=method,
            path_template=path_template,
            sources=["corpus_only"],
        )
        graph.operations.append(op)
        return op

    def _update_operation_from_corpus(
        self, op: Operation, item: RequestCorpusItem
    ) -> None:
        if "corpus" not in op.sources and op.sources != ["corpus_only"]:
            op.sources = sorted({*op.sources, "corpus"})
        if item.status_code and item.status_code not in op.observed_status_codes:
            op.observed_status_codes.append(item.status_code)
        if item.auth_profile and item.auth_profile not in op.observed_roles:
            op.observed_roles.append(item.auth_profile)

    def _add_request_response_examples(
        self, graph: ApiGraph, op: Operation, item: RequestCorpusItem
    ) -> None:
        already_request = any(
            r.request_id == item.request_id for r in graph.request_examples
        )
        if not already_request:
            request_example_id = f"rex_{uuid4().hex[:10]}"
            graph.request_examples.append(
                RequestExample(
                    example_id=request_example_id,
                    operation_id=op.operation_id,
                    request_id=item.request_id,
                    auth_profile=item.auth_profile,
                    status_code=item.status_code,
                    classification=item.classification.value,
                )
            )
            graph.edges.append(
                GraphEdge(
                    edge_id=f"e_{uuid4().hex[:10]}",
                    type="HAS_EXAMPLE",
                    from_node=op.operation_id,
                    to_node=request_example_id,
                    confidence=1.0,
                    sources=["corpus"],
                    metadata={"kind": "request"},
                )
            )
        if item.response_body_redacted is not None:
            already_response = any(
                r.request_id == item.request_id for r in graph.response_examples
            )
            if not already_response:
                response_fields_seen: list[str] = []
                if isinstance(item.response_body_redacted, Mapping):
                    response_fields_seen = [
                        str(k) for k in item.response_body_redacted.keys()
                    ]
                response_example_id = f"respx_{uuid4().hex[:10]}"
                graph.response_examples.append(
                    ResponseExample(
                        example_id=response_example_id,
                        operation_id=op.operation_id,
                        request_id=item.request_id,
                        status_code=item.status_code,
                        response_fields_seen=response_fields_seen,
                        extracted_id_keys=list(item.extracted_ids.keys()),
                    )
                )
                graph.edges.append(
                    GraphEdge(
                        edge_id=f"e_{uuid4().hex[:10]}",
                        type="HAS_EXAMPLE",
                        from_node=op.operation_id,
                        to_node=response_example_id,
                        confidence=1.0,
                        sources=["corpus"],
                        metadata={"kind": "response"},
                    )
                )

    def _upsert_auth_profile(
        self, graph: ApiGraph, op: Operation, item: RequestCorpusItem
    ) -> None:
        if not item.auth_profile:
            return
        auth_profile_id = f"auth:{item.auth_profile}"
        existing = next(
            (a for a in graph.auth_profiles if a.auth_profile_id == auth_profile_id),
            None,
        )
        if existing is None:
            existing = AuthProfile(
                auth_profile_id=auth_profile_id,
                role_name=item.auth_profile,
                has_credentials=True,
                operations_observed=[op.operation_id],
            )
            graph.auth_profiles.append(existing)
        else:
            if op.operation_id not in existing.operations_observed:
                existing.operations_observed.append(op.operation_id)

    def _merge_resource_instances(self, graph: ApiGraph) -> None:
        seen: set[str] = {ri.resource_instance_id for ri in graph.resource_instances}
        existing_edges_for_rt: set[tuple[str, str]] = set()
        for edge in graph.edges:
            if edge.type == "HAS_RESOURCE_INSTANCE":
                existing_edges_for_rt.add((edge.from_node, edge.to_node))
        for raw in memory_store.list_resources_by_campaign(graph.campaign_id):
            rid = str(raw.get("resource_instance_id") or "")
            if not rid or rid in seen:
                continue
            ri = ResourceInstanceRef(
                resource_instance_id=rid,
                resource_type=str(raw.get("resource_type") or ""),
                object_id=str(raw.get("object_id") or ""),
                owner_role=str(raw.get("owner_role") or ""),
                observed_by_roles=list(raw.get("observed_by_roles") or []),
                cross_role_observed=len(list(raw.get("observed_by_roles") or [])) >= 2,
            )
            graph.resource_instances.append(ri)
            seen.add(rid)
            if ri.resource_type:
                rt = self._upsert_resource_type(graph, ri.resource_type)
                if rt is not None:
                    rt.instance_count += 1
                from_node = f"restype:{ri.resource_type}"
                to_node = f"res:{ri.resource_type}:{ri.object_id}"
                if (from_node, to_node) not in existing_edges_for_rt:
                    graph.edges.append(
                        GraphEdge(
                            edge_id=f"e_{uuid4().hex[:10]}",
                            type="HAS_RESOURCE_INSTANCE",
                            from_node=from_node,
                            to_node=to_node,
                            confidence=1.0,
                            sources=["corpus"],
                        )
                    )
                    existing_edges_for_rt.add((from_node, to_node))
            if ri.cross_role_observed and ri.owner_role:
                graph.edges.append(
                    GraphEdge(
                        edge_id=f"e_{uuid4().hex[:10]}",
                        type="OWNED_BY",
                        from_node=f"res:{ri.resource_type}:{ri.object_id}",
                        to_node=f"auth:{ri.owner_role}",
                        confidence=0.6,
                        sources=["corpus"],
                        metadata={"observed_roles": ri.observed_by_roles},
                    )
                )

    def _mark_cross_role_signals(self, graph: ApiGraph) -> None:
        candidates = self._corpus.find_cross_role_candidates(graph.campaign_id)
        for candidate in candidates:
            key = str(candidate.get("operation_key") or "")
            if not key:
                continue
            for op in graph.operations:
                if (
                    op.operation_id == key
                    or f"{op.method.upper()}:{op.path_template}" == key
                ):
                    if "cross_role_signal" not in op.risk_hints:
                        op.risk_hints.append("cross_role_signal")

    def _upgrade_dependency_edges_from_corpus(
        self, graph: ApiGraph, items: list[RequestCorpusItem]
    ) -> None:
        seeds = [
            i for i in items
            if i.classification == StatusClassification.successful_seed
        ]
        produced_ids_by_resource: dict[str, set[str]] = {}
        consumed_ids_by_resource: dict[str, set[str]] = {}
        for item in seeds:
            op = self._match_operation(graph, item)
            if op is None or not op.resource_type:
                continue
            if op.method.upper() == "POST":
                response_ids = item.extracted_ids.get("responseId") or []
                produced_ids_by_resource.setdefault(op.resource_type, set()).update(
                    response_ids
                )
            consumed_ids: set[str] = set()
            for key, values in item.extracted_ids.items():
                if key == "responseId":
                    continue
                if _looks_like_object_id(key):
                    consumed_ids.update(values)
            if consumed_ids:
                consumed_ids_by_resource.setdefault(op.resource_type, set()).update(
                    consumed_ids
                )
        for edge in graph.edges:
            if edge.type not in {"PRODUCES", "CONSUMES"}:
                continue
            if not edge.to_node.startswith("restype:"):
                continue
            resource_type = edge.to_node[len("restype:"):]
            produced = produced_ids_by_resource.get(resource_type, set())
            consumed = consumed_ids_by_resource.get(resource_type, set())
            if produced and consumed and produced & consumed:
                edge.confidence = max(edge.confidence, 0.95)
                if "openapi" in edge.sources:
                    edge.sources = sorted({"openapi", "corpus"})
                else:
                    edge.sources = sorted({*edge.sources, "corpus"})
                edge.metadata["overlapping_ids"] = sorted(produced & consumed)


DEFAULT_API_GRAPH_SERVICE = ApiGraphService()
