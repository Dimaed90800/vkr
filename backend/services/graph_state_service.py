from __future__ import annotations

from typing import Any, Mapping

try:
    from backend.models.testing import ExecutionContext, TaskModel
except ModuleNotFoundError:  # pragma: no cover
    from models.testing import ExecutionContext, TaskModel


class GraphStateService:
    """Maintains a lightweight executable dependency graph inside execution_context.graph_state.

    The graph is intentionally small and practical. It tracks three dependency families:
    auth_state, object_state and workflow_state.
    """

    GRAPH_VERSION = "v1"

    def ensure_graph(self, context: ExecutionContext) -> dict[str, Any]:
        graph = dict(context.graph_state or {})
        graph.setdefault("version", self.GRAPH_VERSION)
        graph.setdefault("nodes", {})
        graph.setdefault("edges", [])
        context.graph_state = graph
        return graph

    def upsert_auth_identities(self, context: ExecutionContext, identities: list[dict[str, Any]]) -> dict[str, Any]:
        graph = self.ensure_graph(context)
        nodes = graph["nodes"]
        for identity in identities or []:
            if not isinstance(identity, dict):
                continue
            for alias in self._identity_aliases(identity):
                node_id = f"auth:{alias}:context"
                nodes[node_id] = {
                    "id": node_id,
                    "kind": "auth_context",
                    "status": "ready" if self._has_auth_material(identity) else "candidate",
                    "aliases": sorted(self._identity_aliases(identity)),
                    "role": str(identity.get("role") or "").strip() or alias,
                    "has_auth_material": self._has_auth_material(identity),
                }
        return graph

    def upsert_prepared_object(self, context: ExecutionContext, prepared_object: Mapping[str, Any] | None) -> dict[str, Any]:
        graph = self.ensure_graph(context)
        if not isinstance(prepared_object, Mapping):
            return graph
        object_id = self._normalize_object_id(prepared_object.get("object_id"))
        family = self._normalized_family(prepared_object.get("resource_family") or prepared_object.get("object_type"))
        if not object_id:
            return graph
        node_id = f"object:{family or 'generic'}:{object_id}"
        graph["nodes"][node_id] = {
            "id": node_id,
            "kind": "object",
            "status": "ready",
            "object_id": object_id,
            "resource_family": family,
            "source": str(prepared_object.get("source") or "prepared_object").strip() or "prepared_object",
        }
        if family:
            family_node = f"object_family:{family}:ready"
            graph["nodes"][family_node] = {
                "id": family_node,
                "kind": "object_state",
                "status": "ready",
                "resource_family": family,
                "object_id": object_id,
            }
        return graph

    def upsert_harvested_ids(self, context: ExecutionContext, harvested_ids: list[str], *, resource_family: str = "") -> dict[str, Any]:
        graph = self.ensure_graph(context)
        family = self._normalized_family(resource_family)
        for raw in harvested_ids or []:
            object_id = self._normalize_object_id(raw)
            if not object_id:
                continue
            node_id = f"object:{family or 'generic'}:{object_id}"
            graph["nodes"][node_id] = {
                "id": node_id,
                "kind": "object",
                "status": "candidate",
                "object_id": object_id,
                "resource_family": family,
                "source": "harvested_object_ids",
            }
        return graph

    def upsert_workflow_context(self, context: ExecutionContext, workflow_context: Mapping[str, Any] | None) -> dict[str, Any]:
        graph = self.ensure_graph(context)
        if not isinstance(workflow_context, Mapping) or not workflow_context:
            return graph
        endpoint = str(workflow_context.get("endpoint") or workflow_context.get("path") or "").strip()
        family = self._normalized_family(workflow_context.get("resource_family"))
        object_id = self._normalize_object_id(workflow_context.get("object_id"))
        state_id = endpoint or family or "generic"
        node_id = f"workflow:{state_id}:ready"
        graph["nodes"][node_id] = {
            "id": node_id,
            "kind": "workflow_state",
            "status": "ready",
            "endpoint": endpoint,
            "resource_family": family,
            "object_id": object_id,
            "source": str(workflow_context.get("source") or "workflow_context").strip() or "workflow_context",
        }
        return graph

    def auth_context_available(self, task: TaskModel, context: ExecutionContext) -> bool:
        owner = str(task.auth_context.owner_role or "").strip().lower()
        other = str(task.auth_context.other_role or "").strip().lower()
        available_aliases = self._available_auth_aliases(context)
        if owner and owner not in available_aliases:
            return False
        if other and other not in available_aliases:
            return False
        if owner or other:
            return True
        return bool(available_aliases or context.capabilities.get("has_auth_profiles") or context.capabilities.get("has_multi_role_auth"))

    def resolve_object_id(self, task: TaskModel, context: ExecutionContext) -> tuple[str | None, list[str]]:
        values: list[str] = []
        preferred_family = self._task_resource_family(task)
        candidate_values = [task.params.selected_object_id, *(task.params.object_id_candidates or [])]
        if preferred_family:
            prepared = context.prepared_objects.get(preferred_family) if isinstance(context.prepared_objects, dict) else None
            if isinstance(prepared, Mapping):
                candidate_values.insert(0, prepared.get("object_id"))
        for item in context.harvested_object_ids or []:
            candidate_values.append(item)
        graph = self.ensure_graph(context)
        for node in graph.get("nodes", {}).values():
            if not isinstance(node, Mapping) or str(node.get("kind") or "") != "object":
                continue
            node_family = self._normalized_family(node.get("resource_family"))
            if preferred_family and node_family and node_family != preferred_family:
                continue
            candidate_values.append(node.get("object_id"))
        for item in candidate_values:
            normalized = self._normalize_object_id(item)
            if normalized and normalized not in values:
                values.append(normalized)
        return (values[0] if values else None), values

    def workflow_state_available(self, task: TaskModel, context: ExecutionContext, resolved_object_id: str | None = None) -> bool:
        hints = task.context_hints or {}
        capability_state = task.capability_state or {}
        if bool(hints.get("prepared_workflow_state")) or bool(capability_state.get("has_workflow_hints")):
            return True
        family = self._task_resource_family(task)
        workflow_context = context.workflow_context or {}
        if isinstance(workflow_context, Mapping):
            wf_family = self._normalized_family(workflow_context.get("resource_family"))
            wf_endpoint = str(workflow_context.get("endpoint") or workflow_context.get("path") or "").strip().lower()
            if family and wf_family == family:
                return True
            if wf_endpoint and wf_endpoint == str(task.endpoint or "").strip().lower():
                return True
            if resolved_object_id and self._normalize_object_id(workflow_context.get("object_id")) == resolved_object_id:
                return True
        graph = self.ensure_graph(context)
        endpoint = str(task.endpoint or "").strip().lower()
        for node in graph.get("nodes", {}).values():
            if not isinstance(node, Mapping) or str(node.get("kind") or "") != "workflow_state":
                continue
            if str(node.get("status") or "") != "ready":
                continue
            node_family = self._normalized_family(node.get("resource_family"))
            node_endpoint = str(node.get("endpoint") or "").strip().lower()
            if endpoint and node_endpoint == endpoint:
                return True
            if family and node_family == family:
                return True
            if resolved_object_id and self._normalize_object_id(node.get("object_id")) == resolved_object_id:
                return True
        return False

    def build_required_nodes(self, task: TaskModel) -> list[str]:
        nodes: list[str] = []
        owner = str(task.auth_context.owner_role or "").strip().lower()
        other = str(task.auth_context.other_role or "").strip().lower()
        if task.prerequisites.requires_auth_context:
            if owner:
                nodes.append(f"auth:{owner}:context")
            if other:
                nodes.append(f"auth:{other}:context")
            if not owner and not other:
                nodes.append("auth:any:context")
        if task.prerequisites.requires_object_id:
            family = self._task_resource_family(task) or "generic"
            nodes.append(f"object_family:{family}:ready")
        if task.prerequisites.requires_workflow_state:
            endpoint = str(task.endpoint or "").strip() or family if (family := self._task_resource_family(task)) else "generic"
            nodes.append(f"workflow:{endpoint}:ready")
        return nodes

    def add_requirement_edges(self, context: ExecutionContext, task: TaskModel) -> None:
        graph = self.ensure_graph(context)
        edges = graph["edges"]
        task_node = f"task:{task.id}"
        for node_id in self.build_required_nodes(task):
            edge = {"from": task_node, "to": node_id, "type": "requires"}
            if edge not in edges:
                edges.append(edge)

    def _available_auth_aliases(self, context: ExecutionContext) -> set[str]:
        aliases: set[str] = set()
        for role in context.roles or []:
            if not isinstance(role, Mapping) or not self._has_auth_material(role):
                continue
            aliases.update(self._identity_aliases(role))
        graph = self.ensure_graph(context)
        for node in graph.get("nodes", {}).values():
            if not isinstance(node, Mapping) or str(node.get("kind") or "") != "auth_context":
                continue
            if not bool(node.get("has_auth_material")):
                continue
            for alias in node.get("aliases") or []:
                value = str(alias or "").strip().lower()
                if value:
                    aliases.add(value)
        return aliases

    def _identity_aliases(self, identity: Mapping[str, Any]) -> set[str]:
        aliases: set[str] = set()
        for key in ("name", "role", "username", "email"):
            value = str(identity.get(key) or "").strip().lower()
            if value:
                aliases.add(value)
        for item in identity.get("aliases") or []:
            value = str(item or "").strip().lower()
            if value:
                aliases.add(value)
        return aliases

    def _task_resource_family(self, task: TaskModel) -> str:
        hints = task.context_hints or {}
        return self._normalized_family(task.resource_family or hints.get("resource_family"))

    def _normalized_family(self, value: Any) -> str:
        return str(value or "").strip().lower()

    def _normalize_object_id(self, value: Any) -> str | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        if normalized.startswith("{") and normalized.endswith("}"):
            return None
        return normalized

    def _has_auth_material(self, role: Mapping[str, Any]) -> bool:
        return bool(role.get("token") or role.get("auth_headers") or role.get("cookies"))


DEFAULT_GRAPH_STATE = GraphStateService()
