"""Phase 15A — compact API graph bundle for scenario planning (no secrets)."""
from __future__ import annotations

from typing import Any

try:
    from backend.models.api_graph import Operation
    from backend.models.campaign import Campaign
    from backend.services.api_graph_service import ApiGraphService
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation
    from models.campaign import Campaign
    from services.api_graph_service import ApiGraphService


def _role_names_from_campaign(campaign: Campaign) -> list[str]:
    names: list[str] = []
    for entry in campaign.roles_json or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name") or entry.get("role") or entry.get("role_name")
        if name is not None:
            s = str(name).strip()
            if s and s not in names:
                names.append(s)
    return names


def _compact_operation(op: Operation, *, owasp_max: int = 6, risk_max: int = 6) -> dict[str, Any]:
    qparams = list(op.query_params or [])
    pparams = list(op.path_params or [])
    return {
        "operation_id": op.operation_id,
        "method": str(op.method or "").upper(),
        "path_template": op.path_template or "",
        "auth_required": bool(op.auth_required),
        "resource_type": op.resource_type or "",
        "owasp_candidates": list(op.owasp_candidates or [])[:owasp_max],
        "risk_hints": list(op.risk_hints or [])[:risk_max],
        "seed_count": len(op.successful_seed_request_ids or []),
        "has_auth_baseline": bool(op.auth_baseline_request_ids),
        "query_param_count": len(qparams),
        "query_params_sample": qparams[:5],
        "path_param_count": len(pparams),
    }


class ScenarioGraphCompactService:
    def __init__(self) -> None:
        self._graph = ApiGraphService()

    def build(self, campaign: Campaign, *, max_operations: int) -> dict[str, Any]:
        campaign_id = campaign.campaign_id
        summary = self._graph.summary_for_planner(campaign_id)
        operations = self._graph.list_operations(campaign_id)
        cap = max(1, min(int(max_operations or 120), 500))
        sorted_ops = sorted(operations, key=lambda o: o.operation_id)[:cap]
        operations_compact = [_compact_operation(op) for op in sorted_ops]
        role_names = _role_names_from_campaign(campaign)
        return {
            "campaign_id": campaign_id,
            "graph_summary": summary.model_dump(mode="json"),
            "operations_compact": operations_compact,
            "roles_compact": {
                "role_names": role_names,
                "role_count": len(role_names),
            },
        }
