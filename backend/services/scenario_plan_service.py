"""Phase 15A — orchestrate compact graph + LLM stub + validation (stateless)."""
from __future__ import annotations

try:
    from backend.models.campaign import Campaign
    from backend.models.scenario_plan import (
        ScenarioPlanRequestBody,
        ScenarioPlanResponse,
        ScenarioStatus,
        ValidatedScenarioItem,
    )
    from backend.services.api_graph_service import ApiGraphService
    from backend.services.openapi_scenario_llm_planner import (
        ScenarioLlmClient,
        StubScenarioLlmClient,
    )
    from backend.services.scenario_graph_compact_service import ScenarioGraphCompactService
    from backend.services.scenario_plan_validator import (
        ScenarioPlanValidator,
        ScenarioValidationContext,
    )
    from backend.services.tool_registry import ToolRegistry
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.scenario_plan import (
        ScenarioPlanRequestBody,
        ScenarioPlanResponse,
        ScenarioStatus,
        ValidatedScenarioItem,
    )
    from services.api_graph_service import ApiGraphService
    from services.openapi_scenario_llm_planner import (
        ScenarioLlmClient,
        StubScenarioLlmClient,
    )
    from services.scenario_graph_compact_service import ScenarioGraphCompactService
    from services.scenario_plan_validator import (
        ScenarioPlanValidator,
        ScenarioValidationContext,
    )
    from services.tool_registry import ToolRegistry
    from storage.memory_store import memory_store


class ScenarioPlanError(Exception):
    def __init__(self, code: str, message: str, *, http_status: int = 400) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.http_status = http_status


def _has_passive_signal(campaign_id: str) -> bool:
    for obs in memory_store.list_observations_by_campaign(campaign_id):
        t = str(obs.get("type") or "")
        if t in ("zap_alert", "nuclei_match", "discovered_endpoint"):
            return True
    return False


def _merge_duplicate_scenarios(
    items: list[ValidatedScenarioItem],
) -> list[ValidatedScenarioItem]:
    """Merge by (scenario_type, sorted(operation_ids)); keep first, warn rest."""
    seen: dict[tuple[str, tuple[str, ...]], int] = {}
    out: list[ValidatedScenarioItem] = []
    for item in items:
        key = (item.scenario_type, tuple(sorted(item.operation_ids)))
        if key not in seen:
            seen[key] = len(out)
            out.append(item)
            continue
        idx = seen[key]
        prev = out[idx]
        w = list(prev.warnings or [])
        w.append("duplicate_scenario_merged")
        out[idx] = prev.model_copy(update={"warnings": w})
    return out


def _block_accepted_when_graph_empty(
    scenarios: list[ValidatedScenarioItem],
    *,
    graph_empty: bool,
) -> list[ValidatedScenarioItem]:
    if not graph_empty:
        return scenarios
    out: list[ValidatedScenarioItem] = []
    for s in scenarios:
        if s.status != ScenarioStatus.accepted:
            out.append(s)
            continue
        codes = sorted(set((s.blocking_codes or []) + ["graph_empty"]))
        out.append(
            s.model_copy(
                update={"status": ScenarioStatus.blocked, "blocking_codes": codes},
            ),
        )
    return out


class ScenarioPlanService:
    def __init__(
        self,
        *,
        compact_service: ScenarioGraphCompactService | None = None,
        validator: ScenarioPlanValidator | None = None,
        llm_client: ScenarioLlmClient | None = None,
        graph_api: ApiGraphService | None = None,
        registry: ToolRegistry | None = None,
    ) -> None:
        self._registry = registry or ToolRegistry()
        self._compact = compact_service or ScenarioGraphCompactService()
        self._validator = validator or ScenarioPlanValidator(registry=self._registry)
        self._llm = llm_client or StubScenarioLlmClient()
        self._graph = graph_api or ApiGraphService()

    def plan(self, campaign_id: str, request: ScenarioPlanRequestBody) -> ScenarioPlanResponse:
        raw = memory_store.get_campaign(campaign_id)
        if raw is None:
            raise ScenarioPlanError(
                "campaign_not_found",
                f"Campaign '{campaign_id}' not found.",
                http_status=404,
            )
        campaign = Campaign.model_validate(raw)
        compact = self._compact.build(campaign, max_operations=request.max_operations)
        gs = compact.get("graph_summary") or {}
        graph_empty = int(gs.get("operations_total") or 0) == 0

        warnings: list[str] = []
        if graph_empty:
            warnings.append("api_graph_empty_or_missing")
        if not request.llm.enabled:
            warnings.append("llm_disabled_using_stub_heuristic")
        else:
            warnings.append("llm_stub_no_external_provider")

        raw_plan = self._llm.generate_raw_plan(
            campaign_id=campaign_id,
            compact_graph=compact,
            request=request,
        )

        operations = self._graph.list_operations(campaign_id)
        valid_ids = frozenset(op.operation_id for op in operations)
        object_ids = frozenset(str(x) for x in (gs.get("object_id_operations") or []))
        role_count = int((compact.get("roles_compact") or {}).get("role_count") or 0)
        ctx = ScenarioValidationContext(
            campaign_id=campaign_id,
            valid_operation_ids=valid_ids,
            object_id_operation_ids=object_ids,
            role_count=role_count,
            has_passive_signal=_has_passive_signal(campaign_id),
            graph_empty=graph_empty,
            registry=self._registry,
        )

        scenarios, plan_warnings = self._validator.validate_raw_plan(
            raw_plan if isinstance(raw_plan, dict) else {},
            ctx,
        )
        warnings.extend(plan_warnings)
        merged = _merge_duplicate_scenarios(scenarios)
        max_sc = max(1, min(int(request.max_scenarios or 30), 100))
        merged = merged[:max_sc]
        merged = _block_accepted_when_graph_empty(merged, graph_empty=graph_empty)

        return ScenarioPlanResponse(
            campaign_id=campaign_id,
            graph_empty=graph_empty,
            warnings=warnings,
            scenarios=merged,
        )
