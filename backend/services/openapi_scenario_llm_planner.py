"""Phase 15A — LLM scenario planner interface + stub (no network)."""
from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

try:
    from backend.models.scenario_plan import ScenarioPlanRequestBody, ScenarioType
except ModuleNotFoundError:  # pragma: no cover
    from models.scenario_plan import ScenarioPlanRequestBody, ScenarioType


@runtime_checkable
class ScenarioLlmClient(Protocol):
    def generate_raw_plan(
        self,
        *,
        campaign_id: str,
        compact_graph: dict[str, Any],
        request: ScenarioPlanRequestBody,
    ) -> dict[str, Any]:
        """Return raw dict matching ``scenario-plan/v1`` (list under ``scenarios``)."""
        ...


class PromptBuilder:
    """Build prompts for a future real LLM client (no HTTP here)."""

    @staticmethod
    def system_prompt(*, prompt_version: str) -> str:
        return (
            f"You are ScenarioPlanner ({prompt_version}). "
            "Output JSON only matching schema scenario-plan/v1. "
            "Do not create findings. ScenarioPlan is analysis-only. "
            "Use only operation_id values from the provided allowlist. "
            "Do not invent free-text paths. Never include http:// or https:// URLs in output. "
            "Do not output HTTP requests, tokens, "
            "Authorization, Cookie, Bearer, api keys, or JWTs. "
            "candidate_workers must be from the known tool list provided. "
            "scenario_type must be one of the allowed scenario types."
        )

    @staticmethod
    def user_prompt(*, campaign_id: str, compact_graph: dict[str, Any]) -> str:
        import json

        allowlist = [
            op.get("operation_id")
            for op in (compact_graph.get("operations_compact") or [])
            if isinstance(op, dict) and op.get("operation_id")
        ]
        bundle = {
            "campaign_id": campaign_id,
            "graph_summary": compact_graph.get("graph_summary"),
            "operations_compact": compact_graph.get("operations_compact"),
            "roles_compact": compact_graph.get("roles_compact"),
            "allowed_operation_ids_sample": allowlist[:200],
        }
        return (
            "Propose scenarios as JSON with key scenarios (array). "
            "Each scenario must reference only allowed_operation_ids_sample "
            "for operation_ids.\n"
            f"{json.dumps(bundle, ensure_ascii=False)}"
        )


def _first_ops(compact: dict[str, Any], *, n: int = 3) -> list[str]:
    out: list[str] = []
    for op in compact.get("operations_compact") or []:
        if not isinstance(op, dict):
            continue
        oid = str(op.get("operation_id") or "").strip()
        if oid and oid not in out:
            out.append(oid)
        if len(out) >= n:
            break
    return out


def _ops_by_methods(compact: dict[str, Any], methods: set[str], *, n: int = 2) -> list[str]:
    out: list[str] = []
    for op in compact.get("operations_compact") or []:
        if not isinstance(op, dict):
            continue
        m = str(op.get("method") or "").upper()
        if m in methods:
            oid = str(op.get("operation_id") or "").strip()
            if oid and oid not in out:
                out.append(oid)
        if len(out) >= n:
            break
    return out


def _ops_with_owasp(compact: dict[str, Any], token: str, *, n: int = 2) -> list[str]:
    out: list[str] = []
    for op in compact.get("operations_compact") or []:
        if not isinstance(op, dict):
            continue
        cands = [str(x).upper() for x in (op.get("owasp_candidates") or [])]
        if any(token in c for c in cands):
            oid = str(op.get("operation_id") or "").strip()
            if oid and oid not in out:
                out.append(oid)
        if len(out) >= n:
            break
    return out


class StubScenarioLlmClient:
    """Deterministic heuristic planner; never performs HTTP."""

    def generate_raw_plan(
        self,
        *,
        campaign_id: str,
        compact_graph: dict[str, Any],
        request: ScenarioPlanRequestBody,
    ) -> dict[str, Any]:
        op_rows = compact_graph.get("operations_compact") or []
        if not isinstance(op_rows, list) or not op_rows:
            return {
                "schema_version": "scenario-plan/v1",
                "campaign_id": campaign_id,
                "source": "llm_openapi_scenario_planner",
                "scenarios": [],
            }

        max_sc = max(1, min(int(request.max_scenarios or 30), 100))
        gs = compact_graph.get("graph_summary") or {}
        object_ops = list(gs.get("object_id_operations") or [])
        bfla_ops = list(gs.get("bfla_candidates") or [])
        scenarios: list[dict[str, Any]] = []

        def push(sc: dict[str, Any]) -> None:
            if len(scenarios) >= max_sc:
                return
            scenarios.append(sc)

        push({
            "scenario_id": "scn_heuristic_schema_negative",
            "scenario_type": ScenarioType.schema_negative_testing.value,
            "vulnerability_classes": ["SCHEMA"],
            "operation_ids": _first_ops(compact_graph, n=4),
            "resource_type": "",
            "required_preconditions": ["openapi_schema"],
            "candidate_workers": ["schemathesis_negative_test"],
            "confidence": 0.45,
            "rationale": "Contract/schema negative testing candidate from graph operations.",
        })

        bola_ops = [oid for oid in _first_ops(compact_graph, n=12) if oid in set(object_ops)]
        if bola_ops:
            push({
                "scenario_id": "scn_heuristic_bola",
                "scenario_type": ScenarioType.access_control_bola.value,
                "vulnerability_classes": ["BOLA"],
                "operation_ids": bola_ops[:3],
                "resource_type": "",
                "required_preconditions": [
                    "two_authenticated_roles",
                    "owner_object_id",
                    "object_id_operation",
                ],
                "candidate_workers": ["bola_replay_probe"],
                "confidence": 0.55,
                "rationale": "Object-level path operations suggest BOLA verification.",
            })

        bfla_pick = bfla_ops[:2] or _ops_with_owasp(compact_graph, "API5", n=2)
        if bfla_pick:
            push({
                "scenario_id": "scn_heuristic_bfla",
                "scenario_type": ScenarioType.access_control_bfla.value,
                "vulnerability_classes": ["BFLA"],
                "operation_ids": bfla_pick,
                "resource_type": "",
                "required_preconditions": ["admin_or_privileged_role"],
                "candidate_workers": ["auth_test_access"],
                "confidence": 0.4,
                "rationale": "Privilege/function misuse checks for flagged operations.",
            })

        ma_ops = _ops_by_methods(compact_graph, {"POST", "PUT", "PATCH"}, n=2)
        if ma_ops:
            push({
                "scenario_id": "scn_heuristic_mass_assignment",
                "scenario_type": ScenarioType.mass_assignment.value,
                "vulnerability_classes": ["MASS_ASSIGNMENT"],
                "operation_ids": ma_ops,
                "resource_type": "",
                "required_preconditions": ["writable_schema", "authenticated_session"],
                "candidate_workers": ["property_mutation_test"],
                "confidence": 0.35,
                "rationale": "Write operations may allow mass-assignment style property abuse.",
            })

        ede_ops = _ops_with_owasp(compact_graph, "API3", n=2)
        if ede_ops:
            push({
                "scenario_id": "scn_heuristic_data_exposure",
                "scenario_type": ScenarioType.excessive_data_exposure.value,
                "vulnerability_classes": ["DATA_EXPOSURE"],
                "operation_ids": ede_ops,
                "resource_type": "",
                "required_preconditions": ["response_schema"],
                "candidate_workers": ["data_exposure_test"],
                "confidence": 0.35,
                "rationale": "Operations tagged with data exposure risk.",
            })

        push({
            "scenario_id": "scn_heuristic_passive_signal",
            "scenario_type": ScenarioType.passive_signal_validation.value,
            "vulnerability_classes": ["MISCONFIG"],
            "operation_ids": _first_ops(compact_graph, n=1),
            "resource_type": "",
            "required_preconditions": ["passive_signal_context"],
            "candidate_workers": ["zap_discovery_passive"],
            "confidence": 0.3,
            "rationale": "Passive inventory / signal capture for downstream validation.",
        })

        push({
            "scenario_id": "scn_heuristic_security_header",
            "scenario_type": ScenarioType.security_header_validation.value,
            "vulnerability_classes": ["MISCONFIG"],
            "operation_ids": _first_ops(compact_graph, n=1),
            "resource_type": "",
            "required_preconditions": ["passive_signal_context"],
            "candidate_workers": ["security_header_validator"],
            "confidence": 0.3,
            "rationale": "Security header replay validation after passive signals exist.",
        })

        push({
            "scenario_id": "scn_heuristic_discovery",
            "scenario_type": ScenarioType.discovery_expansion.value,
            "vulnerability_classes": ["INVENTORY"],
            "operation_ids": _first_ops(compact_graph, n=2),
            "resource_type": "",
            "required_preconditions": ["seed_url"],
            "candidate_workers": ["httpx"],
            "confidence": 0.25,
            "rationale": "Lightweight discovery expansion when budget allows.",
        })

        return {
            "schema_version": "scenario-plan/v1",
            "campaign_id": campaign_id,
            "source": "llm_openapi_scenario_planner",
            "scenarios": scenarios[:max_sc],
        }
