"""Phase 15A — validate and normalize raw ScenarioPlan output."""
from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any

try:
    from backend.models.scenario_plan import (
        SCENARIO_TYPES,
        REQUIRED_PRECONDITIONS,
        VULNERABILITY_CLASS_ALLOWLIST,
        RawScenarioItem,
        RawScenarioPlan,
        ScenarioStatus,
        ScenarioType,
        ValidatedScenarioItem,
    )
    from backend.services.tool_registry import ToolRegistry
except ModuleNotFoundError:  # pragma: no cover
    from models.scenario_plan import (
        SCENARIO_TYPES,
        REQUIRED_PRECONDITIONS,
        VULNERABILITY_CLASS_ALLOWLIST,
        RawScenarioItem,
        RawScenarioPlan,
        ScenarioStatus,
        ScenarioType,
        ValidatedScenarioItem,
    )
    from services.tool_registry import ToolRegistry

_RATIONALE_MAX = 800
_VULN_CLASS_MAX_LEN = 64

_JWT_LIKE = re.compile(
    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
)


def _contains_raw_url(text: str) -> bool:
    lower = (text or "").lower()
    return "http://" in lower or "https://" in lower


def _contains_raw_url_any(obj: Any) -> bool:
    if isinstance(obj, str):
        return _contains_raw_url(obj)
    if isinstance(obj, list):
        return any(_contains_raw_url_any(x) for x in obj)
    if isinstance(obj, dict):
        return any(_contains_raw_url_any(k) or _contains_raw_url_any(v) for k, v in obj.items())
    return False


def _contains_secret(text: str) -> bool:
    if not text:
        return False
    lower = text.lower()
    if "authorization" in lower:
        return True
    if "bearer " in lower or lower.startswith("bearer "):
        return True
    if "cookie:" in lower or "set-cookie" in lower:
        return True
    if "token=" in lower or "api_key=" in lower:
        return True
    if "access_token" in lower or "refresh_token" in lower:
        return True
    if _JWT_LIKE.search(text):
        return True
    return False


def _contains_secret_any(obj: Any) -> bool:
    if isinstance(obj, str):
        return _contains_secret(obj)
    if isinstance(obj, list):
        return any(_contains_secret_any(x) for x in obj)
    if isinstance(obj, dict):
        return any(_contains_secret_any(k) or _contains_secret_any(v) for k, v in obj.items())
    return False


def _truncate_rationale(text: str) -> str:
    s = str(text or "")
    if len(s) <= _RATIONALE_MAX:
        return s
    return s[:_RATIONALE_MAX]


def _coerce_confidence(raw: Any) -> tuple[float | None, str | None]:
    if raw is None:
        return 0.0, None
    try:
        v = float(raw)
    except (TypeError, ValueError):
        return None, "invalid_confidence_type"
    if math.isnan(v) or math.isinf(v):
        return None, "invalid_confidence_non_finite"
    if v < 0.0 or v > 1.0:
        return None, "invalid_confidence_range"
    return v, None


def _normalize_vulnerability_classes(items: Any) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    if items is None:
        return [], errors
    if not isinstance(items, list):
        return [], ["invalid_vulnerability_classes_type"]
    out: list[str] = []
    for item in items:
        s = str(item or "").strip()
        if not s:
            continue
        if len(s) > _VULN_CLASS_MAX_LEN:
            errors.append("vulnerability_class_too_long")
            continue
        if s not in VULNERABILITY_CLASS_ALLOWLIST:
            errors.append(f"unknown_vulnerability_class:{s}")
            continue
        if s not in out:
            out.append(s)
    return out, errors


@dataclass(frozen=True)
class ScenarioValidationContext:
    campaign_id: str
    valid_operation_ids: frozenset[str]
    object_id_operation_ids: frozenset[str]
    role_count: int
    has_passive_signal: bool
    graph_empty: bool
    registry: ToolRegistry


class ScenarioPlanValidator:
    def __init__(self, registry: ToolRegistry | None = None) -> None:
        self._registry = registry or ToolRegistry()

    @property
    def registry(self) -> ToolRegistry:
        return self._registry

    def validate_raw_plan(
        self,
        raw: dict[str, Any],
        context: ScenarioValidationContext,
    ) -> tuple[list[ValidatedScenarioItem], list[str]]:
        plan_warnings: list[str] = []
        if not isinstance(raw, dict):
            return [], ["invalid_raw_plan_not_object"]

        if raw.get("schema_version") != "scenario-plan/v1":
            plan_warnings.append("invalid_raw_schema_version_expected_scenario_plan_v1")

        try:
            model = RawScenarioPlan.model_validate(raw)
        except Exception:
            return [], plan_warnings + ["invalid_raw_plan_shape"]

        scenarios_in = list(model.scenarios or [])
        if not scenarios_in and context.graph_empty:
            return [], plan_warnings

        results: list[ValidatedScenarioItem] = []
        for idx, item in enumerate(scenarios_in):
            results.append(self._validate_one(item, idx, context))
        return results, plan_warnings

    def _validate_one(
        self,
        item: RawScenarioItem,
        index: int,
        ctx: ScenarioValidationContext,
    ) -> ValidatedScenarioItem:
        errors: list[str] = []
        warnings: list[str] = []
        blocking: list[str] = []
        scenario_id = str(item.scenario_id or "").strip() or f"scn_in_{index}"
        scenario_type = str(item.scenario_type or "").strip()

        if _contains_raw_url_any(item.model_dump(mode="json")):
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type or "unknown",
                errors=["raw_url_not_allowed"],
            )

        if _contains_secret_any(item.model_dump()):
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type or "unknown",
                errors=["secret_pattern_in_scenario_fields"],
            )

        if scenario_type not in SCENARIO_TYPES:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type or "unknown",
                errors=["unknown_scenario_type"],
            )

        op_ids = [str(x).strip() for x in (item.operation_ids or []) if str(x).strip()]
        for oid in op_ids:
            if oid not in ctx.valid_operation_ids:
                return ValidatedScenarioItem(
                    scenario_id=scenario_id,
                    status=ScenarioStatus.rejected,
                    scenario_type=scenario_type,
                    operation_ids=op_ids,
                    errors=[f"unknown_operation_id:{oid}"],
                )

        workers = [str(x).strip() for x in (item.candidate_workers or []) if str(x).strip()]
        if not workers:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                operation_ids=op_ids,
                errors=["empty_candidate_workers"],
            )
        if not op_ids:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                candidate_workers=workers,
                errors=["empty_operation_ids"],
            )
        for w in workers:
            if not self._registry.is_known(w):
                return ValidatedScenarioItem(
                    scenario_id=scenario_id,
                    status=ScenarioStatus.rejected,
                    scenario_type=scenario_type,
                    operation_ids=op_ids,
                    candidate_workers=workers,
                    errors=[f"unknown_tool:{w}"],
                )

        conf, cerr = _coerce_confidence(item.confidence)
        if cerr:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                operation_ids=op_ids,
                candidate_workers=workers,
                errors=[cerr],
            )

        rationale = _truncate_rationale(str(item.rationale or ""))
        if _contains_secret(rationale):
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                operation_ids=op_ids,
                candidate_workers=workers,
                errors=["secret_pattern_in_rationale"],
            )

        preconds = [str(x).strip() for x in (item.required_preconditions or []) if str(x).strip()]
        for p in preconds:
            if p not in REQUIRED_PRECONDITIONS:
                return ValidatedScenarioItem(
                    scenario_id=scenario_id,
                    status=ScenarioStatus.rejected,
                    scenario_type=scenario_type,
                    operation_ids=op_ids,
                    candidate_workers=workers,
                    required_preconditions=preconds,
                    errors=[f"unknown_precondition:{p}"],
                )

        vuln_classes, verr = _normalize_vulnerability_classes(item.vulnerability_classes)
        if verr:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                operation_ids=op_ids,
                candidate_workers=workers,
                vulnerability_classes=vuln_classes,
                errors=verr,
            )

        resource_type = str(item.resource_type or "").strip()
        if len(resource_type) > 120:
            errors.append("resource_type_too_long")
        if errors:
            return ValidatedScenarioItem(
                scenario_id=scenario_id,
                status=ScenarioStatus.rejected,
                scenario_type=scenario_type,
                operation_ids=op_ids,
                candidate_workers=workers,
                vulnerability_classes=vuln_classes,
                required_preconditions=preconds,
                resource_type=resource_type[:120],
                errors=errors,
            )

        status = ScenarioStatus.accepted
        if not any(self._registry.has_adapter(w) for w in workers):
            status = ScenarioStatus.blocked
            blocking.append("no_executable_adapter")

        if scenario_type == ScenarioType.access_control_bola.value:
            if ctx.graph_empty or not ctx.object_id_operation_ids:
                status = ScenarioStatus.blocked
                blocking.append("no_object_id_operations_in_graph")
            elif op_ids and not set(op_ids) & ctx.object_id_operation_ids:
                status = ScenarioStatus.blocked
                blocking.append("missing_object_id_operation")
            if ctx.role_count < 2:
                status = ScenarioStatus.blocked
                blocking.append("missing_two_authenticated_roles")

        if scenario_type in (
            ScenarioType.security_header_validation.value,
            ScenarioType.passive_signal_validation.value,
        ):
            if not ctx.has_passive_signal:
                status = ScenarioStatus.blocked
                blocking.append("missing_passive_signal_context")

        blocking = sorted(set(blocking))
        if status == ScenarioStatus.accepted and blocking:
            status = ScenarioStatus.blocked

        return ValidatedScenarioItem(
            scenario_id=scenario_id,
            status=status,
            scenario_type=scenario_type,
            vulnerability_classes=vuln_classes,
            operation_ids=op_ids,
            resource_type=resource_type[:120],
            required_preconditions=preconds,
            candidate_workers=workers,
            confidence=float(conf or 0.0),
            rationale=rationale,
            blocking_codes=blocking,
            warnings=warnings,
        )
