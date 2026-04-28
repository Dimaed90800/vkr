"""LLM-assisted ranking for planner candidates (safe summaries only, no execution)."""
from __future__ import annotations

import json
import logging
from typing import Any, Callable

try:
    from backend.models.api_graph import Operation
except ModuleNotFoundError:  # pragma: no cover
    from models.api_graph import Operation  # type: ignore

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a candidate ranking assistant for safe REST API DAST.
Use only the provided OpenAPI graph summary (operation_id, method, path metadata, schema field names).
Do not invent endpoints or operation_id values.
Do not propose destructive actions.
Do not call anything a vulnerability or a confirmed finding.
Rank candidates for the data_exposure_validator tool (response field inventory only).

Return strict JSON with this shape only:
{
  "ranked_candidates": [
    {
      "operation_id": "...",
      "recommended": true,
      "priority": 0,
      "requires_seed": false,
      "requires_auth": false,
      "reason": "short text"
    }
  ],
  "warnings": []
}

Lower priority number means higher preference (0 is best).
Only include operation_id values that appear in the input operations list.
"""


def build_data_exposure_ranking_user_json(campaign_id: str, operations: list[dict[str, Any]]) -> str:
    bundle = {"campaign_id": campaign_id, "operations": operations}
    return json.dumps(bundle, ensure_ascii=False)


class LlmCandidateAdvisor:
    """Ranks data_exposure_validator targets from safe OpenAPI summaries. LLM is optional."""

    def __init__(self, llm_complete: Callable[[str, str], str] | None = None) -> None:
        self._llm_complete = llm_complete

    @staticmethod
    def operation_to_safe_summary(op: Operation, *, deterministic_score: float = 0.0) -> dict[str, Any]:
        path_t = str(op.path_template or "").strip()
        return {
            "operation_id": op.operation_id,
            "method": str(op.method or "").strip().upper(),
            "path_template": path_t,
            "has_path_params": bool(op.path_params),
            "auth_required": bool(op.auth_required),
            "resource_type": str(op.resource_type or "").strip(),
            "request_field_names": list(op.body_fields or [])[:80],
            "response_field_names": list(op.response_fields or [])[:80],
            "tags": list(op.tags or [])[:24],
            "summary": str(op.summary or "")[:240],
            "deterministic_score": float(deterministic_score),
        }

    @staticmethod
    def _strip_internal_fields(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for row in rows:
            clean = {k: v for k, v in row.items() if k != "deterministic_score"}
            out.append(clean)
        return out

    @staticmethod
    def _deterministic_ranked(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
        ordered = sorted(
            operations,
            key=lambda x: (-float(x.get("deterministic_score", 0.0)), str(x.get("operation_id") or "")),
        )
        ranked: list[dict[str, Any]] = []
        for i, op in enumerate(ordered):
            oid = str(op.get("operation_id") or "").strip()
            if not oid:
                continue
            ranked.append({
                "operation_id": oid,
                "recommended": True,
                "priority": i,
                "requires_seed": bool(op.get("has_path_params")),
                "requires_auth": bool(op.get("auth_required")),
                "reason": "deterministic_openapi_heuristic",
            })
        return ranked

    def _parse_llm_payload(self, raw: str, allowed: set[str]) -> tuple[list[dict[str, Any]], list[str]]:
        warnings: list[str] = []
        data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError("root_not_object")
        rc = data.get("ranked_candidates")
        if not isinstance(rc, list):
            raise ValueError("missing_ranked_candidates")
        merged: list[dict[str, Any]] = []
        unknown: list[str] = []
        for row in rc:
            if not isinstance(row, dict):
                continue
            oid = str(row.get("operation_id") or "").strip()
            if not oid or oid not in allowed:
                if oid:
                    unknown.append(oid)
                continue
            merged.append({
                "operation_id": oid,
                "recommended": bool(row.get("recommended", True)),
                "priority": int(row.get("priority", len(merged))),
                "requires_seed": bool(row.get("requires_seed", False)),
                "requires_auth": bool(row.get("requires_auth", False)),
                "reason": str(row.get("reason") or "")[:500],
            })
        if unknown:
            warnings.append(f"ignored_unknown_operation_ids:{','.join(unknown[:8])}")
        wl = data.get("warnings")
        if isinstance(wl, list):
            for w in wl[:12]:
                t = str(w).strip()
                if t:
                    warnings.append(t[:240])
        return merged, warnings

    def rank_data_exposure_candidates(
        self,
        campaign_id: str,
        operations: list[dict[str, Any]],
        max_candidates: int = 10,
        *,
        enable_llm: bool = False,
    ) -> dict[str, Any]:
        ops = [dict(x) for x in (operations or []) if isinstance(x, dict)]
        if not ops:
            return {"advisor_available": False, "ranked_candidates": [], "warnings": ["no_operations"]}

        warnings: list[str] = []
        sorted_ops = sorted(
            ops,
            key=lambda x: (-float(x.get("deterministic_score", 0.0)), str(x.get("operation_id") or "")),
        )
        cap = max(1, int(max_candidates or 10))
        llm_focus = sorted_ops[: min(cap, len(sorted_ops))]
        allowed = {str(o.get("operation_id") or "").strip() for o in llm_focus if o.get("operation_id")}

        fallback_full = self._deterministic_ranked(sorted_ops)
        fallback_focus = self._deterministic_ranked(llm_focus)

        if not enable_llm:
            warnings.append("llm_candidate_advisor_disabled")
            return {"advisor_available": False, "ranked_candidates": fallback_full, "warnings": warnings}

        if self._llm_complete is None:
            warnings.append("llm_candidate_advisor_unconfigured")
            return {"advisor_available": False, "ranked_candidates": fallback_full, "warnings": warnings}

        user_json = build_data_exposure_ranking_user_json(
            campaign_id,
            self._strip_internal_fields(llm_focus),
        )
        try:
            raw = self._llm_complete(SYSTEM_PROMPT, user_json)
            merged, w_extra = self._parse_llm_payload(raw, allowed)
            warnings.extend(w_extra)
        except Exception as exc:  # noqa: BLE001 — advisor must not break planner
            logger.debug("llm_candidate_advisor failure: %s", exc)
            warnings.append(f"llm_candidate_advisor_error:{type(exc).__name__}")
            return {"advisor_available": False, "ranked_candidates": fallback_full, "warnings": warnings}

        if not merged:
            warnings.append("llm_ranked_empty_after_validation")
            return {"advisor_available": False, "ranked_candidates": fallback_full, "warnings": warnings}

        ranked_ids = {r["operation_id"] for r in merged}
        by_id = {r["operation_id"]: r for r in fallback_full}
        combined = list(merged)
        for op in sorted_ops:
            oid = str(op.get("operation_id") or "").strip()
            if oid and oid not in ranked_ids and oid in by_id:
                combined.append(by_id[oid])
                ranked_ids.add(oid)
        return {"advisor_available": True, "ranked_candidates": combined, "warnings": warnings}
