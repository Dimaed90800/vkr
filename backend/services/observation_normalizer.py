"""Phase 5.6 — ObservationNormalizer.

Reads a stored ToolResult by tool_run_id and produces a list of
normalized Observations. Does NOT call Judge, create EvidencePack,
or produce confirmed findings.

Idempotent: calling normalize twice for the same tool_run_id
returns the already-created observations without duplicating.
"""
from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

try:
    from backend.models.observation import Observation, SecurityRelevance
    from backend.models.tool_run import ToolResult
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.observation import Observation, SecurityRelevance
    from models.tool_run import ToolResult
    from storage.memory_store import memory_store


_TERMINAL_STATUSES = {
    "finished",
    "failed",
    "timeout",
    "cancelled",
    "skipped",
    "partial",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_obs_id() -> str:
    return f"obs_{uuid4().hex[:16]}"


class NormalizeError:
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message


class ObservationNormalizer:

    def normalize(self, tool_run_id: str) -> list[Observation] | NormalizeError:
        run_data = memory_store.get_tool_run(tool_run_id)
        if run_data is None:
            return NormalizeError("tool_run_not_found", f"ToolRun '{tool_run_id}' not found.")

        status = run_data.get("status", "")
        if status not in _TERMINAL_STATUSES:
            return NormalizeError(
                "tool_run_not_terminal",
                f"ToolRun '{tool_run_id}' has status '{status}'; only terminal runs can be normalized.",
            )

        existing = memory_store.list_observations_by_tool_run(tool_run_id)
        if existing:
            return [Observation.model_validate(o) for o in existing]

        result_data = memory_store.get_tool_result(tool_run_id)
        if result_data is None:
            return NormalizeError(
                "tool_result_not_found",
                f"No ToolResult stored for ToolRun '{tool_run_id}'.",
            )

        result = ToolResult.model_validate(result_data)
        campaign_id = result.campaign_id
        task_id = result.task_id
        command_id = result.command_id
        source = result.tool_name

        observations: list[Observation] = []

        if result.status in ("failed", "timeout"):
            obs = self._from_failed_result(result, tool_run_id, campaign_id, task_id, command_id, source)
            if obs:
                observations.append(obs)

        if result.status == "finished":
            for resp in result.responses:
                if resp.status_code >= 500:
                    req_match = next(
                        (r for r in result.requests if r.request_id == resp.request_id),
                        None,
                    )
                    observations.append(Observation(
                        observation_id=_make_obs_id(),
                        campaign_id=campaign_id,
                        tool_run_id=tool_run_id,
                        task_id=task_id,
                        command_id=command_id,
                        source=source,
                        type="unexpected_500",
                        operation_id=req_match.path_template if req_match else "",
                        request_id=resp.request_id,
                        auth_profile=req_match.role if req_match else "",
                        status_code=resp.status_code,
                        confidence=0.5,
                        security_relevance="low",
                        judge_worthy=False,
                        recommended_next_action="replay_minimized_payload",
                        details={"status_code": resp.status_code},
                        created_at=_now_iso(),
                    ))

        for lite in result.observations:
            if not lite.observation_type:
                continue
            lite_details = lite.details if isinstance(lite.details, dict) else {}
            sec_rel: SecurityRelevance = SecurityRelevance.unknown
            rec_act = ""
            if str(lite.observation_type) == "injection_signal":
                rec_act = str(lite_details.get("recommended_next_action") or "")
                sec_raw = str(lite_details.get("security_relevance") or "unknown").lower()
                try:
                    sec_rel = SecurityRelevance(sec_raw)
                except ValueError:
                    sec_rel = SecurityRelevance.unknown
            observations.append(Observation(
                observation_id=_make_obs_id(),
                campaign_id=campaign_id,
                tool_run_id=tool_run_id,
                task_id=task_id,
                command_id=command_id,
                source=source,
                type=lite.observation_type,
                operation_id=str(lite_details.get("operation_id", "") or ""),
                request_id=str(lite_details.get("request_id", "") or ""),
                auth_profile=str(lite_details.get("auth_profile", "") or ""),
                confidence=lite.confidence,
                security_relevance=(
                    sec_rel if str(lite.observation_type) == "injection_signal" else SecurityRelevance.unknown
                ),
                judge_worthy=False,
                recommended_next_action=rec_act,
                details=lite_details,
                created_at=_now_iso(),
            ))

        for obs in observations:
            memory_store.store_observation(
                obs.observation_id, campaign_id, tool_run_id,
                obs.model_dump(mode="json"),
            )

        return observations

    def _from_failed_result(
        self,
        result: ToolResult,
        tool_run_id: str,
        campaign_id: str,
        task_id: str,
        command_id: str,
        source: str,
    ) -> Observation | None:
        if not result.errors:
            return Observation(
                observation_id=_make_obs_id(),
                campaign_id=campaign_id,
                tool_run_id=tool_run_id,
                task_id=task_id,
                command_id=command_id,
                source=source,
                type="tool_error",
                confidence=0.0,
                security_relevance="informational",
                judge_worthy=False,
                recommended_next_action="store_only",
                details={"status": result.status},
                created_at=_now_iso(),
            )

        first_err = result.errors[0]
        if first_err.error_type == "timeout":
            return Observation(
                observation_id=_make_obs_id(),
                campaign_id=campaign_id,
                tool_run_id=tool_run_id,
                task_id=task_id,
                command_id=command_id,
                source=source,
                type="timeout_signal",
                confidence=0.0,
                security_relevance="informational",
                judge_worthy=False,
                recommended_next_action="store_only",
                details={"error_type": first_err.error_type, "message": first_err.message},
                created_at=_now_iso(),
            )

        if first_err.error_type == "adapter_not_available":
            return Observation(
                observation_id=_make_obs_id(),
                campaign_id=campaign_id,
                tool_run_id=tool_run_id,
                task_id=task_id,
                command_id=command_id,
                source=source,
                type="unsupported_tool_signal",
                confidence=0.0,
                security_relevance="informational",
                judge_worthy=False,
                recommended_next_action="store_only",
                details={"error_type": first_err.error_type, "message": first_err.message},
                created_at=_now_iso(),
            )

        return Observation(
            observation_id=_make_obs_id(),
            campaign_id=campaign_id,
            tool_run_id=tool_run_id,
            task_id=task_id,
            command_id=command_id,
            source=source,
            type="tool_error",
            confidence=0.0,
            security_relevance="informational",
            judge_worthy=False,
            recommended_next_action="store_only",
            details={"error_type": first_err.error_type, "message": first_err.message},
            created_at=_now_iso(),
        )
