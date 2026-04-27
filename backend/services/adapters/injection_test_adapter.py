"""Phase 17B-1 — bounded safe injection probe (metadata-only signals).

Baseline + allowlisted probes via query parameters. Observations use payload
labels only — never raw payloads, bodies, or headers.
"""
from __future__ import annotations

import re
import time
from typing import Any, Protocol, runtime_checkable

try:
    from backend.models.campaign import Campaign
    from backend.models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from backend.models.worker_command import WorkerCommand
    from backend.services.artifact_store import ArtifactStore
    from backend.services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.tool_run import (
        ToolResult,
        ToolResultError,
        ToolResultObservationLite,
        ToolResultRequest,
        ToolResultResponse,
        ToolResultSummary,
    )
    from models.worker_command import WorkerCommand
    from services.artifact_store import ArtifactStore
    from services.http.safe_http_client import SafeHttpClient, sanitize_url_for_storage


ALLOWED_PAYLOAD_FAMILIES: frozenset[str] = frozenset({
    "sql_like",
    "nosql_like",
    "template_marker",
    "path_traversal_marker",
    "xss_reflection_marker",
})

FAMILY_LABELS: dict[str, tuple[str, ...]] = {
    "sql_like": ("sql_quote_single", "sql_quote_double", "sql_or_true_marker"),
    "nosql_like": ("nosql_ne_null",),
    "template_marker": ("template_curly_7x7", "template_dollar_7x7"),
    "path_traversal_marker": ("traversal_dotdot", "traversal_encoded_dotdot"),
    "xss_reflection_marker": ("xss_marker_plain", "xss_marker_angle"),
}

_LABEL_TO_VALUE: dict[str, str] = {
    "sql_quote_single": "'",
    "sql_quote_double": '"',
    "sql_or_true_marker": "' OR '1'='1",
    "template_curly_7x7": "{{7*7}}",
    "template_dollar_7x7": "${7*7}",
    "traversal_dotdot": "../",
    "traversal_encoded_dotdot": "..%2f",
    "xss_marker_plain": "xss_probe_1337",
    "xss_marker_angle": "<xss_probe_1337>",
}

_STRONG_SIGNALS = frozenset({
    "db_error_pattern",
    "reflected_marker",
    "template_evaluation_marker",
    "traversal_marker",
    "nosql_operator_effect",
    "server_error_on_payload",
})

_DB_ERROR_PAT = re.compile(
    r"sql syntax|syntax error|sqlite|postgresql|mysql|mariadb|ora-\d|"
    r"odbc|unclosed quotation|quoted string not properly terminated",
    re.IGNORECASE,
)


def _size_bucket(byte_len: int) -> str:
    if byte_len < 500:
        return "small"
    if byte_len < 8000:
        return "medium"
    return "large"


def _text_for_detection(body: Any) -> str:
    if body is None:
        return ""
    if isinstance(body, (dict, list)):
        return ""
    return str(body)[:65536]


def _error_pattern_from_body(text: str) -> str:
    if _DB_ERROR_PAT.search(text):
        return "db_error"
    return "none"


def _marker_reflected(family: str, text: str) -> bool:
    if family != "xss_reflection_marker":
        return False
    return "xss_probe_1337" in text


def _classify_signals(
    *,
    baseline_status: int,
    attack_status: int,
    baseline_bucket: str,
    attack_bucket: str,
    marker_reflected: bool,
    error_pattern_class: str,
    family: str,
    label: str,
    attack_body_text: str,
) -> tuple[list[str], str]:
    signals: list[str] = []
    if 500 <= attack_status <= 599 and not (500 <= baseline_status <= 599):
        signals.append("server_error_on_payload")
    if marker_reflected:
        signals.append("reflected_marker")
    if error_pattern_class == "db_error":
        signals.append("db_error_pattern")
    if family == "template_marker" and "49" in attack_body_text:
        signals.append("template_evaluation_marker")
    if family == "path_traversal_marker":
        low = attack_body_text.lower()
        if "../" in low or "..%2f" in low or "path" in low or "directory" in low:
            signals.append("traversal_marker")
    if family == "nosql_like" and label == "nosql_ne_null":
        if attack_status != baseline_status or attack_bucket != baseline_bucket:
            signals.append("nosql_operator_effect")

    strong_here = [s for s in signals if s in _STRONG_SIGNALS]
    if not strong_here:
        if baseline_status != attack_status:
            signals.append("status_changed")
        if baseline_bucket != attack_bucket:
            signals.append("response_size_changed")

    if 500 <= attack_status <= 599 and not (500 <= baseline_status <= 599):
        response_delta = "new_5xx"
    elif baseline_status != attack_status:
        response_delta = "status_changed"
    elif baseline_bucket != attack_bucket:
        response_delta = "response_size_changed"
    else:
        response_delta = "unchanged"
    return signals, response_delta


@runtime_checkable
class InjectionHttpExecutor(Protocol):
    def get_with_query(
        self,
        campaign: Campaign,
        *,
        url: str,
        query: dict[str, str],
        timeout_sec: float,
    ) -> tuple[int, Any]:
        ...


class _SafeClientInjectionHttpExecutor:
    def __init__(self, http: SafeHttpClient) -> None:
        self._http = http

    def get_with_query(
        self,
        campaign: Campaign,
        *,
        url: str,
        query: dict[str, str],
        timeout_sec: float,
    ) -> tuple[int, Any]:
        res = self._http.request(
            campaign,
            method="GET",
            url=url,
            query=query or None,
            timeout_sec=timeout_sec,
            max_response_bytes=65536,
            follow_redirects=False,
        )
        if res.error is not None:
            return 0, ""
        return int(res.status_code or 0), res.response_body


class InjectionTestAdapter:
    """Safe injection MVP: at most one injection_signal observation per run."""

    def __init__(
        self,
        http_client: SafeHttpClient | None = None,
        *,
        http_executor: InjectionHttpExecutor | None = None,
        synthetic_outcomes: list[dict[str, Any]] | None = None,
    ) -> None:
        self._http = http_client or SafeHttpClient()
        self._http_executor = http_executor
        self._synthetic = synthetic_outcomes
        self._artifacts = ArtifactStore()

    def execute(
        self,
        command: WorkerCommand,
        campaign: Campaign,
        tool_run_id: str,
    ) -> ToolResult:
        t0 = int(time.monotonic() * 1000)

        def dur_ms() -> int:
            return int(time.monotonic() * 1000) - t0

        if (command.strategy or "").strip() != "injection_probe":
            return self._fail(
                command, tool_run_id, dur_ms(),
                "invalid_strategy", "injection_test requires strategy 'injection_probe'.",
            )
        op_id = (command.operation_id or "").strip()
        if not op_id:
            return self._fail(
                command, tool_run_id, dur_ms(),
                "operation_id_required", "operation_id is required for injection_test.",
            )

        inputs = command.inputs if isinstance(command.inputs, dict) else {}
        target_url = str(inputs.get("target_url") or "").strip()
        trusted = (campaign.target_url or "").rstrip("/")
        if target_url.rstrip("/") != trusted.rstrip("/"):
            return self._fail(
                command, tool_run_id, dur_ms(),
                "injection_target_url_mismatch",
                "inputs.target_url must equal campaign.target_url (ignoring trailing slash).",
            )

        max_req = max(1, min(int(command.budget.max_requests), 10))
        timeout_sec = float(max(1, min(int(command.budget.timeout_sec), 30)))
        timeout_sec = min(timeout_sec, float(campaign.limits.max_duration_sec))

        raw_families = inputs.get("payload_families")
        if isinstance(raw_families, list) and raw_families:
            families = [str(x).strip() for x in raw_families if str(x).strip()]
        else:
            families = list(ALLOWED_PAYLOAD_FAMILIES)
        unknown = [f for f in families if f not in ALLOWED_PAYLOAD_FAMILIES]
        if unknown:
            return self._fail(
                command, tool_run_id, dur_ms(),
                "unknown_payload_family",
                f"Unknown payload_families: {unknown}.",
            )

        mpp_raw = inputs.get("max_payloads_per_param", 1)
        try:
            max_payloads_per_param = int(mpp_raw)
        except (TypeError, ValueError):
            max_payloads_per_param = 1
        max_payloads_per_param = max(1, min(max_payloads_per_param, 2))

        param_name = "inj_probe"
        param_in = "query"
        json_object_ok = False
        raw_cands = inputs.get("parameter_candidates")
        if isinstance(raw_cands, list) and raw_cands:
            first = raw_cands[0]
            if isinstance(first, dict):
                pn = str(first.get("name") or "").strip()
                if pn:
                    param_name = pn
                pin = str(first.get("in") or "query").strip().lower()
                if pin in {"query", "path", "body"}:
                    param_in = pin
                json_object_ok = bool(first.get("json_object") is True)

        if self._synthetic is None and param_in != "query":
            return self._fail(
                command, tool_run_id, dur_ms(),
                "injection_param_in_unsupported",
                "MVP live execution supports query parameters only.",
            )

        probes: list[tuple[str, str]] = []
        skipped_payload_families: list[str] = []
        skipped_reasons: list[str] = []
        for fam in families:
            if fam == "nosql_like" and not json_object_ok:
                skipped_payload_families.append(fam)
                skipped_reasons.append("nosql_like_requires_json_object_parameter")
                continue
            if fam == "nosql_like" and self._synthetic is None:
                skipped_payload_families.append(fam)
                skipped_reasons.append("nosql_like_not_supported_for_live_get_query_mvp")
                continue
            labels = FAMILY_LABELS.get(fam, ())
            if not labels:
                skipped_payload_families.append(fam)
                skipped_reasons.append("payload_family_has_no_configured_labels")
                continue
            for lab in labels[:max_payloads_per_param]:
                probes.append((fam, lab))

        max_attacks = max(0, max_req - 1)
        probes = probes[:max_attacks]
        payload_families_used = sorted({fam for fam, _ in probes})
        parameters_tested = [param_name] if probes else []
        if not probes:
            art = self._summary_artifact(
                command,
                tool_run_id,
                operation_id=op_id,
                parameters_tested=parameters_tested,
                payload_families_used=payload_families_used,
                probes_attempted=0,
                signals_found=[],
                result="no_signal",
                skipped_payload_families=skipped_payload_families,
                skipped_reasons=skipped_reasons,
            )
            return ToolResult(
                tool_run_id=tool_run_id,
                campaign_id=command.campaign_id,
                task_id=command.task_id,
                command_id=command.command_id,
                tool_name=command.tool_name,
                status="finished",
                summary=ToolResultSummary(request_count=0, success_count=0, duration_ms=dur_ms()),
                observations=[],
                artifacts=[art],
            )

        if self._synthetic is not None:
            outcomes = [dict(self._synthetic[min(i, len(self._synthetic) - 1)]) for i in range(len(probes))]
        else:
            ex = self._http_executor or _SafeClientInjectionHttpExecutor(self._http)
            outcomes = self._run_live_query(
                campaign, target_url, ex, probes, param_name, timeout_sec,
            )

        if not outcomes:
            return self._fail(
                command, tool_run_id, dur_ms(),
                "baseline_http_failed",
                "No probe outcomes (baseline or attacks failed).",
            )

        merged_signals: list[str] = []
        best: dict[str, Any] | None = None

        for i, (fam, lab) in enumerate(probes):
            row = outcomes[i]
            b_stat = int(row["baseline_status"])
            a_stat = int(row["attack_status"])
            b_buck = str(row["baseline_size_bucket"])
            a_buck = str(row["attack_size_bucket"])
            mref = bool(row["marker_reflected"])
            err_cls = str(row["error_pattern_class"])
            body_text = str(row.get("_attack_body_text", ""))

            sigs, rdc = _classify_signals(
                baseline_status=b_stat,
                attack_status=a_stat,
                baseline_bucket=b_buck,
                attack_bucket=a_buck,
                marker_reflected=mref,
                error_pattern_class=err_cls,
                family=fam,
                label=lab,
                attack_body_text=body_text,
            )
            for s in sigs:
                if s not in merged_signals:
                    merged_signals.append(s)
            strong_here = [s for s in sigs if s in _STRONG_SIGNALS]
            if strong_here and best is None:
                best = {
                    "family": fam,
                    "label": lab,
                    "param_name": param_name,
                    "param_in": param_in,
                    "baseline_status": b_stat,
                    "attack_status": a_stat,
                    "response_delta_class": rdc,
                    "marker_reflected": mref,
                    "error_pattern_class": err_cls,
                }

        if not merged_signals:
            art = self._summary_artifact(
                command,
                tool_run_id,
                operation_id=op_id,
                parameters_tested=parameters_tested,
                payload_families_used=payload_families_used,
                probes_attempted=len(probes),
                signals_found=[],
                result="no_signal",
                skipped_payload_families=skipped_payload_families,
                skipped_reasons=skipped_reasons,
            )
            return ToolResult(
                tool_run_id=tool_run_id,
                campaign_id=command.campaign_id,
                task_id=command.task_id,
                command_id=command.command_id,
                tool_name=command.tool_name,
                status="finished",
                summary=ToolResultSummary(
                    request_count=1 + len(probes),
                    success_count=1 + len(probes),
                    duration_ms=dur_ms(),
                ),
                observations=[],
                artifacts=[art],
            )

        if best is None:
            row0 = outcomes[0]
            fam0, lab0 = probes[0]
            best = {
                "family": fam0,
                "label": lab0,
                "param_name": param_name,
                "param_in": param_in,
                "baseline_status": int(row0["baseline_status"]),
                "attack_status": int(row0["attack_status"]),
                "response_delta_class": str(row0["response_delta_class"]),
                "marker_reflected": bool(row0["marker_reflected"]),
                "error_pattern_class": str(row0["error_pattern_class"]),
            }

        strong_any = [s for s in merged_signals if s in _STRONG_SIGNALS]
        result_status = "partial" if strong_any else "finished"
        conf, sec_rel, next_act = self._confidence_tier(merged_signals, strong_any)

        details: dict[str, Any] = {
            "operation_id": op_id,
            "tool_name": "injection_test",
            "parameter_name": str(best["param_name"]),
            "parameter_location": str(best["param_in"]),
            "payload_family": str(best["family"]),
            "payload_label": str(best["label"]),
            "signal_types": merged_signals,
            "baseline_status": int(best["baseline_status"]),
            "attack_status": int(best["attack_status"]),
            "response_delta_class": str(best["response_delta_class"]),
            "marker_reflected": bool(best["marker_reflected"]),
            "error_pattern_class": str(best["error_pattern_class"]),
            "recommended_next_action": next_act,
            "security_relevance": sec_rel,
        }

        obs = ToolResultObservationLite(
            observation_type="injection_signal",
            confidence=conf,
            details=details,
        )

        req_count = 1 + len(probes)
        requests: list[ToolResultRequest] = []
        responses: list[ToolResultResponse] = []
        for idx in range(req_count):
            rid = f"req_inj_{tool_run_id[:8]}_{idx}"
            requests.append(ToolResultRequest(
                request_id=rid,
                role="",
                method="GET",
                url=sanitize_url_for_storage(target_url),
                path_template="",
            ))
            st = int(best["baseline_status"]) if idx == 0 else int(best["attack_status"])
            responses.append(ToolResultResponse(request_id=rid, status_code=st))
        art = self._summary_artifact(
            command,
            tool_run_id,
            operation_id=op_id,
            parameters_tested=parameters_tested,
            payload_families_used=payload_families_used,
            probes_attempted=len(probes),
            signals_found=merged_signals,
            result="signals_detected",
            skipped_payload_families=skipped_payload_families,
            skipped_reasons=skipped_reasons,
        )

        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status=result_status,
            summary=ToolResultSummary(
                request_count=req_count,
                success_count=req_count,
                duration_ms=dur_ms(),
            ),
            requests=requests,
            responses=responses,
            observations=[obs],
            artifacts=[art],
        )

    def _summary_artifact(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        *,
        operation_id: str,
        parameters_tested: list[str],
        payload_families_used: list[str],
        probes_attempted: int,
        signals_found: list[str],
        result: str,
        skipped_payload_families: list[str],
        skipped_reasons: list[str],
    ) -> Any:
        payload: dict[str, Any] = {
            "artifact_type": "injection_probe_summary",
            "operation_id": operation_id,
            "parameters_tested": [str(p) for p in parameters_tested if str(p).strip()],
            "payload_families_used": [str(f) for f in payload_families_used if str(f).strip()],
            "probes_attempted": max(0, int(probes_attempted)),
            "signals_found": [str(s) for s in signals_found if str(s).strip()],
            "result": "signals_detected" if result == "signals_detected" else "no_signal",
        }
        skipped_families = [str(f) for f in skipped_payload_families if str(f).strip()]
        skipped_reasons_norm = [str(r) for r in skipped_reasons if str(r).strip()]
        if skipped_families:
            payload["skipped_payload_families"] = sorted(set(skipped_families))
        if skipped_reasons_norm:
            payload["skipped_reasons"] = sorted(set(skipped_reasons_norm))
        return self._artifacts.save_artifact(
            campaign_id=command.campaign_id,
            tool_run_id=tool_run_id,
            artifact_type="injection_probe_summary",
            content=payload,
        )

    def _run_live_query(
        self,
        campaign: Campaign,
        target_url: str,
        executor: InjectionHttpExecutor,
        probes: list[tuple[str, str]],
        param_name: str,
        timeout_sec: float,
    ) -> list[dict[str, Any]]:
        b_stat, b_body = executor.get_with_query(
            campaign, url=target_url, query={}, timeout_sec=timeout_sec,
        )
        if b_stat <= 0:
            return []
        b_text = _text_for_detection(b_body)
        b_bucket = _size_bucket(len(b_text.encode("utf-8")) if b_text else 0)

        outcomes: list[dict[str, Any]] = []
        for fam, lab in probes:
            internal = _LABEL_TO_VALUE.get(lab)
            if internal is None:
                continue
            q = {param_name: str(internal)}
            a_stat, a_body = executor.get_with_query(
                campaign, url=target_url, query=q, timeout_sec=timeout_sec,
            )
            if a_stat <= 0:
                continue
            a_text = _text_for_detection(a_body)
            a_bucket = _size_bucket(len(a_text.encode("utf-8")) if a_text else 0)
            err_cls = _error_pattern_from_body(a_text)
            mref = _marker_reflected(fam, a_text)
            sigs, rdc = _classify_signals(
                baseline_status=b_stat,
                attack_status=a_stat,
                baseline_bucket=b_bucket,
                attack_bucket=a_bucket,
                marker_reflected=mref,
                error_pattern_class=err_cls,
                family=fam,
                label=lab,
                attack_body_text=a_text,
            )
            outcomes.append({
                "baseline_status": b_stat,
                "attack_status": a_stat,
                "baseline_size_bucket": b_bucket,
                "attack_size_bucket": a_bucket,
                "marker_reflected": mref,
                "error_pattern_class": err_cls,
                "response_delta_class": rdc,
                "_attack_body_text": "",
                "_signal_types": sigs,
            })
        return outcomes

    @staticmethod
    def _confidence_tier(
        merged_signals: list[str],
        strong_any: list[str],
    ) -> tuple[float, str, str]:
        tier_hi = {"db_error_pattern", "reflected_marker", "template_evaluation_marker",
                   "traversal_marker", "nosql_operator_effect"} & set(merged_signals)
        if tier_hi:
            return 0.75, "medium", "validate_injection_impact"
        if "server_error_on_payload" in merged_signals:
            return 0.6, "medium", "validate_injection_impact"
        return 0.35, "informational", "store_only"

    def _fail(
        self,
        command: WorkerCommand,
        tool_run_id: str,
        duration_ms: int,
        code: str,
        message: str,
    ) -> ToolResult:
        return ToolResult(
            tool_run_id=tool_run_id,
            campaign_id=command.campaign_id,
            task_id=command.task_id,
            command_id=command.command_id,
            tool_name=command.tool_name,
            status="failed",
            summary=ToolResultSummary(duration_ms=duration_ms),
            errors=[ToolResultError(error_type=code, message=message, recoverable=False)],
        )
