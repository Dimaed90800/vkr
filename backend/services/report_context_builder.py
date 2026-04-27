"""Phase Report-0 — deterministic backend ReportContext builder."""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
from typing import Any

try:
    from backend.models.campaign import Campaign
    from backend.models.report_context import (
        REPORT_CONTEXT_SCHEMA_VERSION,
        ReportCampaignContext,
        ReportContext,
        ReportDataQuality,
        ReportExecutiveSummary,
    )
    from backend.storage.memory_store import memory_store
except ModuleNotFoundError:  # pragma: no cover
    from models.campaign import Campaign
    from models.report_context import (
        REPORT_CONTEXT_SCHEMA_VERSION,
        ReportCampaignContext,
        ReportContext,
        ReportDataQuality,
        ReportExecutiveSummary,
    )
    from storage.memory_store import memory_store


_ALWAYS_LIMITATIONS = [
    "No destructive tests were performed.",
    "Raw request/response bodies, raw headers, cookies and secrets are not stored in the report context.",
    "Findings are created only through JudgeApply.",
    "Mass Assignment findings require runtime_effect_proven:true.",
    "BOLA/BFLA checks require role/object materialization and may be blocked without object_pairs.",
    "no_observations means no strong signal was detected within bounded checks, not proof of absence.",
]

_RECOMMENDATIONS_BY_CLASS = {
    "security_header_misconfiguration": "Set strict security headers server-side and validate them on all sensitive endpoints.",
    "cors_misconfiguration": "Restrict allowed origins and never combine wildcard origins with credentialed requests.",
    "cookie_flag_misconfiguration": "Set Secure, HttpOnly, and appropriate SameSite flags for session cookies.",
    "schema_contract_violation": "Align API behavior with schema contracts and reject malformed inputs deterministically.",
    "api_schema_contract_violation": "Align API behavior with schema contracts and reject malformed inputs deterministically.",
    "potential_mass_assignment": "Use explicit allow-lists for writable fields and enforce server-side field-level authorization.",
}

_IMPACT_BY_CLASS = {
    "security_header_misconfiguration": "Ослаблены клиентские защитные механизмы (например, от clickjacking и небезопасного content-sniffing), что повышает риск эксплуатации связанных уязвимостей.",
    "cors_misconfiguration": "При некорректной CORS-политике может возникнуть несанкционированное чтение данных в браузерном контексте авторизованного пользователя.",
    "cookie_flag_misconfiguration": "Сессионные cookie могут быть более подвержены перехвату или использованию в нежелательном контексте при отсутствии защитных флагов.",
    "schema_contract_violation": "Отклонение от контракта API может привести к непредсказуемой обработке входных данных и росту риска логических и валидационных дефектов.",
    "api_schema_contract_violation": "Отклонение от контракта API может привести к непредсказуемой обработке входных данных и росту риска логических и валидационных дефектов.",
    "potential_mass_assignment": "Неконтролируемая запись полей может позволить изменение чувствительных атрибутов объекта при наличии подходящего авторизованного контекста.",
}

_EXPLOITATION_SUMMARY_BY_CLASS = {
    "security_header_misconfiguration": "В рамках разрешённой тестовой среды можно подтвердить отсутствие или ослабление защитных заголовков на целевом endpoint.",
    "cors_misconfiguration": "В рамках разрешённой тестовой среды можно проверить, что CORS-доверие к Origin настроено слишком широко для credentialed-сценариев.",
    "cookie_flag_misconfiguration": "В рамках разрешённой тестовой среды можно подтвердить отсутствие обязательных защитных атрибутов сессионных cookie.",
    "schema_contract_violation": "В рамках разрешённой тестовой среды можно подтвердить отклонение фактического поведения API от OpenAPI-контракта.",
    "api_schema_contract_violation": "В рамках разрешённой тестовой среды можно подтвердить отклонение фактического поведения API от OpenAPI-контракта.",
    "potential_mass_assignment": "В рамках разрешённой тестовой среды можно проверить риск изменения чувствительных полей через разрешённый API-вызов.",
}

_NORMALIZED_OWASP_BY_CLASS = {
    "api_schema_contract_violation": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "schema_contract_violation": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "schema_mismatch": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "security_header_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cors_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cookie_flag_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cookie_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "potential_mass_assignment": "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
}

_SAFE_KEY_EXCEPTIONS = {
    "cookie_name_hash",
    "cookie_candidate_source",
    "cookie_flag_validator",
    "validated_cookie_flag_issue",
    "blocked_missing_seed_context",
    "api3_broken_object_property_level_authorization",
}

_DROP_KEY_PARTS = (
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "request_body",
    "response_body",
    "raw_body",
    "raw_headers",
    "headers",
    "payload",
)


class ReportContextBuilder:
    def build(
        self,
        campaign_id: str,
        runtime_state_snapshot: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        raw_campaign = memory_store.get_campaign(campaign_id)
        if raw_campaign is None:
            return None, "campaign_not_found"
        campaign = Campaign.model_validate(raw_campaign)

        runtime = runtime_state_snapshot if isinstance(runtime_state_snapshot, dict) else None
        runtime_attached = runtime is not None

        findings = memory_store.list_confirmed_findings_by_campaign(campaign_id)
        evidence = memory_store.list_evidence_packs_by_campaign(campaign_id)
        evidence_by_id = {
            str(item.get("evidence_id") or ""): item
            for item in evidence
            if isinstance(item, dict)
        }
        observations = memory_store.list_observations_by_campaign(campaign_id)
        verification_plans = memory_store.list_verification_plans_by_campaign(campaign_id)
        judge_decisions = memory_store.list_judge_decisions_by_campaign(campaign_id)
        tool_runs = memory_store.list_tool_runs_by_campaign(campaign_id)
        graph = memory_store.get_graph_for_campaign(campaign_id) or {}

        latest_decision_by_evidence: dict[str, dict[str, Any]] = {}
        for item in judge_decisions:
            evidence_id = str(item.get("evidence_id") or "")
            if evidence_id:
                latest_decision_by_evidence[evidence_id] = item

        confirmed_findings = self._build_confirmed_findings(
            findings=findings,
            evidence_by_id=evidence_by_id,
            latest_decision_by_evidence=latest_decision_by_evidence,
        )
        pending_verification = self._build_pending_verification(
            verification_plans=verification_plans,
            judge_decisions=judge_decisions,
            runtime=runtime,
        )
        blocked_checks = self._build_blocked_checks(runtime)
        ready_but_not_executed = self._build_ready_not_executed(runtime)
        tool_failures = self._build_tool_failures(runtime)
        worker_execution_summary = self._build_worker_execution_summary(runtime, findings)
        owasp_coverage = self._build_owasp_coverage(
            runtime=runtime,
            findings=confirmed_findings,
            observations=observations,
            evidence=evidence,
            blocked_checks=blocked_checks,
            ready_checks=ready_but_not_executed,
            graph=graph,
            tool_runs=tool_runs,
            worker_execution_summary=worker_execution_summary,
        )

        stopped_reason = "not_available"
        if runtime_attached:
            stopped_reason = str(runtime.get("stopped_reason") or "").strip() or "not_available"

        missing_sections: list[str] = []
        if not runtime_attached:
            missing_sections.append("runtime_state_snapshot")

        context = ReportContext(
            schema_version=REPORT_CONTEXT_SCHEMA_VERSION,
            campaign=ReportCampaignContext(
                campaign_id=campaign.campaign_id,
                target_url=campaign.target_url,
                openapi_url=campaign.openapi_url,
                profile=campaign.profile,
                started_at=campaign.created_at,
                finished_at=None,
                stopped_reason=stopped_reason,
            ),
            executive_summary=ReportExecutiveSummary(
                confirmed_findings_count=len(confirmed_findings),
                pending_verification_count=len(pending_verification),
                iterations_run=self._runtime_int_or_na(runtime, "iterations_run"),
                max_iterations=self._runtime_int_or_na(runtime, "max_iterations"),
                tool_failures_count=self._runtime_int_or_na(runtime, "tool_failures_count"),
            ),
            owasp_coverage=owasp_coverage,
            confirmed_findings=confirmed_findings,
            pending_verification=pending_verification,
            blocked_checks=blocked_checks,
            ready_but_not_executed=ready_but_not_executed,
            tool_failures=tool_failures,
            worker_execution_summary=worker_execution_summary,
            limitations=self._build_limitations(runtime_attached),
            recommendations_seed=self._build_recommendations_seed(findings, evidence),
            data_quality=ReportDataQuality(
                runtime_state_attached=runtime_attached,
                missing_sections=missing_sections,
            ),
        )
        sanitized = self._sanitize_recursive(context.model_dump(mode="json"))
        return sanitized, None

    @staticmethod
    def _runtime_int_or_na(runtime: dict[str, Any] | None, key: str) -> int | str:
        if runtime is None:
            return "not_available"
        raw = runtime.get(key)
        try:
            return int(raw)
        except Exception:
            return 0

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except Exception:
            return default

    def _build_confirmed_findings(
        self,
        *,
        findings: list[dict[str, Any]],
        evidence_by_id: dict[str, dict[str, Any]],
        latest_decision_by_evidence: dict[str, dict[str, Any]],
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        seen: set[str] = set()
        for item in findings:
            finding_id = str(item.get("finding_id") or "").strip()
            if not finding_id or finding_id in seen:
                continue
            seen.add(finding_id)
            evidence_id = str(item.get("evidence_id") or "").strip()
            ev = evidence_by_id.get(evidence_id) or {}
            decision = latest_decision_by_evidence.get(evidence_id) or {}
            replay_steps_count = self._safe_int(item.get("reproduction_pointer", {}).get("replay_steps_count", "0"))
            vulnerability_class = str(item.get("vulnerability_class") or "not_available")
            observation_type = self._detect_observation_type(ev)
            tool_name = str(ev.get("tool_name") or ev.get("source_tool") or "not_available")
            worker_kind = self._worker_kind_from_vulnerability_class(vulnerability_class)
            source_owasp = str(item.get("owasp_category") or "not_available")
            normalized_owasp = self._normalized_owasp_category(
                vulnerability_class=vulnerability_class,
                source_owasp_category=source_owasp,
                observation_type=observation_type,
            )
            category_normalized = normalized_owasp != source_owasp
            out.append({
                "finding_id": finding_id,
                "title": str(item.get("title") or item.get("summary") or "not_available"),
                "owasp_category": normalized_owasp,
                "source_owasp_category": source_owasp if category_normalized else source_owasp,
                "category_normalized": category_normalized,
                "vulnerability_class": vulnerability_class,
                "severity": str(item.get("severity") or "not_available"),
                "endpoint": str(item.get("endpoint") or "not_available"),
                "method": str(item.get("method") or "not_available"),
                "evidence_id": evidence_id or "not_available",
                "evidence_summary": str(ev.get("hypothesis") or "not_available"),
                "judge_verdict": str(decision.get("verdict") or "not_available"),
                "detection_chain": {
                    "worker_kind": worker_kind,
                    "tool_name": tool_name,
                    "observation_type": observation_type,
                    "evidence_id": evidence_id or "not_available",
                    "judge_verdict": str(decision.get("verdict") or "not_available"),
                    "vulnerability_class": vulnerability_class,
                },
                "safe_reproduction_steps": [
                    {
                        "step": 1,
                        "method": str(item.get("method") or "not_available"),
                        "endpoint": str(item.get("endpoint") or "not_available"),
                        "check": self._safe_reproduction_check_1(vulnerability_class),
                        "evidence_id": evidence_id or "not_available",
                    },
                    {
                        "step": 2,
                        "method": str(item.get("method") or "not_available"),
                        "endpoint": str(item.get("endpoint") or "not_available"),
                        "check": "Использовать Evidence ID для сопоставления с сохранёнными структурированными доказательствами. Не использовать raw tokens/cookies/request bodies из отчёта, так как они не сохраняются.",
                        "evidence_id": evidence_id or "not_available",
                    },
                ],
                "exploitation_summary": _EXPLOITATION_SUMMARY_BY_CLASS.get(
                    vulnerability_class,
                    "Авторизованный тестировщик может воспроизвести наблюдение в рамках разрешенного тестирования и подтвердить риск по evidence_id.",
                ),
                "impact_summary": _IMPACT_BY_CLASS.get(
                    vulnerability_class,
                    "Выявленная конфигурация или поведение может снизить уровень защищенности API и требует корректирующих мер.",
                ),
                "safe_reproduction_summary": (
                    f"{replay_steps_count} replay step(s) captured; use evidence_id reference."
                    if replay_steps_count > 0 else "not_available"
                ),
                "remediation_hint": _RECOMMENDATIONS_BY_CLASS.get(
                    vulnerability_class,
                    "Apply least-privilege controls and verify remediation with bounded replay checks.",
                ),
            })
        return out

    @staticmethod
    def _safe_reproduction_check_1(vulnerability_class: str) -> str:
        if vulnerability_class == "security_header_misconfiguration":
            return "В рамках разрешённой тестовой среды выполнить bounded-проверку для указанного endpoint и проверить response metadata на наличие/состояние security header."
        if vulnerability_class in {"schema_contract_violation", "api_schema_contract_violation"}:
            return "В рамках разрешённой тестовой среды повторить bounded contract check against OpenAPI и сравнить фактическое поведение с OpenAPI."
        return "В рамках разрешённой тестовой среды выполнить bounded-проверку для указанного endpoint и зафиксировать безопасные метаданные результата."

    @staticmethod
    def _normalized_owasp_category(
        *,
        vulnerability_class: str,
        source_owasp_category: str,
        observation_type: str,
    ) -> str:
        normalized = _NORMALIZED_OWASP_BY_CLASS.get(vulnerability_class)
        if normalized:
            return normalized
        obs_normalized = _NORMALIZED_OWASP_BY_CLASS.get(observation_type)
        if obs_normalized:
            return obs_normalized
        return source_owasp_category or "not_available"

    @staticmethod
    def _detect_observation_type(evidence: dict[str, Any]) -> str:
        mapping = {
            "validated_security_header_issue": "validated_security_header_issue",
            "validated_cors_issue": "validated_cors_issue",
            "validated_cookie_flag_issue": "validated_cookie_flag_issue",
            "schema_mismatch": "schema_mismatch",
            "mass_assignment_signal": "mass_assignment_signal",
        }
        derived = evidence.get("derived_signals") if isinstance(evidence.get("derived_signals"), list) else []
        for item in derived:
            text = str(item or "").strip().lower()
            for signal, observation in mapping.items():
                if signal in text:
                    return observation
        return str(evidence.get("observation_type") or "not_available")

    @staticmethod
    def _worker_kind_from_vulnerability_class(vulnerability_class: str) -> str:
        mapping = {
            "security_header_misconfiguration": "security_header_validator",
            "cors_misconfiguration": "cors_validator",
            "cookie_flag_misconfiguration": "cookie_flag_validator",
            "schema_contract_violation": "schemathesis_negative_test",
            "api_schema_contract_violation": "schemathesis_negative_test",
            "potential_mass_assignment": "property_mutation_test",
        }
        return mapping.get(vulnerability_class, "not_available")

    def _build_pending_verification(
        self,
        *,
        verification_plans: list[dict[str, Any]],
        judge_decisions: list[dict[str, Any]],
        runtime: dict[str, Any] | None,
    ) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for plan in verification_plans:
            status = str(plan.get("status") or "")
            if status not in {"pending", "in_progress"}:
                continue
            out.append({
                "source": "verification_plan",
                "verification_plan_id": str(plan.get("verification_plan_id") or ""),
                "status": status,
                "goal": str(plan.get("goal") or ""),
                "required_evidence": plan.get("required_evidence") if isinstance(plan.get("required_evidence"), list) else [],
            })
        for dec in judge_decisions:
            verdict = str(dec.get("verdict") or "")
            if verdict not in {"rework", "inconclusive", "rejected"}:
                continue
            out.append({
                "source": "judge_decision",
                "decision_id": str(dec.get("decision_id") or ""),
                "status": verdict,
                "reason": str(dec.get("reason") or ""),
                "evidence_id": str(dec.get("evidence_id") or ""),
            })
        if runtime is not None:
            for item in runtime.get("pending_summaries") or []:
                if isinstance(item, dict):
                    row = dict(item)
                    row["source"] = "runtime_state"
                    out.append(row)
        return out[:200]

    def _build_blocked_checks(self, runtime: dict[str, Any] | None) -> list[dict[str, Any]]:
        if runtime is None:
            return []
        out: list[dict[str, Any]] = []
        for item in runtime.get("blocked_candidates_sample") or []:
            if not isinstance(item, dict):
                continue
            out.append({
                "kind": str(item.get("kind") or ""),
                "reason": str(item.get("reason") or ""),
                "missing_inputs": item.get("missing_inputs") if isinstance(item.get("missing_inputs"), list) else [],
                "audit_flags": item.get("audit_flags") if isinstance(item.get("audit_flags"), list) else [],
                "operation_id": str(item.get("operation_id") or ""),
                "mass_assignment_candidate_result": str(item.get("mass_assignment_candidate_result") or ""),
                "fields_selected_count": self._safe_int(item.get("fields_selected_count"), 0),
                "seed_request_id_present": bool(item.get("seed_request_id_present")),
                "reason_codes": item.get("reason_codes") if isinstance(item.get("reason_codes"), list) else [],
            })
        return out[:50]

    def _build_ready_not_executed(self, runtime: dict[str, Any] | None) -> list[dict[str, Any]]:
        if runtime is None:
            return []
        out: list[dict[str, Any]] = []
        for item in runtime.get("ready_candidates_sample") or []:
            if not isinstance(item, dict):
                continue
            out.append({
                "kind": str(item.get("kind") or ""),
                "reason": str(item.get("reason") or ""),
                "operation_id": str(item.get("operation_id") or ""),
                "tool_name": str(item.get("tool_name") or ""),
                "worker_class": str(item.get("worker_class") or ""),
                "strategy": str(item.get("strategy") or ""),
                "cors_candidate_source": str(item.get("cors_candidate_source") or ""),
                "cookie_candidate_source": str(item.get("cookie_candidate_source") or ""),
                "cookie_name_hash": str(item.get("cookie_name_hash") or ""),
                "validation_mode": str(item.get("validation_mode") or ""),
                "audit_flags": item.get("audit_flags") if isinstance(item.get("audit_flags"), list) else [],
                "reason_codes": item.get("reason_codes") if isinstance(item.get("reason_codes"), list) else [],
            })
        return out[:50]

    def _build_tool_failures(self, runtime: dict[str, Any] | None) -> list[dict[str, Any]]:
        if runtime is None:
            return []
        out: list[dict[str, Any]] = []
        for item in runtime.get("tool_failure_summaries") or []:
            if not isinstance(item, dict):
                continue
            out.append({
                "candidate_kind": str(item.get("candidate_kind") or ""),
                "tool_name": str(item.get("tool_name") or ""),
                "tool_run_id": str(item.get("tool_run_id") or ""),
                "tool_result_status": str(item.get("tool_result_status") or ""),
                "tool_error_type": str(item.get("tool_error_type") or ""),
                "tool_error_safe_message": str(item.get("tool_error_safe_message") or ""),
            })
        return out[:50]

    def _build_worker_execution_summary(
        self,
        runtime: dict[str, Any] | None,
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        if runtime is None:
            return {"status": "not_available"}
        executed = runtime.get("executed_by_kind") if isinstance(runtime.get("executed_by_kind"), dict) else {}
        failed_by_kind = runtime.get("failed_by_kind") if isinstance(runtime.get("failed_by_kind"), dict) else {}
        blocked_by_kind = runtime.get("blocked_candidates_by_kind_count") if isinstance(runtime.get("blocked_candidates_by_kind_count"), dict) else {}
        ready_by_kind = runtime.get("ready_candidates_by_kind_count") if isinstance(runtime.get("ready_candidates_by_kind_count"), dict) else {}
        summaries = runtime.get("iteration_summaries") if isinstance(runtime.get("iteration_summaries"), list) else []

        finding_kinds = defaultdict(int)
        for item in findings:
            vc = str(item.get("vulnerability_class") or "")
            if vc == "security_header_misconfiguration":
                finding_kinds["security_header_validator"] += 1
            elif vc == "cors_misconfiguration":
                finding_kinds["cors_validator"] += 1
            elif vc == "cookie_flag_misconfiguration":
                finding_kinds["cookie_flag_validator"] += 1
            elif vc in {"api_schema_contract_violation", "schema_contract_violation"}:
                finding_kinds["schemathesis_negative_test"] += 1
            elif vc == "potential_mass_assignment":
                finding_kinds["property_mutation_test"] += 1

        per_kind: dict[str, Any] = {}
        keys = set(executed.keys()) | set(failed_by_kind.keys()) | set(ready_by_kind.keys()) | set(blocked_by_kind.keys())
        for key in keys:
            no_obs = 0
            pending = 0
            tool_failed = 0
            for row in summaries:
                if not isinstance(row, dict):
                    continue
                if str(row.get("candidate_kind") or "") != key:
                    continue
                if str(row.get("outcome") or "") == "no_observations":
                    no_obs += 1
                if str(row.get("outcome") or "") == "pending_verification":
                    pending += 1
                if str(row.get("outcome") or "") == "tool_failed":
                    tool_failed += 1
            per_kind[key] = {
                "executed": self._safe_int(executed.get(key), 0),
                "findings_created": self._safe_int(finding_kinds.get(key), 0),
                "no_observations": no_obs,
                "pending_verification": pending,
                "tool_failed": max(tool_failed, self._safe_int(failed_by_kind.get(key), 0)),
                "blocked": self._safe_int(blocked_by_kind.get(key), 0),
                "ready": self._safe_int(ready_by_kind.get(key), 0),
            }
        return {
            "executed_by_kind": deepcopy(executed),
            "failed_by_kind": deepcopy(failed_by_kind),
            "per_kind": per_kind,
        }

    def _build_owasp_coverage(
        self,
        *,
        runtime: dict[str, Any] | None,
        findings: list[dict[str, Any]],
        observations: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
        blocked_checks: list[dict[str, Any]],
        ready_checks: list[dict[str, Any]],
        graph: dict[str, Any],
        tool_runs: list[dict[str, Any]],
        worker_execution_summary: dict[str, Any],
    ) -> dict[str, Any]:
        executed = runtime.get("executed_by_kind") if isinstance(runtime, dict) and isinstance(runtime.get("executed_by_kind"), dict) else {}
        ready_map = runtime.get("ready_candidates_by_kind_count") if isinstance(runtime, dict) and isinstance(runtime.get("ready_candidates_by_kind_count"), dict) else {}
        blocked_map = runtime.get("blocked_candidates_by_kind_count") if isinstance(runtime, dict) and isinstance(runtime.get("blocked_candidates_by_kind_count"), dict) else {}

        findings_api8 = sum(1 for f in findings if str(f.get("owasp_category") or "") == "API8_SECURITY_MISCONFIGURATION")
        findings_api9 = sum(1 for f in findings if str(f.get("owasp_category") or "") == "API9_IMPROPER_INVENTORY_MANAGEMENT")
        findings_api3 = sum(1 for f in findings if str(f.get("owasp_category") or "") == "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION")

        schema_mismatch_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "schema_mismatch")
        mass_assignment_signal_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "mass_assignment_signal")
        runtime_effect_proven_count = 0
        for ev in evidence:
            derived = ev.get("derived_signals") if isinstance(ev.get("derived_signals"), list) else []
            if any(str(x).strip().lower() == "runtime_effect_proven:true" for x in derived):
                runtime_effect_proven_count += 1

        blocked_no_sensitive = 0
        blocked_missing_seed = 0
        for item in blocked_checks:
            reason = str(item.get("mass_assignment_candidate_result") or "")
            if reason == "blocked_no_sensitive_fields":
                blocked_no_sensitive += 1
            if reason == "blocked_missing_seed_context":
                blocked_missing_seed += 1
            reason_codes = item.get("reason_codes") if isinstance(item.get("reason_codes"), list) else []
            if "blocked_no_sensitive_fields" in reason_codes:
                blocked_no_sensitive += 1
            if "blocked_missing_seed_context" in reason_codes:
                blocked_missing_seed += 1

        no_obs_by_kind = self._no_observations_by_kind(runtime)
        operations_total = self._safe_int(graph.get("operations_count"), -1)
        if operations_total < 0:
            operations_total = len(graph.get("operations") or []) if isinstance(graph.get("operations"), list) else "not_available"
        operations_tested = self._operations_tested(tool_runs)

        api8_workers = ["security_header_validator", "cors_validator", "cookie_flag_validator"]
        api8_worker_map = {}
        for key in api8_workers:
            ex = self._safe_int(executed.get(key), 0)
            rd = self._safe_int(ready_map.get(key), 0)
            api8_worker_map[key] = {
                "executed": ex if runtime is not None else "not_available",
                "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get(key, {}).get("findings_created", 0),
                ),
                "no_observations": no_obs_by_kind.get(key, "not_available" if runtime is None else 0),
                "ready": rd if runtime is not None else "not_available",
                "blocked": self._safe_int(blocked_map.get(key), 0) if runtime is not None else "not_available",
                "status": (
                    "checked" if ex > 0 else
                    ("pending" if rd > 0 else "not_available")
                ) if runtime is not None else "not_available",
            }

        api9_ex = self._safe_int(executed.get("schemathesis_negative_test"), 0)
        api9_ready = self._safe_int(ready_map.get("schemathesis_negative_test"), 0)
        api3_ex = self._safe_int(executed.get("property_mutation_test"), 0)
        api3_ready = self._safe_int(ready_map.get("property_mutation_test"), 0)
        api3_blocked_total = self._safe_int(blocked_map.get("property_mutation_test"), 0) if runtime is not None else "not_available"

        return {
            "API8_SECURITY_MISCONFIGURATION": {
                "status": "checked" if (runtime is not None and sum(self._safe_int(executed.get(k), 0) for k in api8_workers) > 0) else ("not_available" if runtime is None else "pending"),
                "workers": api8_worker_map,
                "confirmed_findings_count": findings_api8,
                "no_observations_count": (
                    sum(v for v in no_obs_by_kind.values() if isinstance(v, int))
                    if runtime is not None else "not_available"
                ),
                "blocked_count": (
                    sum(self._safe_int(blocked_map.get(k), 0) for k in api8_workers)
                    if runtime is not None else "not_available"
                ),
            },
            "API9_IMPROPER_INVENTORY_MANAGEMENT": {
                "status": (
                    "checked" if (runtime is not None and api9_ex > 0) else
                    ("pending" if (runtime is not None and api9_ready > 0) else "not_available")
                ),
                "workers": {
                    "schemathesis_negative_test": {
                        "executed": api9_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("schemathesis_negative_test", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("schemathesis_negative_test", "not_available" if runtime is None else 0),
                        "ready": api9_ready if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("schemathesis_negative_test"), 0) if runtime is not None else "not_available",
                    },
                },
                "confirmed_findings_count": findings_api9,
                "schema_mismatch_count": schema_mismatch_count,
                "contract_coverage": {
                    "operations_total": operations_total,
                    "operations_tested": operations_tested,
                },
            },
            "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION": {
                "status": "checked" if runtime_effect_proven_count > 0 else "diagnostic",
                "workers": {
                    "property_mutation_test": {
                        "executed": api3_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("property_mutation_test", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("property_mutation_test", "not_available" if runtime is None else 0),
                        "ready": api3_ready if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("property_mutation_test"), 0) if runtime is not None else "not_available",
                    },
                },
                "mass_assignment_signal_count": mass_assignment_signal_count,
                "candidates_considered": (
                    api3_ex + api3_ready + (api3_blocked_total if isinstance(api3_blocked_total, int) else 0)
                    if runtime is not None else "not_available"
                ),
                "blocked_no_sensitive_fields_count": blocked_no_sensitive if runtime is not None else "not_available",
                "blocked_missing_seed_context_count": blocked_missing_seed if runtime is not None else "not_available",
                "runtime_effect_proven_count": runtime_effect_proven_count,
                "confirmed_findings_count": findings_api3,
            },
        }

    def _no_observations_by_kind(self, runtime: dict[str, Any] | None) -> dict[str, Any]:
        if runtime is None:
            return {}
        out: dict[str, int] = defaultdict(int)
        for item in runtime.get("iteration_summaries") or []:
            if not isinstance(item, dict):
                continue
            if str(item.get("outcome") or "") != "no_observations":
                continue
            kind = str(item.get("candidate_kind") or "").strip()
            if kind:
                out[kind] += 1
        return dict(out)

    def _operations_tested(self, tool_runs: list[dict[str, Any]]) -> int | str:
        tested: set[str] = set()
        for run in tool_runs:
            command_id = str(run.get("command_id") or "")
            if not command_id:
                continue
            command = memory_store.get_command(command_id) or {}
            op = str(command.get("operation_id") or "").strip()
            if op:
                tested.add(op)
        return len(tested) if tested else "not_available"

    def _build_limitations(self, runtime_attached: bool) -> list[str]:
        out = list(_ALWAYS_LIMITATIONS)
        if not runtime_attached:
            out.append("Runtime loop telemetry was not attached.")
        return out

    def _build_recommendations_seed(
        self,
        findings: list[dict[str, Any]],
        evidence: list[dict[str, Any]],
    ) -> list[dict[str, str]]:
        classes: set[str] = set()
        for item in findings:
            cls = str(item.get("vulnerability_class") or "").strip()
            if cls:
                classes.add(cls)
        for item in evidence:
            cls = str(item.get("vulnerability_class") or "").strip()
            if cls:
                classes.add(cls)
        # Always include MVP classes
        classes.update({
            "security_header_misconfiguration",
            "cors_misconfiguration",
            "cookie_flag_misconfiguration",
            "api_schema_contract_violation",
            "potential_mass_assignment",
        })
        out: list[dict[str, str]] = []
        for cls in sorted(classes):
            hint = _RECOMMENDATIONS_BY_CLASS.get(cls)
            if not hint:
                continue
            out.append({
                "vulnerability_class": cls,
                "recommendation": hint,
            })
        return out

    def _sanitize_recursive(self, value: Any) -> Any:
        if isinstance(value, dict):
            out: dict[str, Any] = {}
            for key, item in value.items():
                key_str = str(key)
                if self._should_drop_key(key_str):
                    continue
                out[key_str] = self._sanitize_recursive(item)
            return out
        if isinstance(value, list):
            return [self._sanitize_recursive(item) for item in value]
        if isinstance(value, str):
            return self._sanitize_string(value)
        return value

    def _should_drop_key(self, key: str) -> bool:
        norm = key.strip().lower()
        if norm in _SAFE_KEY_EXCEPTIONS:
            return False
        if any(part in norm for part in _DROP_KEY_PARTS):
            return True
        return False

    @staticmethod
    def _sanitize_string(value: str) -> str:
        lowered = value.lower()
        patterns = ("bearer ", "token=", "authorization:", "set-cookie:")
        if any(pat in lowered for pat in patterns):
            return "[redacted]"
        return value
