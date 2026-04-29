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
    from backend.services.auth_profile_store import AuthProfileStore
    from backend.services.ssrf_evidence_reconciliation_service import reconcile_and_build_ssrf_evidence_for_campaign
    from backend.services.ssrf_callback_store import get_effective_ssrf_callback_state
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
    from services.auth_profile_store import AuthProfileStore
    from services.ssrf_evidence_reconciliation_service import reconcile_and_build_ssrf_evidence_for_campaign
    from services.ssrf_callback_store import get_effective_ssrf_callback_state
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
    "undocumented_api_endpoint": "Synchronize runtime-discovered endpoints with the OpenAPI inventory and retire or protect undocumented routes.",
    "ssrf_candidate": "Review URL-like request fields, constrain outbound destinations, and add allow-lists or egress controls before enabling any server-side fetch behavior.",
    "schema_contract_violation": "Align API behavior with schema contracts and reject malformed inputs deterministically.",
    "api_schema_contract_violation": "Align API behavior with schema contracts and reject malformed inputs deterministically.",
    "potential_mass_assignment": "Use explicit allow-lists for writable fields and enforce server-side field-level authorization.",
}

_IMPACT_BY_CLASS = {
    "security_header_misconfiguration": "Ослаблены клиентские защитные механизмы (например, от clickjacking и небезопасного content-sniffing), что повышает риск эксплуатации связанных уязвимостей.",
    "cors_misconfiguration": "При некорректной CORS-политике может возникнуть несанкционированное чтение данных в браузерном контексте авторизованного пользователя.",
    "cookie_flag_misconfiguration": "Сессионные cookie могут быть более подвержены перехвату или использованию в нежелательном контексте при отсутствии защитных флагов.",
    "undocumented_api_endpoint": "Неописанный endpoint усложняет контроль поверхности атаки и может обходить ожидаемые процессы тестирования, авторизации и инвентаризации.",
    "ssrf_candidate": "URL-подобные входные поля могут стать SSRF-риском, если сервер использует их для исходящих запросов без строгой валидации и сетевых ограничений.",
    "schema_contract_violation": "Отклонение от контракта API может привести к непредсказуемой обработке входных данных и росту риска логических и валидационных дефектов.",
    "api_schema_contract_violation": "Отклонение от контракта API может привести к непредсказуемой обработке входных данных и росту риска логических и валидационных дефектов.",
    "potential_mass_assignment": "Неконтролируемая запись полей может позволить изменение чувствительных атрибутов объекта при наличии подходящего авторизованного контекста.",
}

_EXPLOITATION_SUMMARY_BY_CLASS = {
    "security_header_misconfiguration": "В рамках разрешённой тестовой среды можно подтвердить отсутствие или ослабление защитных заголовков на целевом endpoint.",
    "cors_misconfiguration": "В рамках разрешённой тестовой среды можно проверить, что CORS-доверие к Origin настроено слишком широко для credentialed-сценариев.",
    "cookie_flag_misconfiguration": "В рамках разрешённой тестовой среды можно подтвердить отсутствие обязательных защитных атрибутов сессионных cookie.",
    "undocumented_api_endpoint": "В рамках разрешённой тестовой среды можно подтвердить, что runtime-обнаруженный endpoint отвечает и отсутствует в OpenAPI-инвентаре.",
    "ssrf_candidate": "На данном этапе подтвержден только диагностический признак SSRF-кандидата по OpenAPI-схеме; активные SSRF-проверки не выполнялись.",
    "schema_contract_violation": "В рамках разрешённой тестовой среды можно подтвердить отклонение фактического поведения API от OpenAPI-контракта.",
    "api_schema_contract_violation": "В рамках разрешённой тестовой среды можно подтвердить отклонение фактического поведения API от OpenAPI-контракта.",
    "potential_mass_assignment": "В рамках разрешённой тестовой среды можно проверить риск изменения чувствительных полей через разрешённый API-вызов.",
}

_NORMALIZED_OWASP_BY_CLASS = {
    "api_schema_contract_violation": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "schema_contract_violation": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "schema_mismatch": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "undocumented_api_endpoint": "API9_IMPROPER_INVENTORY_MANAGEMENT",
    "security_header_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cors_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cookie_flag_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "cookie_misconfiguration": "API8_SECURITY_MISCONFIGURATION",
    "potential_mass_assignment": "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION",
    "ssrf_candidate": "API7_SERVER_SIDE_REQUEST_FORGERY",
}

_STATIC_RESOURCE_MARKERS = (
    "/static/",
    "/images/",
    ".css",
    ".js",
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".svg",
    ".map",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
)

_SAFE_KEY_EXCEPTIONS = {
    "cookie_name_hash",
    "cookie_candidate_source",
    "cookie_flag_validator",
    "validated_cookie_flag_issue",
    "blocked_missing_seed_context",
    "api3_broken_object_property_level_authorization",
    "api1_broken_object_level_authorization",
    # Aggregate count name contains "token" but is not a secret field.
    "token_response_candidate_count",
    "token_response_detected",
    "token_ref",
    "token_field_path",
    "auth_profile_id",
    "owner_auth_profile_id",
    "attacker_auth_profile_id",
    "credential_ref",
    "payload_synthesis_result",
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
    "object_id",
    "raw_object",
)

_SSRF_POSITIVE_HINTS = (
    "api", "endpoint", "callback", "webhook", "url", "uri", "contact", "notify",
    "target", "destination", "service", "request", "report", "mechanic", "integration", "connect",
)

_SSRF_NEGATIVE_HINTS = (
    "product", "image", "video", "file", "upload", "media", "avatar", "logo", "picture",
)


class ReportContextBuilder:
    def __init__(self) -> None:
        self._auth_profiles = AuthProfileStore()

    def build(
        self,
        campaign_id: str,
        runtime_state_snapshot: dict[str, Any] | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        try:
            reconcile_and_build_ssrf_evidence_for_campaign(campaign_id)
        except Exception:
            pass
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
        finding_groups = self._build_finding_groups(confirmed_findings)
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
        auth_flow_diagnostics = self._build_auth_flow_diagnostics(campaign_id, observations)
        adaptive_planner_diagnostics = self._build_adaptive_planner_diagnostics(runtime)
        compact_attempt_summary = self._build_compact_attempt_summary(
            runtime=runtime,
            observations=observations,
        )
        last_observation_summary = self._build_last_observation_summary(observations)

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
            finding_groups=finding_groups,
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
            auth_flow_diagnostics=auth_flow_diagnostics,
            adaptive_planner_diagnostics=adaptive_planner_diagnostics,
            compact_attempt_summary=compact_attempt_summary,
            last_observation_summary=last_observation_summary,
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
            endpoint = self._resolve_report_endpoint(item=item, evidence=ev)
            title = str(item.get("title") or item.get("summary") or "not_available")
            resource_context = self._resource_context(endpoint, vulnerability_class)
            group_key = self._finding_group_key(
                vulnerability_class=vulnerability_class,
                title=title,
                evidence=ev,
            )
            out.append({
                "finding_id": finding_id,
                "title": title,
                "owasp_category": normalized_owasp,
                "source_owasp_category": source_owasp if category_normalized else source_owasp,
                "category_normalized": category_normalized,
                "vulnerability_class": vulnerability_class,
                "severity": str(item.get("severity") or "not_available"),
                "endpoint": endpoint,
                "method": str(item.get("method") or "not_available"),
                "evidence_id": evidence_id or "not_available",
                "evidence_summary": str(ev.get("hypothesis") or "not_available"),
                "judge_verdict": str(decision.get("verdict") or "not_available"),
                "resource_context": resource_context,
                "finding_group_key": group_key,
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
                        "endpoint": endpoint,
                        "check": self._safe_reproduction_check_1(vulnerability_class),
                        "evidence_id": evidence_id or "not_available",
                    },
                    {
                        "step": 2,
                        "method": str(item.get("method") or "not_available"),
                        "endpoint": endpoint,
                        "check": self._safe_reproduction_check_2(vulnerability_class),
                        "evidence_id": evidence_id or "not_available",
                    },
                    {
                        "step": 3,
                        "method": str(item.get("method") or "not_available"),
                        "endpoint": endpoint,
                        "check": f"Использовать Evidence ID {evidence_id or 'не доступно'} для сопоставления с сохранёнными структурированными доказательствами.",
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
                    f"{replay_steps_count} шаг(ов) воспроизведения сохранено; используйте ссылку на Evidence ID."
                    if replay_steps_count > 0 else "не доступно"
                ),
                "remediation_hint": _RECOMMENDATIONS_BY_CLASS.get(
                    vulnerability_class,
                    "Apply least-privilege controls and verify remediation with bounded replay checks.",
                ),
            })
        group_map: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in out:
            group_key = str(row.get("finding_group_key") or "").strip()
            if group_key:
                group_map[group_key].append(row)
        for row in out:
            group_key = str(row.get("finding_group_key") or "").strip()
            peers = group_map.get(group_key) or []
            similar_count = len(peers)
            row["similar_finding_hint"] = {
                "enabled": similar_count > 1,
                "group_title": str(row.get("title") or "not_available"),
            }
            row["similar_findings_count"] = similar_count
            row["similar_affected_endpoints"] = sorted(
                {
                    str(peer.get("endpoint") or "")
                    for peer in peers
                    if str(peer.get("endpoint") or "").strip()
                }
            )[:20]
        return out

    @staticmethod
    def _safe_reproduction_check_1(vulnerability_class: str) -> str:
        if vulnerability_class == "security_header_misconfiguration":
            return "В рамках разрешённой тестовой среды выполнить ограниченную проверку указанного endpoint."
        if vulnerability_class in {"schema_contract_violation", "api_schema_contract_violation"}:
            return "В рамках разрешённой тестовой среды повторить ограниченную проверку контракта по OpenAPI для указанной операции."
        return "В рамках разрешённой тестовой среды выполнить ограниченную проверку указанного endpoint и зафиксировать безопасные метаданные результата."

    @staticmethod
    def _safe_reproduction_check_2(vulnerability_class: str) -> str:
        if vulnerability_class == "security_header_misconfiguration":
            return "Проверить метаданные ответа на наличие и состояние требуемого заголовка безопасности."
        if vulnerability_class in {"schema_contract_violation", "api_schema_contract_violation"}:
            return "Сравнить фактическое поведение API с ожидаемым поведением, описанным в OpenAPI."
        return "Зафиксировать результат проверки без использования сырых токенов, cookie, тел запросов и ответов."

    @staticmethod
    def _resolve_report_endpoint(*, item: dict[str, Any], evidence: dict[str, Any]) -> str:
        raw_endpoint = str(item.get("endpoint") or "").strip()
        if raw_endpoint and raw_endpoint.lower() != "not_available":
            return raw_endpoint
        candidates: list[str] = []
        endpoint = str(evidence.get("endpoint") or "").strip()
        if endpoint:
            candidates.append(endpoint)
        attack = evidence.get("attack") if isinstance(evidence.get("attack"), dict) else {}
        request_ref = attack.get("request_ref") if isinstance(attack.get("request_ref"), dict) else {}
        for key in ("path_template", "path", "url"):
            value = str(request_ref.get(key) or "").strip()
            if value:
                candidates.append(value)
        for step in evidence.get("replay_steps") or []:
            if not isinstance(step, dict):
                continue
            for key in ("path_template", "path", "url"):
                value = str(step.get(key) or "").strip()
                if value:
                    candidates.append(value)
        for signal in evidence.get("derived_signals") or []:
            text = str(signal or "").strip()
            low = text.lower()
            for prefix in ("endpoint:", "path:", "url:"):
                if low.startswith(prefix):
                    value = text.split(":", 1)[1].strip()
                    if value:
                        candidates.append(value)
        for cand in candidates:
            if cand:
                return cand
        return "не доступно"

    def _build_finding_groups(self, confirmed_findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for row in confirmed_findings:
            key = str(row.get("finding_group_key") or "").strip()
            if key:
                grouped[key].append(row)
        out: list[dict[str, Any]] = []
        for group_key, rows in grouped.items():
            first = rows[0]
            severities = [str(x.get("severity") or "").strip() for x in rows if str(x.get("severity") or "").strip()]
            out.append(
                {
                    "group_key": group_key,
                    "group_title": str(first.get("title") or "не доступно"),
                    "vulnerability_class": str(first.get("vulnerability_class") or "не доступно"),
                    "owasp_category": str(first.get("owasp_category") or "не доступно"),
                    "affected_endpoints": sorted({str(x.get("endpoint") or "").strip() for x in rows if str(x.get("endpoint") or "").strip()})[:50],
                    "finding_ids": sorted({str(x.get("finding_id") or "").strip() for x in rows if str(x.get("finding_id") or "").strip()})[:50],
                    "evidence_ids": sorted({str(x.get("evidence_id") or "").strip() for x in rows if str(x.get("evidence_id") or "").strip()})[:50],
                    "severity": max(severities) if severities else "не доступно",
                    "severity_max": max(severities) if severities else "не доступно",
                    "count": len(rows),
                }
            )
        return sorted(out, key=lambda x: str(x.get("group_key") or ""))

    @staticmethod
    def _resource_context(endpoint: str, vulnerability_class: str) -> dict[str, Any]:
        ep = str(endpoint or "").strip()
        lower = ep.lower()
        is_static = any(marker in lower for marker in _STATIC_RESOURCE_MARKERS)
        resource_type = "static_asset" if is_static else ("api_endpoint" if ep and ep != "not_available" else "unknown")
        impact_note = "Стандартный контекст API endpoint."
        if is_static:
            impact_note = "Контекст статического ресурса; влияние может отличаться от бизнес-API и требует отдельной приоритизации."
        if is_static and vulnerability_class == "security_header_misconfiguration":
            impact_note = (
                "Находка относится к статическому или служебному ресурсу; влияние обычно ниже, чем для бизнес-API, "
                "но заголовки безопасности рекомендуется применять централизованно."
            )
        return {
            "is_static_asset": is_static,
            "resource_type": resource_type,
            "impact_note": impact_note,
        }

    @staticmethod
    def _finding_group_key(
        *,
        vulnerability_class: str,
        title: str,
        evidence: dict[str, Any],
    ) -> str:
        if vulnerability_class != "security_header_misconfiguration":
            return f"{vulnerability_class}:{title or 'not_available'}"
        header_name = str(evidence.get("header_name") or "").strip()
        if not header_name:
            derived = evidence.get("derived_signals") if isinstance(evidence.get("derived_signals"), list) else []
            for item in derived:
                text = str(item or "")
                if text.lower().startswith("header_name:"):
                    header_name = text.split(":", 1)[1].strip()
                    break
        key_tail = header_name or title or "not_available"
        return f"security_header_misconfiguration:{key_tail}"

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
            "undocumented_endpoint_signal": "undocumented_endpoint_signal",
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
            "undocumented_api_endpoint": "undocumented_endpoint_validator",
            "schema_contract_violation": "schemathesis_negative_test",
            "api_schema_contract_violation": "schemathesis_negative_test",
            "potential_mass_assignment": "property_mutation_test",
            "sensitive_property_exposure": "data_exposure_validator",
            "ssrf_candidate": "ssrf_candidate_detector",
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
            error_type = str(item.get("tool_error_type") or item.get("error_type") or "not_available")
            safe_message = str(item.get("tool_error_safe_message") or item.get("message") or "not_available")
            out.append({
                "candidate_kind": str(item.get("candidate_kind") or ""),
                "tool_name": str(item.get("tool_name") or ""),
                "tool_run_id": str(item.get("tool_run_id") or ""),
                "status": str(item.get("tool_result_status") or item.get("status") or ""),
                "iteration_index": self._safe_int(item.get("iteration_index"), 0),
                "error_type": error_type,
                "safe_message": safe_message,
            })
        return out[:50]

    def _build_compact_attempt_summary(
        self,
        *,
        runtime: dict[str, Any] | None,
        observations: list[dict[str, Any]],
        limit: int = 12,
    ) -> list[dict[str, Any]]:
        finding_by_tool_run_id: dict[str, bool] = {}
        if runtime is not None:
            for row in runtime.get("iteration_summaries") or []:
                if not isinstance(row, dict):
                    continue
                tool_run_id = str(row.get("tool_run_id") or "").strip()
                if tool_run_id and str(row.get("finding_id") or "").strip():
                    finding_by_tool_run_id[tool_run_id] = True

        out: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()

        def _push(row: dict[str, Any]) -> None:
            key = (
                str(row.get("kind") or ""),
                str(row.get("operation_id") or ""),
                str(row.get("field_path") or row.get("object_pair_id") or ""),
                str(row.get("dedup_key") or ""),
            )
            if key in seen:
                return
            seen.add(key)
            out.append(row)

        for raw in reversed(observations):
            if not isinstance(raw, dict):
                continue
            otype = str(raw.get("type") or raw.get("observation_type") or "").strip()
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            tool_run_id = str(raw.get("tool_run_id") or "").strip()
            if otype == "ssrf_probe_result":
                operation_id = str(det.get("operation_id") or raw.get("operation_id") or "").strip()
                field_path = str(det.get("field_path") or "").strip()
                auth_mode = str(det.get("auth_mode") or "").strip()
                result = str(det.get("result") or "").strip()
                status_code = self._safe_int(det.get("target_status_code") or det.get("status_code") or raw.get("status_code"), 0)
                effective = get_effective_ssrf_callback_state({"details": det})
                dedup_key = f"ssrf_probe|{operation_id}|{field_path}|{auth_mode}"
                _push({
                    "kind": "ssrf_probe",
                    "operation_id": operation_id,
                    "field_path": field_path,
                    "object_pair_id": "",
                    "auth_mode": auth_mode,
                    "result": result,
                    "status_code": status_code,
                    "callback_received": bool(effective.get("callback_received_effective")),
                    "access_granted": False,
                    "owner_baseline_valid": False,
                    "evidence_strength": str(det.get("evidence_strength") or ""),
                    "created_finding": bool(finding_by_tool_run_id.get(tool_run_id)),
                    "dedup_key": dedup_key,
                })
            elif otype == "bola_replay_result" and str(det.get("validation_mode") or "").strip() == "bola_replay":
                operation_id = str(det.get("target_operation_id") or raw.get("operation_id") or "").strip()
                object_pair_id = str(det.get("object_pair_id") or "").strip()
                attacker_auth = str(det.get("attacker_auth_profile_id") or "").strip()
                auth_mode = "authenticated" if attacker_auth else ""
                result = str(det.get("result") or det.get("replay_classification") or "").strip()
                status_code = self._safe_int(det.get("status_code") or det.get("attacker_status_code") or raw.get("status_code"), 0)
                dedup_key = f"bola_replay_probe|{operation_id}|{object_pair_id}|{attacker_auth}"
                _push({
                    "kind": "bola_replay_probe",
                    "operation_id": operation_id,
                    "field_path": "",
                    "object_pair_id": object_pair_id,
                    "auth_mode": auth_mode,
                    "result": result,
                    "status_code": status_code,
                    "callback_received": False,
                    "access_granted": bool(det.get("access_granted")),
                    "owner_baseline_valid": bool(det.get("owner_baseline_valid")),
                    "evidence_strength": str(det.get("evidence_strength") or ""),
                    "created_finding": bool(finding_by_tool_run_id.get(tool_run_id)),
                    "dedup_key": dedup_key,
                })
            if len(out) >= limit:
                return out[:limit]

        if runtime is not None and len(out) < limit:
            for row in reversed(runtime.get("iteration_summaries") or []):
                if not isinstance(row, dict):
                    continue
                kind = str(row.get("candidate_kind") or "").strip()
                if not kind:
                    continue
                _push({
                    "kind": kind,
                    "operation_id": "",
                    "field_path": "",
                    "object_pair_id": "",
                    "auth_mode": "",
                    "result": str(row.get("outcome") or row.get("tool_result_status") or "").strip(),
                    "status_code": 0,
                    "callback_received": False,
                    "access_granted": False,
                    "owner_baseline_valid": False,
                    "evidence_strength": "",
                    "created_finding": bool(str(row.get("finding_id") or "").strip()),
                    "dedup_key": f"{kind}|{str(row.get('tool_run_id') or '').strip() or str(row.get('iteration_index') or '')}",
                })
                if len(out) >= limit:
                    break
        return out[:limit]

    def _build_last_observation_summary(self, observations: list[dict[str, Any]]) -> dict[str, Any]:
        for raw in reversed(observations):
            if not isinstance(raw, dict):
                continue
            otype = str(raw.get("type") or raw.get("observation_type") or "").strip()
            det = raw.get("details") if isinstance(raw.get("details"), dict) else {}
            return {
                "type": otype,
                "operation_id": str(det.get("operation_id") or det.get("target_operation_id") or raw.get("operation_id") or ""),
                "field_path": str(det.get("field_path") or ""),
                "object_pair_id": str(det.get("object_pair_id") or ""),
                "auth_mode": str(det.get("auth_mode") or ("authenticated" if str(det.get("attacker_auth_profile_id") or "").strip() else "")),
                "result": str(det.get("result") or det.get("replay_classification") or ""),
                "status_code": self._safe_int(det.get("target_status_code") or det.get("status_code") or raw.get("status_code"), 0),
                "callback_received": bool(det.get("callback_received")),
                "access_granted": bool(det.get("access_granted")),
                "owner_baseline_valid": bool(det.get("owner_baseline_valid")),
                "evidence_strength": str(det.get("evidence_strength") or ""),
            }
        return {}

    def _build_adaptive_planner_diagnostics(self, runtime: dict[str, Any] | None) -> dict[str, Any]:
        if runtime is None:
            return {
                "status": "not_available",
                "reason": "planner_diagnostics_not_persisted",
            }
        summaries = runtime.get("iteration_summaries") if isinstance(runtime.get("iteration_summaries"), list) else []
        llm_used_count = 0
        llm_fallback_count = 0
        recent: list[dict[str, Any]] = []
        for row in summaries:
            if not isinstance(row, dict):
                continue
            selection_outcome = str(row.get("selection_outcome") or "").strip()
            fallback_used = bool(selection_outcome.startswith("llm_") and selection_outcome != "selected_ready")
            if selection_outcome.startswith("llm_") or bool(runtime.get("llm_planner_used")):
                llm_used_count += 1
            if fallback_used:
                llm_fallback_count += 1
            selected_candidate_id = str(row.get("selected_candidate_id") or runtime.get("llm_selected_candidate_id") or "").strip()
            selected_kind = str(row.get("candidate_kind") or runtime.get("llm_selected_kind") or "").strip()
            reason = str(row.get("selection_reason") or runtime.get("llm_selection_reason") or "").strip()
            decision = "fallback" if fallback_used else "execute"
            if selected_candidate_id or selected_kind:
                recent.append({
                    "selected_candidate_id": selected_candidate_id,
                    "selected_kind": selected_kind,
                    "decision": decision,
                    "fallback_used": fallback_used,
                    "reason": reason[:200],
                })
        if not recent and not runtime.get("llm_selected_candidate_id") and not runtime.get("llm_selected_kind"):
            return {
                "status": "not_available",
                "reason": "planner_diagnostics_not_persisted",
            }
        return {
            "status": "available",
            "llm_planner_used_count": int(llm_used_count),
            "llm_planner_fallback_count": int(llm_fallback_count),
            "last_selected_candidate_id": str(runtime.get("llm_selected_candidate_id") or ""),
            "last_selected_kind": str(runtime.get("llm_selected_kind") or ""),
            "last_selection_reason": str(runtime.get("llm_selection_reason") or "")[:200],
            "last_fallback_reason": str(runtime.get("llm_planner_fallback") or "")[:120],
            "recent_selected_candidates": recent[-10:],
        }

    def _build_api7_ssrf_pipeline_trace(
        self,
        *,
        runtime: dict[str, Any] | None,
        observations: list[dict[str, Any]],
        ssrf_candidate_signal_count: int,
        ssrf_ready_checks: list[dict[str, Any]],
        ssrf_blocked_checks: list[dict[str, Any]],
        ssrf_probe_samples: list[dict[str, Any]],
    ) -> dict[str, Any]:
        ready_candidate_ids = [
            str(row.get("candidate_id") or row.get("dedup_key") or row.get("operation_id") or "")
            for row in ssrf_ready_checks
            if str(row.get("candidate_id") or row.get("dedup_key") or row.get("operation_id") or "").strip()
        ]
        top_ready = ssrf_ready_checks[0] if ssrf_ready_checks else {}
        top_row = ssrf_probe_samples[0] if ssrf_probe_samples else {}
        top_candidate_operation_id = str(top_ready.get("operation_id") or top_row.get("operation_id") or "") or None
        top_candidate_field_path = str(top_row.get("field_path") or top_ready.get("field_path") or "") or None
        selected_candidate_id = ""
        selected_candidate_kind = ""
        selected_candidate_operation_id = ""
        if isinstance(runtime, dict):
            selected_candidate_id = str(
                runtime.get("llm_selected_candidate_id")
                or runtime.get("selected_candidate_id")
                or runtime.get("last_selected_candidate_id")
                or ""
            ).strip()
            selected_candidate_kind = str(
                runtime.get("llm_selected_kind")
                or runtime.get("selected_candidate_kind")
                or runtime.get("last_selected_kind")
                or ""
            ).strip()
            selected_candidate_operation_id = str(
                runtime.get("selected_candidate_operation_id")
                or runtime.get("last_selected_operation_id")
                or ""
            ).strip()
        ssrf_tool_failure = None
        tool_failure_summaries = runtime.get("tool_failure_summaries") if isinstance(runtime, dict) and isinstance(runtime.get("tool_failure_summaries"), list) else []
        for item in tool_failure_summaries:
            if not isinstance(item, dict):
                continue
            if str(item.get("candidate_kind") or "") == "ssrf_probe":
                ssrf_tool_failure = item
                break
        ssrf_failure_error_type = str(
            (ssrf_tool_failure or {}).get("tool_error_type")
            or (ssrf_tool_failure or {}).get("error_type")
            or ""
        ).strip()
        tool_executor_called = bool(ssrf_probe_samples or ssrf_tool_failure)
        adapter_called = bool(ssrf_probe_samples or (ssrf_tool_failure and ssrf_failure_error_type and "validation" not in ssrf_failure_error_type))
        ssrf_probe_result_emitted = bool(ssrf_probe_samples)
        ssrf_probe_result_persisted = bool(ssrf_probe_samples)
        report_context_has_ssrf_probe_results = bool(ssrf_probe_samples)
        markdown_rendered_ssrf_probe_results = bool(runtime.get("markdown_rendered_ssrf_probe_results")) if isinstance(runtime, dict) else False
        command_built = bool(ready_candidate_ids or selected_candidate_kind == "ssrf_probe")
        command_validation_passed: bool | None = None
        command_validation_error = ""
        last_failure_stage = ""
        last_failure_reason = ""
        for item in tool_failure_summaries:
            if not isinstance(item, dict):
                continue
            if str(item.get("candidate_kind") or "") != "ssrf_probe":
                continue
            command_validation_error = str(item.get("tool_error_safe_message") or item.get("safe_message") or "")[:200]
            error_type = str(item.get("tool_error_type") or item.get("error_type") or "")
            if "validation" in error_type:
                command_validation_passed = False
                last_failure_stage = "command_validation"
                last_failure_reason = error_type or command_validation_error
                break
            if not tool_executor_called:
                last_failure_stage = "tool_executor"
                last_failure_reason = error_type or command_validation_error or "tool execution failed before adapter call"
            elif not adapter_called:
                last_failure_stage = "adapter_lookup"
                last_failure_reason = error_type or command_validation_error or "adapter not called"
            else:
                last_failure_stage = "observation_persistence"
                last_failure_reason = error_type or command_validation_error or "adapter result not persisted"
            command_validation_passed = True if command_validation_passed is None else command_validation_passed
            break
        if command_validation_passed is None and command_built:
            command_validation_passed = True
        if not last_failure_stage:
            if ssrf_candidate_signal_count > 0 and not ready_candidate_ids:
                last_failure_stage = "planner"
                last_failure_reason = "no_ready_ssrf_probe_candidate"
            elif command_built and not tool_executor_called:
                last_failure_stage = "tool_executor"
                last_failure_reason = "ssrf_probe command was not executed"
            elif tool_executor_called and not adapter_called:
                last_failure_stage = "adapter_lookup"
                last_failure_reason = "ssrf_probe adapter was not called"
            elif adapter_called and not report_context_has_ssrf_probe_results:
                last_failure_stage = "observation_persistence"
                last_failure_reason = "ssrf_probe_result was not persisted"
            elif report_context_has_ssrf_probe_results and not markdown_rendered_ssrf_probe_results:
                last_failure_stage = "markdown_renderer"
                last_failure_reason = "markdown report did not render ssrf_probe_results"
        return {
            "ssrf_candidate_signal_count": int(ssrf_candidate_signal_count),
            "top_candidate_operation_id": top_candidate_operation_id,
            "top_candidate_field_path": top_candidate_field_path,
            "ready_ssrf_probe_count": len(ssrf_ready_checks),
            "ready_candidate_ids": ready_candidate_ids[:10],
            "selected_candidate_id": selected_candidate_id or None,
            "selected_candidate_kind": selected_candidate_kind or None,
            "selected_candidate_operation_id": selected_candidate_operation_id or None,
            "command_built": bool(command_built),
            "command_kind": "ssrf_probe" if (selected_candidate_kind == "ssrf_probe" or ready_candidate_ids) else None,
            "command_operation_id": selected_candidate_operation_id or top_candidate_operation_id,
            "command_validation_passed": command_validation_passed,
            "command_validation_error": command_validation_error or None,
            "tool_executor_called": bool(tool_executor_called),
            "adapter_called": bool(adapter_called),
            "ssrf_probe_result_emitted": bool(ssrf_probe_result_emitted),
            "ssrf_probe_result_persisted": bool(ssrf_probe_result_persisted),
            "report_context_has_ssrf_probe_results": bool(report_context_has_ssrf_probe_results),
            "markdown_rendered_ssrf_probe_results": bool(markdown_rendered_ssrf_probe_results),
            "last_failure_stage": last_failure_stage or None,
            "last_failure_reason": last_failure_reason or None,
        }

    def _build_auth_flow_diagnostics(self, campaign_id: str, observations: list[dict[str, Any]]) -> dict[str, Any]:
        empty = {
            "auth_flow_detected": False,
            "signup_candidate_count": 0,
            "login_candidate_count": 0,
            "token_response_candidate_count": 0,
            "profile_candidate_count": 0,
            "auth_flow_candidates_sample": [],
            "missing_prerequisites": [],
            "auth_limitations": [],
            "test_account_materialization_status": "not_attempted",
            "auth_profiles_created_count": 0,
            "signup_success_count": 0,
            "login_success_count": 0,
            "owner_auth_profile_id": "",
            "attacker_auth_profile_id": "",
            "auth_type": "unknown",
            "token_response_detected": False,
            "materialization_errors": [],
            "auth_profiles": [],
            "selected_signup_path": "",
            "selected_login_path": "",
            "signup_response_status_codes": [],
            "login_response_status_codes": [],
            "attempted_signup_operation_ids": [],
            "attempted_login_operation_ids": [],
            "signup_payload_field_names": [],
            "login_payload_field_names": [],
            "materialization_reason_codes": [],
            "owner_signup_attempts_count": 0,
            "attacker_signup_attempts_count": 0,
            "owner_login_attempts_count": 0,
            "attacker_login_attempts_count": 0,
            "signup_retry_count": 0,
            "login_retry_count": 0,
        }
        latest: dict[str, Any] | None = None
        latest_materialization: dict[str, Any] | None = None
        for o in reversed(observations):
            otype = str(o.get("type") or o.get("observation_type") or "")
            if otype != "auth_flow_signal":
                if latest_materialization is None and otype == "test_account_materialization_result":
                    det = o.get("details") if isinstance(o.get("details"), dict) else {}
                    if str(det.get("source") or "") == "test_account_materializer":
                        latest_materialization = det
                continue
            det = o.get("details") if isinstance(o.get("details"), dict) else {}
            if str(det.get("source") or "") != "auth_flow_detector":
                continue
            latest = det
            if latest_materialization is not None:
                break
        if latest is None and latest_materialization is None:
            return empty
        out = dict(empty)
        if latest is not None:
            def _count(key: str) -> int:
                v = latest.get(key)
                return len(v) if isinstance(v, list) else 0

            sample: list[dict[str, Any]] = []
            for bucket in (
                "signup_candidates",
                "login_candidates",
                "token_response_candidates",
                "profile_candidates",
            ):
                rows = latest.get(bucket)
                if not isinstance(rows, list):
                    continue
                for row in rows:
                    if not isinstance(row, dict):
                        continue
                    sample.append({
                        "operation_id": str(row.get("operation_id") or ""),
                        "method": str(row.get("method") or ""),
                        "path": str(row.get("path") or ""),
                        "confidence": str(row.get("confidence") or ""),
                        "reason_codes": list(row.get("reason_codes") or [])
                        if isinstance(row.get("reason_codes"), list) else [],
                    })
                    if len(sample) >= 12:
                        break
                if len(sample) >= 12:
                    break

            miss = latest.get("missing_prerequisites")
            miss_list = list(miss) if isinstance(miss, list) else []
            out.update({
                "auth_flow_detected": bool(latest.get("auth_flow_detected")),
                "signup_candidate_count": _count("signup_candidates"),
                "login_candidate_count": _count("login_candidates"),
                "token_response_candidate_count": _count("token_response_candidates"),
                "profile_candidate_count": _count("profile_candidates"),
                "auth_flow_candidates_sample": sample,
                "missing_prerequisites": miss_list,
                "auth_limitations": miss_list,
            })

        if latest_materialization is not None:
            created = self._safe_int(latest_materialization.get("auth_profiles_created_count"), 0)
            out.update({
                "test_account_materialization_status": (
                    "materialized" if created >= 2 else "partial_or_failed"
                ),
                "auth_profiles_created_count": created,
                "signup_success_count": self._safe_int(latest_materialization.get("signup_success_count"), 0),
                "login_success_count": self._safe_int(latest_materialization.get("login_success_count"), 0),
                "owner_auth_profile_id": str(latest_materialization.get("owner_auth_profile_id") or ""),
                "attacker_auth_profile_id": str(latest_materialization.get("attacker_auth_profile_id") or ""),
                "auth_type": str(latest_materialization.get("auth_type") or "unknown"),
                "token_response_detected": bool(latest_materialization.get("token_response_detected")),
                "materialization_errors": list(latest_materialization.get("materialization_errors") or [])[:10],
                "selected_signup_path": str(latest_materialization.get("selected_signup_path") or ""),
                "selected_login_path": str(latest_materialization.get("selected_login_path") or ""),
                "signup_response_status_codes": list(latest_materialization.get("signup_response_status_codes") or [])[:10],
                "login_response_status_codes": list(latest_materialization.get("login_response_status_codes") or [])[:10],
                "attempted_signup_operation_ids": list(latest_materialization.get("attempted_signup_operation_ids") or [])[:15],
                "attempted_login_operation_ids": list(latest_materialization.get("attempted_login_operation_ids") or [])[:15],
                "signup_payload_field_names": list(latest_materialization.get("signup_payload_field_names") or [])[:20],
                "login_payload_field_names": list(latest_materialization.get("login_payload_field_names") or [])[:20],
                "materialization_reason_codes": list(
                    latest_materialization.get("materialization_reason_codes")
                    or latest_materialization.get("reason_codes")
                    or []
                )[:20],
                "owner_signup_attempts_count": self._safe_int(
                    latest_materialization.get("owner_signup_attempts_count"), 0
                ),
                "attacker_signup_attempts_count": self._safe_int(
                    latest_materialization.get("attacker_signup_attempts_count"), 0
                ),
                "owner_login_attempts_count": self._safe_int(
                    latest_materialization.get("owner_login_attempts_count"), 0
                ),
                "attacker_login_attempts_count": self._safe_int(
                    latest_materialization.get("attacker_login_attempts_count"), 0
                ),
                "signup_retry_count": self._safe_int(latest_materialization.get("signup_retry_count"), 0),
                "login_retry_count": self._safe_int(latest_materialization.get("login_retry_count"), 0),
            })

        out["auth_profiles"] = self._auth_profiles.list_auth_profiles(campaign_id)[:10]
        return out

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
            elif vc == "undocumented_api_endpoint":
                finding_kinds["undocumented_endpoint_validator"] += 1
            elif vc in {"api_schema_contract_violation", "schema_contract_violation"}:
                finding_kinds["schemathesis_negative_test"] += 1
            elif vc == "potential_mass_assignment":
                finding_kinds["property_mutation_test"] += 1
            elif vc == "sensitive_property_exposure":
                finding_kinds["data_exposure_validator"] += 1
            elif vc == "ssrf_candidate":
                finding_kinds["ssrf_candidate_detector"] += 1

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

    @staticmethod
    def _js_extraction_coverage(observations: list[dict[str, Any]]) -> dict[str, Any]:
        markers: list[dict[str, Any]] = []
        for o in observations:
            otype = str(o.get("type") or o.get("observation_type") or "")
            if otype != "js_endpoint_extraction_result":
                continue
            det = o.get("details") if isinstance(o.get("details"), dict) else {}
            if str(det.get("source") or "") != "js_endpoint_extractor":
                continue
            markers.append(det)
        if not markers:
            return {
                "js_endpoint_extraction_count": 0,
                "js_route_fragments_count": 0,
                "js_route_fragments_matched_count": 0,
                "js_endpoints_emitted_count": 0,
                "js_extraction_results": [],
            }
        frag_total = sum(ReportContextBuilder._safe_int(m.get("route_fragments_count"), 0) for m in markers)
        matched_total = sum(ReportContextBuilder._safe_int(m.get("route_fragments_matched_count"), 0) for m in markers)
        emitted_total = sum(ReportContextBuilder._safe_int(m.get("endpoints_emitted_count"), 0) for m in markers)
        samples: list[dict[str, Any]] = []
        for det in markers[:10]:
            rc = det.get("reason_codes")
            samples.append({
                "js_url_sanitized": str(det.get("js_url_sanitized") or ""),
                "source_js_ref": str(det.get("source_js_ref") or ""),
                "result": str(det.get("result") or ""),
                "absolute_paths_count": ReportContextBuilder._safe_int(det.get("absolute_paths_count"), 0),
                "route_fragments_count": ReportContextBuilder._safe_int(det.get("route_fragments_count"), 0),
                "route_fragments_matched_count": ReportContextBuilder._safe_int(det.get("route_fragments_matched_count"), 0),
                "endpoints_emitted_count": ReportContextBuilder._safe_int(det.get("endpoints_emitted_count"), 0),
                "reason_codes": list(rc) if isinstance(rc, list) else [],
            })
        return {
            "js_endpoint_extraction_count": len(markers),
            "js_route_fragments_count": frag_total,
            "js_route_fragments_matched_count": matched_total,
            "js_endpoints_emitted_count": emitted_total,
            "js_extraction_results": samples,
        }

    @staticmethod
    def _api3_data_exposure_coverage(
        observations: list[dict[str, Any]],
        findings: list[dict[str, Any]],
    ) -> dict[str, Any]:
        inv_count = 0
        sig_count = 0
        probe_count = 0
        auth_inv_count = 0
        auth_sig_count = 0
        auth_probe_count = 0
        auth_non_200 = 0
        auth_fields_extracted = 0
        fields_extracted = 0
        auth_profiles_used: set[str] = set()
        auth_inventory_ops: set[str] = set()
        resource_inventory_count = 0
        resource_instances_count = 0
        resource_types: set[str] = set()
        resource_ops: set[str] = set()
        resource_samples: list[dict[str, Any]] = []
        typed_object_ref_count = 0
        owner_evidence_object_ref_count = 0
        seed_count = 0
        seed_success = 0
        seed_attempts_count = 0
        seed_failed_count = 0
        seed_object_refs_created = 0
        seed_samples: list[dict[str, Any]] = []
        bola_pair_inventory_count = 0
        bola_pairs_count = 0
        bola_pair_resource_types: set[str] = set()
        bola_replay_ready_count = 0
        bola_pairs_samples: list[dict[str, Any]] = []
        bola_replay_result_count = 0
        bola_replay_granted_count = 0
        owner_baseline_valid_count = 0
        bola_replay_denied_count = 0
        bola_replay_invalid_pair_count = 0
        bola_replay_inconclusive_count = 0
        invalid_pair_rework_count = 0
        object_ref_semantic_mismatch_count = 0
        weak_object_ref_provenance_count = 0
        blocked_bola_pair_count = 0
        low_baseline_probability_pair_count = 0
        last_invalid_pair_reason = ""
        last_invalid_pair_owner_status_code = 0
        last_invalid_pair_object_id_field = ""
        last_invalid_pair_path_param_name = ""
        last_invalid_pair_semantic_id_kind = ""
        dependency_edges_count = 0
        top_object_pair_score = 0.0
        top_object_pair_reasons: list[str] = []
        top_object_pair_block_reasons: list[str] = []
        last_blocked_bola_pair_reasons: list[str] = []
        last_invalid_bola_pair_reasons: list[str] = []
        semantic_match_pair_count = 0
        best_pair_operation_id = ""
        best_pair_status = "not_available"
        owner_baseline_status_code = 0
        attacker_status_code = 0
        last_replay_result = ""
        rework_reason = ""
        corpus_seed_count = 0
        corpus_seed_2xx_json_count = 0
        corpus_seed_auth_owner_count = 0
        corpus_seed_auth_attacker_count = 0
        bola_replay_samples: list[dict[str, Any]] = []
        probe_samples: list[dict[str, Any]] = []
        auth_probe_samples: list[dict[str, Any]] = []
        probe_results: list[str] = []
        for o in observations:
            otype = str(o.get("type") or o.get("observation_type") or "")
            if otype == "response_field_inventory":
                inv_count += 1
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("tool_name") or "") == "data_exposure_validator" and str(det.get("auth_mode") or "unauthenticated") == "authenticated":
                    auth_inv_count += 1
                    if str(det.get("auth_profile_id") or "").strip():
                        auth_profiles_used.add(str(det.get("auth_profile_id") or "").strip())
                    if str(det.get("operation_id") or "").strip():
                        auth_inventory_ops.add(str(det.get("operation_id") or "").strip())
            elif otype == "data_exposure_signal":
                sig_count += 1
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("tool_name") or "") == "data_exposure_validator" and str(det.get("auth_mode") or "unauthenticated") == "authenticated":
                    auth_sig_count += 1
                    if str(det.get("auth_profile_id") or "").strip():
                        auth_profiles_used.add(str(det.get("auth_profile_id") or "").strip())
            elif otype == "data_exposure_probe_result":
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("source") or "") != "data_exposure_validator":
                    continue
                probe_count += 1
                pr = str(det.get("result") or "")
                probe_results.append(pr)
                field_count = ReportContextBuilder._safe_int(det.get("field_count"), 0)
                extracted = pr in {"fields_extracted", "sensitive_fields_found"} or field_count > 0
                if extracted:
                    fields_extracted += 1
                is_auth = str(det.get("auth_mode") or "unauthenticated") == "authenticated"
                if is_auth:
                    auth_probe_count += 1
                    if str(det.get("auth_profile_id") or "").strip():
                        auth_profiles_used.add(str(det.get("auth_profile_id") or "").strip())
                    if pr == "non_200_response":
                        auth_non_200 += 1
                    if extracted:
                        auth_fields_extracted += 1
                if len(probe_samples) < 15:
                    rc = det.get("reason_codes")
                    sc = det.get("sensitive_categories")
                    probe_samples.append({
                        "operation_id": str(det.get("operation_id") or ""),
                        "method": str(det.get("method") or ""),
                        "path": str(det.get("path") or ""),
                        "status_code": ReportContextBuilder._safe_int(det.get("status_code"), 0),
                        "content_type": str(det.get("content_type") or ""),
                        "result": pr,
                        "field_count": field_count,
                        "sensitive_field_count": ReportContextBuilder._safe_int(det.get("sensitive_field_count"), 0),
                        "sensitive_categories": list(sc) if isinstance(sc, list) else [],
                        "auth_mode": str(det.get("auth_mode") or "unauthenticated"),
                        "auth_profile_id": str(det.get("auth_profile_id") or ""),
                        "role_hint": str(det.get("role_hint") or ""),
                        "reason_codes": list(rc) if isinstance(rc, list) else [],
                    })
                if is_auth and len(auth_probe_samples) < 15:
                    auth_probe_samples.append({
                        "operation_id": str(det.get("operation_id") or ""),
                        "method": str(det.get("method") or ""),
                        "path": str(det.get("path") or ""),
                        "status_code": ReportContextBuilder._safe_int(det.get("status_code"), 0),
                        "result": pr,
                        "field_count": field_count,
                        "sensitive_field_count": ReportContextBuilder._safe_int(det.get("sensitive_field_count"), 0),
                        "auth_mode": "authenticated",
                        "auth_profile_id": str(det.get("auth_profile_id") or ""),
                        "role_hint": str(det.get("role_hint") or ""),
                        "reason_codes": list(det.get("reason_codes") or []) if isinstance(det.get("reason_codes"), list) else [],
                    })
            elif otype == "resource_instance_inventory":
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("source") or "") != "resource_instance_extractor":
                    continue
                resource_inventory_count += 1
                resource_instances_count += ReportContextBuilder._safe_int(det.get("resource_instances_count"), 0)
                op_id = str(det.get("source_operation_id") or "").strip()
                if op_id:
                    resource_ops.add(op_id)
                auth_profile_id = str(det.get("source_auth_profile_id") or "").strip()
                if auth_profile_id:
                    auth_profiles_used.add(auth_profile_id)
                refs = det.get("object_refs") if isinstance(det.get("object_refs"), list) else []
                for row in refs:
                    if not isinstance(row, dict):
                        continue
                    corpus_seed_count += 1
                    if int(row.get("source_status_code") or 0) >= 200 and int(row.get("source_status_code") or 0) < 300:
                        if "json" in str(row.get("source_content_type") or "").lower():
                            corpus_seed_2xx_json_count += 1
                    role_hint = str(row.get("source_role_hint") or det.get("source_role_hint") or "").strip().lower()
                    if role_hint == "owner":
                        corpus_seed_auth_owner_count += 1
                    elif role_hint == "attacker":
                        corpus_seed_auth_attacker_count += 1
                    rtype = str(row.get("resource_type") or "").strip()
                    if rtype:
                        resource_types.add(rtype)
                    if len(resource_samples) < 20:
                        resource_samples.append({
                            "object_ref_id": str(row.get("object_ref_id") or ""),
                            "resource_type": rtype,
                            "object_id_field": str(row.get("object_id_field") or ""),
                            "object_id_ref": str(row.get("object_id_ref") or ""),
                            "source_operation_id": op_id,
                            "source_path": str(det.get("source_path") or ""),
                            "source_auth_profile_id": auth_profile_id,
                            "source_role_hint": str(det.get("source_role_hint") or ""),
                            "confidence": str(row.get("confidence") or ""),
                            "id_json_path": str(row.get("id_json_path") or ""),
                            "owner_evidence": bool(row.get("owner_evidence")),
                            "reason_codes": list(det.get("reason_codes")) if isinstance(det.get("reason_codes"), list) else [],
                        })
                    if str(row.get("semantic_id_kind") or "").strip() not in {"", "unknown_id"}:
                        typed_object_ref_count += 1
                    if bool(row.get("owner_evidence")):
                        owner_evidence_object_ref_count += 1
            elif otype == "resource_seed_result":
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("validation_mode") or "").strip() != "resource_seed":
                    continue
                seed_count += 1
                seed_status = str(det.get("seed_status") or "").strip()
                created = ReportContextBuilder._safe_int(det.get("object_refs_created_count"), 0)
                if seed_status == "seeded":
                    seed_success += 1
                    corpus_seed_count += max(1, created)
                    corpus_seed_2xx_json_count += max(1, created)
                seed_attempts_count += max(0, ReportContextBuilder._safe_int(det.get("resource_seed_attempts_count"), 0))
                seed_failed_count += max(0, ReportContextBuilder._safe_int(det.get("resource_seed_failed_count"), 0))
                seed_object_refs_created += max(0, created)
                if len(seed_samples) < 10:
                    refs = det.get("object_refs") if isinstance(det.get("object_refs"), list) else []
                    safe_refs: list[dict[str, Any]] = []
                    for row in refs[:3]:
                        if not isinstance(row, dict):
                            continue
                        safe_refs.append({
                            "object_ref_id": str(row.get("object_ref_id") or ""),
                            "object_id_ref": str(row.get("object_id_ref") or ""),
                            "object_id_field": str(row.get("object_id_field") or ""),
                            "resource_type": str(row.get("resource_type") or ""),
                            "confidence": str(row.get("confidence") or ""),
                        })
                    rc = det.get("reason_codes")
                    seed_samples.append({
                        "seed_status": seed_status,
                        "resource_type": str(det.get("resource_type") or ""),
                        "owner_auth_profile_id": str(det.get("owner_auth_profile_id") or ""),
                        "seed_operation_id": str(det.get("seed_operation_id") or ""),
                        "seed_method": str(det.get("seed_method") or ""),
                        "seed_path": str(det.get("seed_path") or ""),
                        "followup_operation_id": str(det.get("followup_operation_id") or ""),
                        "followup_method": str(det.get("followup_method") or ""),
                        "followup_path": str(det.get("followup_path") or ""),
                        "object_refs_created_count": created,
                        "object_refs": safe_refs,
                        "http_calls_count": ReportContextBuilder._safe_int(det.get("http_calls_count"), 0),
                        "resource_seed_attempts_count": ReportContextBuilder._safe_int(det.get("resource_seed_attempts_count"), 0),
                        "resource_seed_failed_count": ReportContextBuilder._safe_int(det.get("resource_seed_failed_count"), 0),
                        "reason_codes": list(rc) if isinstance(rc, list) else [],
                    })
            elif otype == "bola_object_pair_inventory":
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("validation_mode") or "").strip() != "bola_object_pair_building":
                    continue
                bola_pair_inventory_count += 1
                pairs = det.get("object_pairs") if isinstance(det.get("object_pairs"), list) else []
                count = ReportContextBuilder._safe_int(det.get("object_pairs_count"), len(pairs))
                bola_pairs_count += max(0, count)
                if count > 0:
                    bola_replay_ready_count += 1
                rtypes = det.get("resource_types")
                if isinstance(rtypes, list):
                    for rt in rtypes:
                        t = str(rt).strip()
                        if t:
                            bola_pair_resource_types.add(t)
                for row in pairs:
                    if not isinstance(row, dict) or len(bola_pairs_samples) >= 20:
                        continue
                    rt = str(row.get("resource_type") or "").strip()
                    if rt:
                        bola_pair_resource_types.add(rt)
                    rc = row.get("reason_codes")
                    metadata = row.get("metadata") if isinstance(row.get("metadata"), dict) else {}
                    if isinstance(metadata.get("dependency_edge"), dict):
                        dependency_edges_count += 1
                    pair_score = float(metadata.get("baseline_probability_score") or 0.0)
                    if pair_score > top_object_pair_score:
                        top_object_pair_score = pair_score
                        top_object_pair_reasons = [str(x) for x in (metadata.get("baseline_probability_reasons") or []) if str(x).strip()][:20]
                        top_object_pair_block_reasons = [str(x) for x in (metadata.get("baseline_block_reasons") or []) if str(x).strip()][:20]
                        best_pair_operation_id = str(row.get("target_operation_id") or "")
                    bola_pairs_samples.append({
                        "object_pair_id": str(row.get("object_pair_id") or ""),
                        "resource_type": rt,
                        "object_ref_id": str(row.get("object_ref_id") or ""),
                        "object_id_ref": str(row.get("object_id_ref") or ""),
                        "owner_auth_profile_id": str(row.get("owner_auth_profile_id") or ""),
                        "attacker_auth_profile_id": str(row.get("attacker_auth_profile_id") or ""),
                        "target_operation_id": str(row.get("target_operation_id") or ""),
                        "target_path_template": str(row.get("target_path_template") or ""),
                        "target_method": str(row.get("target_method") or ""),
                        "path_param_name": str(row.get("path_param_name") or ""),
                        "confidence": str(row.get("confidence") or ""),
                        "baseline_probability_score": pair_score,
                        "baseline_probability_reasons": [str(x) for x in (metadata.get("baseline_probability_reasons") or []) if str(x).strip()][:20],
                        "dependency_edge_confidence": str(metadata.get("dependency_edge_confidence") or ""),
                        "semantic_id_kind": str(metadata.get("semantic_id_kind") or ""),
                        "object_id_field": str(metadata.get("object_id_field") or ""),
                        "source_operation_id": str(metadata.get("source_operation_id") or ""),
                        "dependency_producer_operation_id": str(metadata.get("dependency_producer_operation_id") or ""),
                        "baseline_block_reasons": [str(x) for x in (metadata.get("baseline_block_reasons") or []) if str(x).strip()][:20],
                        "reason_codes": list(rc) if isinstance(rc, list) else [],
                    })
                    all_reasons = {
                        str(x).strip() for x in (
                            list(metadata.get("baseline_probability_reasons") or [])
                            + list(metadata.get("baseline_block_reasons") or [])
                            + (list(rc) if isinstance(rc, list) else [])
                        ) if str(x).strip()
                    }
                    if "path_param_semantic_mismatch" in all_reasons or "object_id_field_semantic_mismatch" in all_reasons:
                        object_ref_semantic_mismatch_count += 1
                    if "semantic_id_kind_matches_path_param" in all_reasons:
                        semantic_match_pair_count += 1
                    if {
                        "seed_creation_non_2xx_penalty",
                        "blocked_required_object_ref_penalty",
                        "source_seed_creation_non_2xx",
                        "source_seed_blocked_required_object_ref",
                        "object_ref_provenance_weak",
                    } & all_reasons:
                        weak_object_ref_provenance_count += 1
                    if metadata.get("baseline_block_reasons"):
                        blocked_bola_pair_count += 1
                        last_blocked_bola_pair_reasons = [str(x) for x in (metadata.get("baseline_block_reasons") or []) if str(x).strip()][:20]
                    if pair_score < 50.0:
                        low_baseline_probability_pair_count += 1
            elif otype == "bola_replay_result":
                det = o.get("details") if isinstance(o.get("details"), dict) else {}
                if str(det.get("validation_mode") or "").strip() != "bola_replay":
                    continue
                bola_replay_result_count += 1
                if bool(det.get("access_granted")):
                    bola_replay_granted_count += 1
                if bool(det.get("owner_baseline_valid")):
                    owner_baseline_valid_count += 1
                result_label = str(det.get("result") or "")
                replay_classification = str(det.get("replay_classification") or "")
                if replay_classification in {"access_denied", "access_denied_or_not_found"} or result_label in {
                    "attacker_access_denied",
                    "attacker_access_denied_or_not_found",
                }:
                    bola_replay_denied_count += 1
                if replay_classification == "invalid_object_pair" or result_label == "invalid_object_pair":
                    bola_replay_invalid_pair_count += 1
                    invalid_pair_rework_count += 1
                    rework_reason = "request_new_resource_seed_or_try_next_object_pair"
                    last_invalid_pair_reason = "owner_baseline_failed"
                    last_invalid_pair_owner_status_code = ReportContextBuilder._safe_int(det.get("owner_status_code"), 0)
                    last_invalid_pair_object_id_field = str(det.get("object_id_field") or "")
                    last_invalid_pair_path_param_name = str(det.get("path_param_name") or "")
                    last_invalid_pair_semantic_id_kind = str(det.get("semantic_id_kind") or "")
                    last_invalid_bola_pair_reasons = [str(x) for x in (det.get("reason_codes") or []) if str(x).strip()][:20]
                if replay_classification == "inconclusive" or result_label == "replay_error":
                    bola_replay_inconclusive_count += 1
                if result_label:
                    last_replay_result = result_label
                owner_baseline_status_code = ReportContextBuilder._safe_int(det.get("owner_status_code"), owner_baseline_status_code)
                attacker_status_code = ReportContextBuilder._safe_int(det.get("attacker_status_code"), attacker_status_code)
                if len(bola_replay_samples) < 20:
                    rc = det.get("reason_codes")
                    bola_replay_samples.append({
                        "object_pair_id": str(det.get("object_pair_id") or ""),
                        "resource_type": str(det.get("resource_type") or ""),
                        "target_operation_id": str(det.get("target_operation_id") or ""),
                        "target_path_template": str(det.get("target_path_template") or ""),
                        "target_method": str(det.get("target_method") or ""),
                        "path_param_name": str(det.get("path_param_name") or ""),
                        "attacker_auth_profile_id": str(det.get("attacker_auth_profile_id") or ""),
                        "owner_auth_profile_id": str(det.get("owner_auth_profile_id") or ""),
                        "status_code": ReportContextBuilder._safe_int(det.get("status_code"), 0),
                        "owner_status_code": ReportContextBuilder._safe_int(det.get("owner_status_code"), 0),
                        "owner_result": str(det.get("owner_result") or ""),
                        "attacker_status_code": ReportContextBuilder._safe_int(det.get("attacker_status_code"), 0),
                        "attacker_result": str(det.get("attacker_result") or ""),
                        "result": result_label,
                        "replay_classification": replay_classification,
                        "owner_baseline_valid": bool(det.get("owner_baseline_valid")),
                        "access_granted": bool(det.get("access_granted")),
                        "evidence_strength": str(det.get("evidence_strength") or ""),
                        "reason_codes": list(rc) if isinstance(rc, list) else [],
                    })
        sens_findings = sum(
            1 for f in findings
            if str(f.get("vulnerability_class") or "") == "sensitive_property_exposure"
        )
        categories: set[str] = set()
        field_sample: list[dict[str, str]] = []
        results: list[dict[str, Any]] = []
        for o in observations:
            otype = str(o.get("type") or o.get("observation_type") or "")
            det = o.get("details") if isinstance(o.get("details"), dict) else {}
            if str(det.get("tool_name") or "") != "data_exposure_validator":
                continue
            if otype == "data_exposure_signal":
                is_auth = str(det.get("auth_mode") or "unauthenticated") == "authenticated"
                rc = det.get("sensitive_categories")
                if isinstance(rc, list):
                    for x in rc:
                        t = str(x).strip()
                        if t:
                            categories.add(t)
                sf = det.get("sensitive_fields")
                if isinstance(sf, list):
                    for item in sf:
                        if isinstance(item, dict) and len(field_sample) < 10:
                            field_sample.append({
                                "field_name": str(item.get("field_name") or ""),
                                "category": str(item.get("category") or ""),
                            })
                results.append({
                    "operation_id": str(det.get("operation_id") or ""),
                    "path": str(det.get("path") or ""),
                    "method": str(det.get("method") or ""),
                    "status_code": ReportContextBuilder._safe_int(det.get("status_code"), 0),
                    "sensitive_field_count": ReportContextBuilder._safe_int(det.get("sensitive_field_count"), 0),
                    "result": "data_exposure_signal",
                    "auth_mode": "authenticated" if is_auth else "unauthenticated",
                    "auth_profile_id": str(det.get("auth_profile_id") or ""),
                    "role_hint": str(det.get("role_hint") or ""),
                })
            elif otype == "response_field_inventory":
                is_auth = str(det.get("auth_mode") or "unauthenticated") == "authenticated"
                results.append({
                    "operation_id": str(det.get("operation_id") or ""),
                    "path": str(det.get("path") or ""),
                    "method": str(det.get("method") or ""),
                    "status_code": ReportContextBuilder._safe_int(det.get("status_code"), 0),
                    "field_count": ReportContextBuilder._safe_int(det.get("field_count"), 0),
                    "sensitive_field_count": ReportContextBuilder._safe_int(det.get("sensitive_field_count"), 0),
                    "result": "response_field_inventory",
                    "auth_mode": "authenticated" if is_auth else "unauthenticated",
                    "auth_profile_id": str(det.get("auth_profile_id") or ""),
                    "role_hint": str(det.get("role_hint") or ""),
                })
        non_200 = sum(1 for x in probe_results if x == "non_200_response")
        non_json = sum(1 for x in probe_results if x == "non_json_response")
        no_fields = sum(1 for x in probe_results if x == "no_fields_found")
        if bola_replay_granted_count > 0:
            best_pair_status = "granted"
        elif bola_replay_invalid_pair_count > 0:
            best_pair_status = "invalid_object_pair"
        elif bola_replay_denied_count > 0:
            best_pair_status = "denied"
        elif bola_replay_ready_count > 0:
            best_pair_status = "ready"
        return {
            "response_field_inventory_count": inv_count,
            "data_exposure_signal_count": sig_count,
            "data_exposure_probe_result_count": probe_count,
            "authenticated_response_field_inventory_count": auth_inv_count,
            "authenticated_data_exposure_signal_count": auth_sig_count,
            "authenticated_data_exposure_probe_result_count": auth_probe_count,
            "data_exposure_non_200_count": non_200,
            "data_exposure_non_json_count": non_json,
            "data_exposure_no_fields_count": no_fields,
            "data_exposure_fields_extracted_count": fields_extracted,
            "data_exposure_authenticated_non_200_count": auth_non_200,
            "data_exposure_authenticated_fields_extracted_count": auth_fields_extracted,
            "auth_profiles_used_count": len(auth_profiles_used),
            "operations_with_authenticated_inventory": len(auth_inventory_ops),
            "resource_instance_inventory_count": resource_inventory_count,
            "resource_instances_count": resource_instances_count,
            "object_refs_count": resource_instances_count,
            "api1_resource_instance_count": resource_instances_count,
            "api1_object_ref_count": resource_instances_count,
            "api1_typed_object_ref_count": typed_object_ref_count,
            "api1_owner_evidence_object_ref_count": owner_evidence_object_ref_count,
            "operations_with_resource_instances": len(resource_ops),
            "resource_types": sorted(resource_types)[:20],
            "resource_instance_results": resource_samples,
            "resource_seed_result_count": seed_count,
            "resource_seed_success_count": seed_success,
            "resource_seed_attempts_count": seed_attempts_count,
            "resource_seed_failed_count": seed_failed_count,
            "resource_seed_object_refs_created_count": seed_object_refs_created,
            "resource_seed_results": seed_samples,
            "corpus_seed_count": corpus_seed_count,
            "corpus_seed_2xx_json_count": corpus_seed_2xx_json_count,
            "corpus_seed_auth_owner_count": corpus_seed_auth_owner_count,
            "corpus_seed_auth_attacker_count": corpus_seed_auth_attacker_count,
            "bola_object_pair_inventory_count": bola_pair_inventory_count,
            "bola_object_pairs_count": bola_pairs_count,
            "dependency_edges_count": dependency_edges_count,
            "bola_pair_resource_types": sorted(bola_pair_resource_types)[:20],
            "bola_replay_ready_count": bola_replay_ready_count,
            "bola_object_pairs": bola_pairs_samples,
            "bola_replay_result_count": bola_replay_result_count,
            "api1_replay_result_count": bola_replay_result_count,
            "bola_replay_granted_count": bola_replay_granted_count,
            "api1_attacker_access_granted_count": bola_replay_granted_count,
            "bola_replay_denied_count": bola_replay_denied_count,
            "bola_replay_invalid_pair_count": bola_replay_invalid_pair_count,
            "api1_invalid_pair_count": bola_replay_invalid_pair_count,
            "bola_replay_inconclusive_count": bola_replay_inconclusive_count,
            "api1_owner_baseline_valid_count": owner_baseline_valid_count,
            "invalid_pair_rework_count": invalid_pair_rework_count,
            "object_ref_semantic_mismatch_count": object_ref_semantic_mismatch_count,
            "weak_object_ref_provenance_count": weak_object_ref_provenance_count,
            "blocked_bola_pair_count": blocked_bola_pair_count,
            "api1_blocked_pair_count": blocked_bola_pair_count,
            "api1_semantic_match_pair_count": semantic_match_pair_count,
            "low_baseline_probability_pair_count": low_baseline_probability_pair_count,
            "last_invalid_pair_reason": last_invalid_pair_reason,
            "last_invalid_pair_owner_status_code": last_invalid_pair_owner_status_code,
            "last_invalid_pair_object_id_field": last_invalid_pair_object_id_field,
            "last_invalid_pair_path_param_name": last_invalid_pair_path_param_name,
            "last_invalid_pair_semantic_id_kind": last_invalid_pair_semantic_id_kind,
            "top_object_pair_score": float(top_object_pair_score),
            "top_object_pair_reasons": top_object_pair_reasons[:20],
            "top_object_pair_block_reasons": top_object_pair_block_reasons[:20],
            "last_blocked_bola_pair_reasons": last_blocked_bola_pair_reasons[:20],
            "last_invalid_bola_pair_reasons": last_invalid_bola_pair_reasons[:20],
            "api1_bola_compact_diagnostics": {
                "best_pair_operation_id": best_pair_operation_id,
                "best_pair_score": float(top_object_pair_score),
                "best_pair_status": best_pair_status,
                "best_pair_block_reasons": top_object_pair_block_reasons[:20],
                "last_replay_result": last_replay_result,
                "owner_baseline_status_code": owner_baseline_status_code,
                "attacker_status_code": attacker_status_code,
                "rework_reason": rework_reason,
            },
            "best_bola_replay_result": last_replay_result,
            "bola_replay_results": bola_replay_samples,
            "data_exposure_probe_results": probe_samples,
            "authenticated_data_exposure_results": auth_probe_samples,
            "sensitive_property_exposure_findings_count": sens_findings,
            "sensitive_field_categories": sorted(categories)[:20],
            "sensitive_fields_sample": field_sample[:10],
            "data_exposure_results": results[:15],
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
        findings_api1 = sum(1 for f in findings if str(f.get("owasp_category") or "") == "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION")
        findings_api7 = sum(1 for f in findings if str(f.get("owasp_category") or "") == "API7_SERVER_SIDE_REQUEST_FORGERY")

        schema_mismatch_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "schema_mismatch")
        undocumented_endpoint_signal_count = sum(
            1
            for o in observations
            if str(o.get("type") or o.get("observation_type") or "") == "undocumented_endpoint_signal"
        )
        mass_assignment_signal_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "mass_assignment_signal")
        ssrf_candidate_signal_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "ssrf_candidate_signal")
        ssrf_probe_result_count = sum(1 for o in observations if str(o.get("type") or o.get("observation_type") or "") == "ssrf_probe_result")
        undocumented_endpoint_findings_count = sum(
            1
            for f in findings
            if str(f.get("vulnerability_class") or "") == "undocumented_api_endpoint"
        )
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
        api9_undoc_ex = self._safe_int(executed.get("undocumented_endpoint_validator"), 0)
        api9_undoc_ready = self._safe_int(ready_map.get("undocumented_endpoint_validator"), 0)
        js_cov = self._js_extraction_coverage(observations)
        api3_ex = self._safe_int(executed.get("property_mutation_test"), 0)
        api3_ready = self._safe_int(ready_map.get("property_mutation_test"), 0)
        api3_blocked_total = self._safe_int(blocked_map.get("property_mutation_test"), 0) if runtime is not None else "not_available"
        api3_dex_ex = self._safe_int(executed.get("data_exposure_validator"), 0)
        api3_dex_ready = self._safe_int(ready_map.get("data_exposure_validator"), 0)
        api3_dex_blocked = self._safe_int(blocked_map.get("data_exposure_validator"), 0) if runtime is not None else "not_available"
        api3_de_cov = self._api3_data_exposure_coverage(observations, findings)
        ssrf_operations: set[str] = set()
        ssrf_fields = 0
        ssrf_rows: list[dict[str, Any]] = []
        ssrf_probe_samples: list[dict[str, Any]] = []
        ssrf_callback_received_count = 0
        ssrf_late_callback_reconciled_count = 0
        ssrf_no_callback_count = 0
        ssrf_confirmable_count = 0
        ssrf_probe_target_non_2xx_count = 0
        ssrf_probe_probe_error_count = 0
        ssrf_probe_schema_synthesized_count = 0
        ssrf_probe_llm_composed_count = 0
        for o in observations:
            if str(o.get("type") or o.get("observation_type") or "") != "ssrf_candidate_signal":
                continue
            det = o.get("details") if isinstance(o.get("details"), dict) else {}
            op_id = str(det.get("operation_id") or o.get("operation_id") or "").strip()
            field_name = str(det.get("field_name") or "").strip()
            field_path = str(det.get("field_path") or "").strip()
            if op_id:
                ssrf_operations.add(op_id)
            if field_name and field_path:
                ssrf_fields += 1
            ssrf_rows.append({
                "operation_id": op_id,
                "method": str(det.get("method") or ""),
                "path": str(det.get("path") or ""),
                "field_name": field_name,
                "field_path": field_path,
                "schema_type": str(det.get("schema_type") or ""),
                "schema_format": str(det.get("schema_format") or ""),
                "confidence": str(det.get("confidence") or ""),
                "reason_codes": list(det.get("reason_codes")) if isinstance(det.get("reason_codes"), list) else [],
                "has_path_params": bool("{" in str(det.get("path") or "") and "}" in str(det.get("path") or "")),
                "auth_required": bool(det.get("auth_required")),
                "auth_mode": str(det.get("auth_mode") or ""),
                "required_body_fields": [str(x) for x in (det.get("required_body_fields") or []) if str(x).strip()][:20],
                "allowed_body_fields_count": len([x for x in (det.get("allowed_body_fields") or []) if str(x).strip()]),
                "schema_summary_source": str(det.get("schema_summary_source") or "none"),
                "ssrf_score": float(det.get("ssrf_score") or 0.0),
                "ssrf_score_reasons": list(det.get("ssrf_score_reasons") or []) if isinstance(det.get("ssrf_score_reasons"), list) else [],
            })
        confidence_rank = {"high": 2, "medium": 1, "low": 0}
        def _ssrf_row_score(row: dict[str, Any]) -> float:
            score = 0.0
            conf = str(row.get("confidence") or "").strip().lower()
            sf = str(row.get("schema_format") or "").strip().lower()
            method = str(row.get("method") or "").strip().upper()
            path = str(row.get("path") or "").strip().lower()
            field_name = str(row.get("field_name") or "").strip().lower()
            field_path = str(row.get("field_path") or "").strip().lower()
            if conf == "high":
                score += 4.0
            elif conf == "medium":
                score += 2.0
            if sf in {"uri", "url"}:
                score += 3.0
            if method in {"POST", "PUT", "PATCH"}:
                score += 2.0
            if not bool(row.get("has_path_params")):
                score += 2.0
            if any(h in field_name for h in _SSRF_POSITIVE_HINTS) or any(h in field_path for h in _SSRF_POSITIVE_HINTS):
                score += 2.5
            if any(h in path for h in _SSRF_POSITIVE_HINTS):
                score += 2.0
            if any(h in field_name for h in _SSRF_NEGATIVE_HINTS) or any(h in field_path for h in _SSRF_NEGATIVE_HINTS) or any(h in path for h in _SSRF_NEGATIVE_HINTS):
                score -= 3.0
            return score
        ssrf_rows_sorted = sorted(
            ssrf_rows,
            key=lambda row: (
                _ssrf_row_score(row),
                confidence_rank.get(str(row.get("confidence") or "").strip().lower(), 0),
                0 if bool(row.get("has_path_params")) else 1,
                str(row.get("operation_id") or ""),
                str(row.get("field_path") or ""),
            ),
            reverse=True,
        )
        ssrf_samples = ssrf_rows_sorted[:10]

        for o in observations:
            if str(o.get("type") or o.get("observation_type") or "") != "ssrf_probe_result":
                continue
            det = o.get("details") if isinstance(o.get("details"), dict) else {}
            effective = get_effective_ssrf_callback_state({"details": det})
            callback_received = bool(det.get("callback_received"))
            callback_received_effective = bool(effective.get("callback_received_effective"))
            late_callback_reconciled = bool(effective.get("late_callback_reconciled"))
            callback_store_received = bool(effective.get("callback_store_received"))
            callback_correlation_id = str(
                effective.get("callback_correlation_id")
                or det.get("callback_correlation_id")
                or det.get("correlation_id")
                or ""
            )
            if callback_received_effective:
                ssrf_callback_received_count += 1
            else:
                ssrf_no_callback_count += 1
            if late_callback_reconciled:
                ssrf_late_callback_reconciled_count += 1
            result_label = str(det.get("result") or "").strip().lower()
            if result_label in {"target_non_2xx", "target_4xx", "target_5xx"}:
                ssrf_probe_target_non_2xx_count += 1
            if result_label == "probe_error":
                ssrf_probe_probe_error_count += 1
            payload_synthesis_result = str(
                det.get("payload_synthesis_result")
                or det.get("payload_synthesis")
                or ("llm_composed" if str(det.get("request_composer") or "").strip().lower() == "llm" else "")
            )
            if payload_synthesis_result in {"schema_synthesized", "draft_rejected_schema_synthesized"}:
                ssrf_probe_schema_synthesized_count += 1
            if payload_synthesis_result == "llm_composed":
                ssrf_probe_llm_composed_count += 1
            if callback_received_effective and str(det.get("evidence_strength") or "").strip().lower() in {"medium", "high"}:
                ssrf_confirmable_count += 1
            if len(ssrf_probe_samples) < 20:
                rc = det.get("reason_codes")
                safe_reason_codes = list(rc) if isinstance(rc, list) else []
                for code in effective.get("reason_codes") or []:
                    if isinstance(code, str) and code.strip() and code.strip() not in safe_reason_codes:
                        safe_reason_codes.append(code.strip())
                ssrf_probe_samples.append({
                    "operation_id": str(det.get("operation_id") or ""),
                    "method": str(det.get("method") or ""),
                    "path": str(det.get("path") or ""),
                    "field_name": str(det.get("field_name") or ""),
                    "field_path": str(det.get("field_path") or ""),
                    "auth_mode": str(det.get("auth_mode") or ""),
                    "auth_profile_id": str(det.get("auth_profile_id") or ""),
                    "role_hint": str(det.get("role_hint") or ""),
                    "correlation_id": str(det.get("correlation_id") or ""),
                    "callback_correlation_id": callback_correlation_id,
                    "target_status_code": ReportContextBuilder._safe_int(det.get("target_status_code"), 0),
                    "callback_received": callback_received,
                    "callback_received_effective": callback_received_effective,
                    "late_callback_reconciled": late_callback_reconciled,
                    "callback_store_received": callback_store_received,
                    "callback_method": str(effective.get("callback_method") or det.get("callback_method") or ""),
                    "callback_headers_count": ReportContextBuilder._safe_int(effective.get("callback_headers_count"), 0),
                    "result": str(det.get("result") or ""),
                    "evidence_strength": str(det.get("evidence_strength") or ""),
                    "request_composer": str(det.get("request_composer") or "deterministic"),
                    "request_draft_validated": bool(det.get("request_draft_validated")),
                    "payload_synthesis_result": payload_synthesis_result,
                    "synthesized_required_fields_count": ReportContextBuilder._safe_int(det.get("synthesized_required_fields_count"), 0),
                    "filled_required_fields_count": ReportContextBuilder._safe_int(det.get("filled_required_fields_count"), 0),
                    "missing_required_fields_count": ReportContextBuilder._safe_int(det.get("missing_required_fields_count"), 0),
                    "rejected_fields_count": ReportContextBuilder._safe_int(det.get("rejected_fields_count"), 0),
                    "synthesized_field_count": ReportContextBuilder._safe_int(det.get("synthesized_field_count"), 0),
                    "schema_summary_source": str(det.get("schema_summary_source") or "none"),
                    "reason_codes": safe_reason_codes,
                })

        ssrf_ready_checks = [row for row in ready_checks if str(row.get("kind") or "") == "ssrf_probe"]
        ssrf_blocked_checks = [row for row in blocked_checks if str(row.get("kind") or "") == "ssrf_probe"]
        ssrf_probe_deprioritized_count = 0
        if isinstance(runtime, dict):
            for row in (runtime.get("iteration_summaries") or []):
                if not isinstance(row, dict):
                    continue
                if str(row.get("candidate_kind") or "") != "ssrf_probe":
                    continue
                if str(row.get("selection_outcome") or "").strip() == "deprioritized":
                    ssrf_probe_deprioritized_count += 1
        top_row = ssrf_rows_sorted[0] if ssrf_rows_sorted else {}
        top_op = str(top_row.get("operation_id") or "")
        top_fp = str(top_row.get("field_path") or "")
        top_candidate_id = ""
        top_status = "skipped"
        top_block_reason: str | None = None
        for row in ssrf_ready_checks:
            if str(row.get("operation_id") or "") == top_op and str(row.get("field_path") or "") == top_fp:
                top_candidate_id = str(row.get("candidate_id") or "")
                top_status = "ready"
                break
        if top_status != "ready":
            for row in ssrf_blocked_checks:
                if str(row.get("operation_id") or "") == top_op and str(row.get("field_path") or "") == top_fp:
                    top_candidate_id = str(row.get("candidate_id") or "")
                    top_status = "blocked"
                    top_block_reason = str(row.get("reason") or "") or None
                    break
        if top_status == "skipped" and top_op and top_fp:
            top_status = "deprioritized"
        api7_already_confirmed = ssrf_callback_received_count > 0
        stopped_reason = str(runtime.get("stopped_reason") or "").strip() if isinstance(runtime, dict) else ""
        api7_reason = "ssrf_probe_ready_available"
        if api7_already_confirmed:
            api7_reason = "api7_already_confirmed"
        elif not ssrf_ready_checks and ssrf_candidate_signal_count > 0:
            api7_reason = "no_ready_ssrf_probe_candidates"
            if stopped_reason == "no_ready_candidate":
                api7_reason = "no_ready_candidate_with_ssrf_signals"
        api7_planning_diagnostics = {
            "ssrf_candidate_signal_count": int(ssrf_candidate_signal_count),
            "ssrf_probe_ready_count": len(ssrf_ready_checks),
            "ssrf_probe_blocked_count": len(ssrf_blocked_checks),
            "ssrf_probe_deprioritized_count": int(ssrf_probe_deprioritized_count),
            "top_candidate_id": top_candidate_id,
            "top_candidate_operation_id": top_op,
            "top_candidate_field_path": top_fp,
            "top_candidate_status": top_status,
            "top_candidate_blocked_reason": top_block_reason,
            "kind_cap_remaining": None,
            "api7_already_confirmed": bool(api7_already_confirmed),
            "reason": api7_reason,
        }
        api7_ssrf_pipeline_trace = self._build_api7_ssrf_pipeline_trace(
            runtime=runtime if isinstance(runtime, dict) else None,
            observations=observations,
            ssrf_candidate_signal_count=ssrf_candidate_signal_count,
            ssrf_ready_checks=ssrf_ready_checks,
            ssrf_blocked_checks=ssrf_blocked_checks,
            ssrf_probe_samples=ssrf_probe_samples,
        )
        if findings_api7 > 0:
            api7_status = "confirmed"
            api7_summary_text = "SSRF подтвержден: целевое приложение выполнило исходящий запрос на контролируемый callback URL."
        elif ssrf_candidate_signal_count > 0 or ssrf_probe_result_count > 0:
            api7_status = "diagnostic"
            api7_summary_text = "Диагностические SSRF-кандидаты обнаружены; подтверждение требует controlled callback proof."
        else:
            api7_status = "not_checked"
            api7_summary_text = "SSRF-сигналы в текущем запуске не зафиксированы."

        evidence_by_id = {
            str(item.get("evidence_id") or ""): item
            for item in evidence
            if isinstance(item, dict) and str(item.get("evidence_id") or "").strip()
        }
        confirmed_ssrf_evidence: list[dict[str, Any]] = []
        confirmed_bola_evidence: list[dict[str, Any]] = []
        for finding in findings:
            if str(finding.get("owasp_category") or "") != "API7_SERVER_SIDE_REQUEST_FORGERY":
                continue
            evidence_id = str(finding.get("evidence_id") or "")
            ev = evidence_by_id.get(evidence_id) or {}
            op_id = str(ev.get("operation_id") or finding.get("operation_id") or "")
            method = str(ev.get("method") or finding.get("method") or "")
            endpoint = str(finding.get("endpoint") or ev.get("endpoint") or ev.get("path") or "")
            field_path = str(ev.get("field_path") or "")
            matched_probe = None
            for row in ssrf_probe_samples:
                if not isinstance(row, dict):
                    continue
                row_op = str(row.get("operation_id") or "")
                row_fp = str(row.get("field_path") or "")
                if op_id and field_path and row_op == op_id and row_fp == field_path:
                    matched_probe = row
                    break
            if matched_probe is None and op_id:
                for row in ssrf_probe_samples:
                    if str(row.get("operation_id") or "") == op_id:
                        matched_probe = row
                        break
            if matched_probe is None:
                matched_probe = next((row for row in ssrf_probe_samples if bool(row.get("callback_received_effective"))), {})
            reason_codes = []
            if isinstance(matched_probe, dict):
                rc = matched_probe.get("reason_codes")
                reason_codes = [str(x) for x in rc[:20]] if isinstance(rc, list) else []
                if not field_path:
                    field_path = str(matched_probe.get("field_path") or "")
                if not op_id:
                    op_id = str(matched_probe.get("operation_id") or "")
                if not method:
                    method = str(matched_probe.get("method") or "")
                if not endpoint:
                    endpoint = str(matched_probe.get("path") or "")
            confirmed_ssrf_evidence.append({
                "finding_id": str(finding.get("finding_id") or ""),
                "evidence_id": evidence_id,
                "operation_id": op_id,
                "method": method,
                "endpoint": endpoint,
                "field_path": field_path,
                "callback_received_effective": bool((matched_probe or {}).get("callback_received_effective")),
                "late_callback_reconciled": bool((matched_probe or {}).get("late_callback_reconciled")),
                "callback_store_received": bool((matched_probe or {}).get("callback_store_received")),
                "evidence_strength": str((matched_probe or {}).get("evidence_strength") or ev.get("severity") or ""),
                "judge_verdict": str(finding.get("judge_verdict") or "confirmed"),
                "reason_codes": reason_codes,
                "vulnerability_class": str(finding.get("vulnerability_class") or ""),
            })
            continue

        for finding in findings:
            if str(finding.get("owasp_category") or "") != "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION":
                continue
            evidence_id = str(finding.get("evidence_id") or "")
            ev = evidence_by_id.get(evidence_id) or {}
            derived = [str(x) for x in (ev.get("derived_signals") or []) if str(x).strip()]
            def _sig(prefix: str) -> str:
                row = next((s for s in derived if s.startswith(prefix)), "")
                return row.split(":", 1)[1].strip() if row else ""
            confirmed_bola_evidence.append({
                "finding_id": str(finding.get("finding_id") or ""),
                "evidence_id": evidence_id,
                "object_pair_id": _sig("object_pair_id:"),
                "operation_id": str(ev.get("operation_id") or finding.get("operation_id") or ""),
                "endpoint": str(finding.get("endpoint") or ev.get("endpoint") or ev.get("path") or ""),
                "method": str(ev.get("method") or finding.get("method") or ""),
                "owner_status_code": self._safe_int(_sig("owner_status_code:"), 0),
                "attacker_status_code": self._safe_int(_sig("attacker_status_code:"), 0),
                "owner_baseline_valid": _sig("owner_baseline_valid:") == "true",
                "attacker_access_granted": (_sig("access_granted:") == "true") or (_sig("result:") == "attacker_access_granted"),
                "replay_classification": _sig("replay_classification:"),
                "evidence_strength": _sig("evidence_strength:"),
                "semantic_id_kind": _sig("semantic_id_kind:"),
                "vulnerability_class": str(finding.get("vulnerability_class") or ""),
                "judge_verdict": str(finding.get("judge_verdict") or "confirmed"),
            })

        return {
            "API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION": {
                "status": "confirmed" if findings_api1 > 0 else "diagnostic",
                "confirmed_findings_count": findings_api1,
                "bola_replay_result_count": self._safe_int(api3_de_cov.get("bola_replay_result_count"), 0),
                "bola_replay_granted_count": self._safe_int(api3_de_cov.get("bola_replay_granted_count"), 0),
                "bola_replay_denied_count": self._safe_int(api3_de_cov.get("bola_replay_denied_count"), 0),
                "bola_replay_invalid_pair_count": self._safe_int(api3_de_cov.get("bola_replay_invalid_pair_count"), 0),
                "bola_replay_inconclusive_count": self._safe_int(api3_de_cov.get("bola_replay_inconclusive_count"), 0),
                "top_object_pair_score": float(api3_de_cov.get("top_object_pair_score") or 0.0),
                "top_object_pair_reasons": list(api3_de_cov.get("top_object_pair_reasons") or []),
                "invalid_pair_rework_count": self._safe_int(api3_de_cov.get("invalid_pair_rework_count"), 0),
                "api1_bola_compact_diagnostics": dict(api3_de_cov.get("api1_bola_compact_diagnostics") or {}),
                "confirmed_bola_evidence": confirmed_bola_evidence[:10],
                "last_invalid_pair_owner_status_code": self._safe_int(api3_de_cov.get("last_invalid_pair_owner_status_code"), 0),
                "last_invalid_pair_semantic_id_kind": str(api3_de_cov.get("last_invalid_pair_semantic_id_kind") or ""),
                "baseline_block_reasons": list(api3_de_cov.get("top_object_pair_reasons") or [])[:20],
            },
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": api7_status,
                "workers": {
                    "ssrf_candidate_detector": {
                        "executed": self._safe_int(executed.get("ssrf_candidate_detector"), 0) if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("ssrf_candidate_detector", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("ssrf_candidate_detector", "not_available" if runtime is None else 0),
                        "ready": self._safe_int(ready_map.get("ssrf_candidate_detector"), 0) if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("ssrf_candidate_detector"), 0) if runtime is not None else "not_available",
                    },
                },
                "confirmed_findings_count": findings_api7,
                "ssrf_candidate_signal_count": ssrf_candidate_signal_count,
                "ssrf_candidate_operations_count": len(ssrf_operations),
                "ssrf_candidate_fields_count": ssrf_fields,
                "ssrf_candidates": ssrf_samples,
                "ssrf_probe_result_count": ssrf_probe_result_count,
                "ssrf_probe_callback_received_count": ssrf_callback_received_count,
                "ssrf_probe_target_non_2xx_count": ssrf_probe_target_non_2xx_count,
                "ssrf_probe_probe_error_count": ssrf_probe_probe_error_count,
                "ssrf_probe_schema_synthesized_count": ssrf_probe_schema_synthesized_count,
                "ssrf_probe_llm_composed_count": ssrf_probe_llm_composed_count,
                "ssrf_probe_late_callback_reconciled_count": ssrf_late_callback_reconciled_count,
                "ssrf_callback_received_count": ssrf_callback_received_count,
                "ssrf_no_callback_count": ssrf_no_callback_count,
                "ssrf_confirmable_count": ssrf_confirmable_count,
                "summary_text": api7_summary_text,
                "confirmed_ssrf_evidence": confirmed_ssrf_evidence[:10],
                "ssrf_probe_results": ssrf_probe_samples,
                "api7_planning_diagnostics": api7_planning_diagnostics,
                "api7_ssrf_pipeline_trace": api7_ssrf_pipeline_trace,
            },
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
                    "checked" if (runtime is not None and (api9_ex > 0 or api9_undoc_ex > 0)) else
                    ("pending" if (runtime is not None and (api9_ready > 0 or api9_undoc_ready > 0)) else "not_available")
                ),
                "workers": {
                    "schemathesis_negative_test": {
                        "executed": api9_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("schemathesis_negative_test", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("schemathesis_negative_test", "not_available" if runtime is None else 0),
                        "ready": api9_ready if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("schemathesis_negative_test"), 0) if runtime is not None else "not_available",
                    },
                    "undocumented_endpoint_validator": {
                        "executed": api9_undoc_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("undocumented_endpoint_validator", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("undocumented_endpoint_validator", "not_available" if runtime is None else 0),
                        "ready": api9_undoc_ready if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("undocumented_endpoint_validator"), 0) if runtime is not None else "not_available",
                    },
                },
                "confirmed_findings_count": findings_api9,
                "schema_mismatch_count": schema_mismatch_count,
                "undocumented_endpoint_signal_count": undocumented_endpoint_signal_count,
                "undocumented_endpoint_findings_count": undocumented_endpoint_findings_count,
                "contract_coverage": {
                    "operations_total": operations_total,
                    "operations_tested": operations_tested,
                },
                **js_cov,
            },
            "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION": {
                "status": "checked" if runtime_effect_proven_count > 0 else "diagnostic",
                "mass_assignment_signal_count": mass_assignment_signal_count,
                "candidates_considered": (
                    api3_ex + api3_ready + (api3_blocked_total if isinstance(api3_blocked_total, int) else 0)
                    + api3_dex_ex + api3_dex_ready + (api3_dex_blocked if isinstance(api3_dex_blocked, int) else 0)
                    if runtime is not None else "not_available"
                ),
                "blocked_no_sensitive_fields_count": blocked_no_sensitive if runtime is not None else "not_available",
                "blocked_missing_seed_context_count": blocked_missing_seed if runtime is not None else "not_available",
                "runtime_effect_proven_count": runtime_effect_proven_count,
                "confirmed_findings_count": findings_api3,
                **api3_de_cov,
                "workers": {
                    "property_mutation_test": {
                        "executed": api3_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("property_mutation_test", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("property_mutation_test", "not_available" if runtime is None else 0),
                        "ready": api3_ready if runtime is not None else "not_available",
                        "blocked": self._safe_int(blocked_map.get("property_mutation_test"), 0) if runtime is not None else "not_available",
                    },
                    "data_exposure_validator": {
                        "executed": api3_dex_ex if runtime is not None else "not_available",
                        "findings": self._safe_int(worker_execution_summary.get("per_kind", {}).get("data_exposure_validator", {}).get("findings_created", 0)),
                        "no_observations": no_obs_by_kind.get("data_exposure_validator", "not_available" if runtime is None else 0),
                        "ready": api3_dex_ready if runtime is not None else "not_available",
                        "blocked": api3_dex_blocked if runtime is not None else "not_available",
                    },
                },
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
            "ssrf_candidate",
            "security_header_misconfiguration",
            "cors_misconfiguration",
            "cookie_flag_misconfiguration",
            "undocumented_api_endpoint",
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
        patterns = ("bearer ", "token=", "authorization:", "set-cookie:", "cookie:", "password=")
        if any(pat in lowered for pat in patterns):
            return "[redacted]"
        return value
