from __future__ import annotations

from pathlib import Path
from typing import Any

from .dify_service import call_dify_report_agent
from .report_service import build_final_session_report


_REMEDIATION_BY_FINDING_TYPE = {
    "possible_bola": [
        "Проверить объектное разграничение доступа на сервере, а не только на клиенте.",
        "Связать каждый доступ к объекту с владельцем, ролью или ACL-политикой.",
        "Добавить негативные автотесты для cross-role и cross-tenant доступа.",
    ],
    "possible_bopla": [
        "Минимизировать поля ответа по принципу least privilege и explicit allow-list.",
        "Разделить DTO/serializer для разных ролей и сценариев API.",
        "Добавить проверку чувствительных полей в regression-тесты API.",
    ],
    "possible_authentication_bypass": [
        "Проверить, что middleware аутентификации применяется ко всем защищённым маршрутам.",
        "Запретить доступ к high-value endpoint без валидного bearer token.",
        "Добавить автотесты на anonymous, invalid-token и expired-token сценарии.",
    ],
    "auth_boundary_signal": [
        "Проверить конфигурацию маршрута и ожидаемое поведение для anonymous/invalid-token запросов.",
        "Убедиться, что коды 404/405 не скрывают ошибочную конфигурацию авторизации.",
        "Провести ручную проверку соседних методов и маршрутов того же ресурса.",
    ],
}


def _render_local_report(final_report: dict[str, Any]) -> str:
    session = final_report["session"]
    executive_summary = final_report["executive_summary"]
    risk_summary = final_report["risk_summary"]
    top_findings = final_report.get("top_findings", [])

    lines = [
        f"# Security Report for {session['target_name']}",
        "",
        f"Target: {session['target_url']}",
        f"Risk level: {executive_summary['risk_level']}",
        "",
        "## Executive Summary",
        "",
        executive_summary["headline"],
        executive_summary["message"],
        "",
        "## Quantitative Summary",
        "",
        f"- Total findings: {risk_summary['total_findings']}",
        f"- Confirmed findings: {risk_summary['confirmed_findings']}",
        f"- Candidate findings: {risk_summary['candidate_findings']}",
        f"- BOLA findings: {risk_summary['bola_findings']}",
        f"- BOPLA findings: {risk_summary['bopla_findings']}",
        "",
        "## Findings and Recommendations",
        "",
    ]

    if not top_findings:
        lines.extend(
            [
                "Существенных находок не зафиксировано. Рекомендуется расширить тестовое покрытие и перепроверить высокоценные маршруты вручную.",
                "",
            ]
        )
    else:
        for finding in top_findings:
            recommendations = _REMEDIATION_BY_FINDING_TYPE.get(finding["type"], [])
            lines.extend(
                [
                    f"### {finding['title'] or finding['type']}",
                    "",
                    f"- Type: {finding['type']}",
                    f"- Severity: {finding['severity']}",
                    f"- Endpoint: {finding['endpoint']}",
                    f"- Verification status: {finding['verification_status']}",
                    f"- Description: {finding['description']}",
                    "",
                    "Recommended remediation:",
                ]
            )
            if recommendations:
                for item in recommendations:
                    lines.append(f"- {item}")
            else:
                lines.append("- Провести дополнительный анализ и подготовить точечные защитные проверки для этого сценария.")
            lines.append("")

    lines.extend(
        [
            "## Narrative",
            "",
            final_report["summary_text"],
            "",
            "## Key Conclusion",
            "",
            final_report["key_conclusion"]["message"],
            "",
        ]
    )

    return "\n".join(lines).strip()


def _get_reports_export_dir(export_root: Path | None = None) -> Path:
    if export_root is not None:
        return export_root
    return Path("/app/exports/reports")


def _save_report_text(*, session_id: int, report_text: str, export_root: Path | None = None) -> str:
    export_dir = _get_reports_export_dir(export_root)
    export_dir.mkdir(parents=True, exist_ok=True)
    report_path = export_dir / f"session_{session_id}_llm_report.md"
    report_path.write_text(report_text, encoding="utf-8")
    return str(report_path)


def build_session_llm_report(
    *,
    session_obj,
    roles,
    findings,
    judge_decisions,
    observations,
    hypotheses=None,
    agent_memory_rows=None,
    agent_judge_feedback_rows=None,
    export_root: Path | None = None,
) -> dict[str, Any]:
    final_report = build_final_session_report(
        session_obj=session_obj,
        roles=roles,
        findings=findings,
        judge_decisions=judge_decisions,
        observations=observations,
        hypotheses=hypotheses,
        agent_memory_rows=agent_memory_rows,
        agent_judge_feedback_rows=agent_judge_feedback_rows,
    )

    fallback_report = _render_local_report(final_report)

    try:
        llm_result = call_dify_report_agent(
            session_id=session_obj.id,
            target_name=session_obj.target_name,
            target_url=session_obj.target_url,
            executive_summary=final_report["executive_summary"],
            risk_summary=final_report["risk_summary"],
            key_conclusion=final_report["key_conclusion"],
            top_findings=final_report["top_findings"],
        )
        saved_report_path = _save_report_text(
            session_id=session_obj.id,
            report_text=llm_result["report_text"],
            export_root=export_root,
        )
        return {
            "provider": llm_result.get("provider", "dify"),
            "used_fallback": False,
            "report_text": llm_result["report_text"],
            "fallback_report_text": fallback_report,
            "saved_report_path": saved_report_path,
        }
    except Exception as exc:
        saved_report_path = _save_report_text(
            session_id=session_obj.id,
            report_text=fallback_report,
            export_root=export_root,
        )
        return {
            "provider": "local_fallback",
            "used_fallback": True,
            "error": str(exc),
            "report_text": fallback_report,
            "saved_report_path": saved_report_path,
        }
