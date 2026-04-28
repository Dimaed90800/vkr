"""Write sanitized report artifacts to disk for a campaign."""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

try:
    from backend.services.report_context_builder import ReportContextBuilder
except ModuleNotFoundError:  # pragma: no cover
    from services.report_context_builder import ReportContextBuilder


class ReportArtifactWriter:
    def __init__(self, root_dir: str | Path = ".") -> None:
        self._root_dir = Path(root_dir)
        self._builder = ReportContextBuilder()

    def write(self, campaign_id: str, runtime_state_snapshot: dict[str, Any] | None = None) -> dict[str, Any]:
        context, error = self._builder.build(
            campaign_id=campaign_id,
            runtime_state_snapshot=runtime_state_snapshot,
        )
        if error:
            return {"error": error}
        assert isinstance(context, dict)

        reports_dir = self._root_dir / "logs" / "dast_runs" / campaign_id / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        full_path = reports_dir / "report_full.md"
        confirmed_path = reports_dir / "report_confirmed_findings.md"
        context_path = reports_dir / "report_context_sanitized.json"

        full_md = self._render_full_report(context)
        confirmed_md = self._render_confirmed_only_report(context)

        full_path.write_text(full_md, encoding="utf-8")
        confirmed_path.write_text(confirmed_md, encoding="utf-8")
        context_path.write_text(json.dumps(context, ensure_ascii=False, indent=2), encoding="utf-8")

        return {
            "campaign_id": campaign_id,
            "reports_dir": str(reports_dir),
            "paths": {
                "report_full_md": str(full_path),
                "report_confirmed_findings_md": str(confirmed_path),
                "report_context_sanitized_json": str(context_path),
            },
            "summary": {
                "confirmed_findings_count": len(context.get("confirmed_findings") or []),
                "pending_verification_count": len(context.get("pending_verification") or []),
                "tool_failures_count": len(context.get("tool_failures") or []),
            },
        }

    def _render_confirmed_only_report(self, context: dict[str, Any]) -> str:
        campaign = context.get("campaign") if isinstance(context.get("campaign"), dict) else {}
        findings = context.get("confirmed_findings") if isinstance(context.get("confirmed_findings"), list) else []

        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in findings:
            if isinstance(item, dict):
                grouped[str(item.get("vulnerability_class") or "not_available")].append(item)

        lines = [
            "# Confirmed Findings Report",
            "",
            "## Scope",
            f"- campaign_id: {campaign.get('campaign_id', '')}",
            f"- target_url: {campaign.get('target_url', 'not_available')}",
            f"- profile: {campaign.get('profile', 'not_available')}",
            "",
            f"confirmed_findings_count: {len(findings)}",
            "",
            "## Grouped Findings By Vulnerability Class",
        ]
        if not grouped:
            lines.append("- none")
        for vuln_class, items in sorted(grouped.items(), key=lambda x: x[0]):
            lines.append(f"### {vuln_class}")
            lines.append("| endpoint | method | finding_id | evidence_id | recommendation |")
            lines.append("|---|---|---|---|---|")
            for finding in items:
                lines.append(
                    "| {endpoint} | {method} | {fid} | {eid} | {rec} |".format(
                        endpoint=str(finding.get("endpoint") or "not_available"),
                        method=str(finding.get("method") or "not_available"),
                        fid=str(finding.get("finding_id") or "not_available"),
                        eid=str(finding.get("evidence_id") or "not_available"),
                        rec=str(finding.get("recommendation") or "not_available"),
                    )
                )
            lines.append("")

        lines.extend(
            [
                "## Affected Endpoints",
                "| endpoint | method | vulnerability_class |",
                "|---|---|---|",
            ]
        )
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            lines.append(
                "| {endpoint} | {method} | {vuln} |".format(
                    endpoint=str(finding.get("endpoint") or "not_available"),
                    method=str(finding.get("method") or "not_available"),
                    vuln=str(finding.get("vulnerability_class") or "not_available"),
                )
            )
        if not findings:
            lines.append("| not_available | not_available | not_available |")

        lines.extend(["", "## Evidence IDs"])
        if findings:
            for finding in findings:
                if not isinstance(finding, dict):
                    continue
                lines.append(f"- {str(finding.get('evidence_id') or 'not_available')}")
        else:
            lines.append("- none")

        lines.extend(["", "## Recommendations"])
        rec_seen: set[str] = set()
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            rec = str(finding.get("recommendation") or "").strip()
            if rec and rec not in rec_seen:
                rec_seen.add(rec)
                lines.append(f"- {rec}")
        if not rec_seen:
            lines.append("- none")
        return "\n".join(lines).strip() + "\n"

    def _render_full_report(self, context: dict[str, Any]) -> str:
        campaign = context.get("campaign") if isinstance(context.get("campaign"), dict) else {}
        exec_summary = context.get("executive_summary") if isinstance(context.get("executive_summary"), dict) else {}
        lines = [
            "# Full Sanitized Report",
            "",
            "## Scope",
            f"- campaign_id: {campaign.get('campaign_id', '')}",
            f"- target_url: {campaign.get('target_url', 'not_available')}",
            f"- openapi_url: {campaign.get('openapi_url', 'not_available')}",
            f"- profile: {campaign.get('profile', 'not_available')}",
            "",
            "## Executive Summary",
            f"- confirmed_findings_count: {exec_summary.get('confirmed_findings_count', 0)}",
            f"- pending_verification_count: {exec_summary.get('pending_verification_count', 0)}",
            f"- iterations_run: {exec_summary.get('iterations_run', 'not_available')}",
            f"- max_iterations: {exec_summary.get('max_iterations', 'not_available')}",
            f"- tool_failures_count: {exec_summary.get('tool_failures_count', 'not_available')}",
            "",
            "## Worker Execution Summary",
            "```json",
            json.dumps(context.get("worker_execution_summary") or {}, ensure_ascii=False, indent=2),
            "```",
            "",
            "## Tool Failures",
            "```json",
            json.dumps(context.get("tool_failures") or [], ensure_ascii=False, indent=2),
            "```",
            "",
            "## Blocked Checks",
            "```json",
            json.dumps(context.get("blocked_checks") or [], ensure_ascii=False, indent=2),
            "```",
            "",
            "## Pending Verification",
            "```json",
            json.dumps(context.get("pending_verification") or [], ensure_ascii=False, indent=2),
            "```",
            "",
            "## OWASP Coverage (API3/API7/API8/API9)",
            "```json",
            json.dumps(
                {
                    "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION": (context.get("owasp_coverage") or {}).get(
                        "API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION", {}
                    ),
                    "API7_SERVER_SIDE_REQUEST_FORGERY": (context.get("owasp_coverage") or {}).get(
                        "API7_SERVER_SIDE_REQUEST_FORGERY", {}
                    ),
                    "API8_SECURITY_MISCONFIGURATION": (context.get("owasp_coverage") or {}).get(
                        "API8_SECURITY_MISCONFIGURATION", {}
                    ),
                    "API9_IMPROPER_INVENTORY_MANAGEMENT": (context.get("owasp_coverage") or {}).get(
                        "API9_IMPROPER_INVENTORY_MANAGEMENT", {}
                    ),
                },
                ensure_ascii=False,
                indent=2,
            ),
            "```",
            "",
            "## Auth / Resource Extraction Diagnostics",
            "```json",
            json.dumps(context.get("auth_flow_diagnostics") or {}, ensure_ascii=False, indent=2),
            "```",
        ]
        return "\n".join(lines).strip() + "\n"
