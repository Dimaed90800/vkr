#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Optional


GROUP_KEYS = [
    "findings_total",
    "confirmed_findings",
    "bola_findings",
    "bopla_findings",
    "auth_findings",
    "auth_boundary_signals",
    "confirmed_bola",
    "confirmed_bopla",
    "confirmed_auth_findings",
    "confirmed_auth_boundary_signals",
    "confirmation_rate",
    "fallback_count",
    "avg_score",
    "stability_index",
    "efficiency_index",
    "avg_budget_requests_used",
    "avg_budget_time_used",
    "avg_selected_estimated_cost",
    "requests_per_confirmed_finding",
    "time_per_confirmed_finding",
    "estimated_cost_per_confirmed_finding",
]

AGENT_ORDER = [
    "authentication_agent",
    "authorization_agent",
    "exposure_agent",
]

MODE_ORDER = [
    "rule_based",
    "dify",
    "unified",
]


def _load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _find_latest_job_dir(base_dir: Path) -> Path:
    candidates = [path for path in base_dir.iterdir() if path.is_dir() and path.name.startswith("batch-")]
    if not candidates:
        raise FileNotFoundError(f"No batch job directories found under {base_dir}")
    return max(candidates, key=lambda path: path.stat().st_mtime)


def _find_job_dir_by_session_id(base_dir: Path, session_id: int) -> Optional[Path]:
    for job_dir in sorted(base_dir.iterdir()):
        if not job_dir.is_dir() or not job_dir.name.startswith("batch-"):
            continue
        session_reports_path = job_dir / "session_reports.json"
        if not session_reports_path.exists():
            continue
        try:
            session_reports = _load_json(session_reports_path)
        except Exception:
            continue
        for report in session_reports:
            if report.get("session_id") == session_id:
                return job_dir
    return None


def _resolve_job_dir(job_dir_arg: Optional[str], jobs_root: Path) -> Path:
    if not job_dir_arg:
        return _find_latest_job_dir(jobs_root)

    raw = job_dir_arg.strip()
    as_path = Path(raw)

    if as_path.exists():
        return as_path

    candidate = jobs_root / raw
    if candidate.exists():
        return candidate

    if raw.isdigit():
        resolved = _find_job_dir_by_session_id(jobs_root, int(raw))
        if resolved:
            return resolved
        raise FileNotFoundError(
            f"Could not find a batch job directory in {jobs_root} for session_id={raw}"
        )

    batch_candidate = jobs_root / f"batch-{raw}"
    if batch_candidate.exists():
        return batch_candidate

    raise FileNotFoundError(
        f"Could not resolve job directory from '{raw}'. "
        f"Pass a full path, a batch-* directory name, a bare job id suffix, or a session id."
    )


def _print_group_summary(data):
    print("# Group Summary")
    print()
    rows = sorted(
        data["group_summary"].items(),
        key=lambda item: (
            item[1].get("target_name") or "",
            item[1].get("profile") or "",
            item[1].get("judge_mode") or "",
        ),
    )
    for key, row in rows:
        print(f"[{key}]")
        if row.get("target_name"):
            print(f"target_name: {row.get('target_name')}")
        if row.get("enabled_logical_agents"):
            print(f"enabled_logical_agents: {row.get('enabled_logical_agents')}")
        for field in GROUP_KEYS:
            print(f"{field}: {row.get(field)}")
        print()


def _print_pairwise(data):
    print("# Pairwise Comparisons")
    print()
    for row in data.get("pairwise_profile_comparisons", []):
        print(f"[{row['left_mode']} vs {row['right_mode']}]")
        delta = row.get("delta_right_minus_left", {})
        print(f"delta findings_total: {delta.get('findings_total')}")
        print(f"delta confirmed_findings: {delta.get('confirmed_findings')}")
        print(f"delta avg_score: {delta.get('avg_score')}")
        print(f"delta confirmation_rate: {delta.get('confirmation_rate')}")
        print(f"winner_by_metric: {json.dumps(row.get('winner_by_metric', {}), ensure_ascii=False)}")
        print()


def _print_portability(data):
    print("# Portability Summary")
    print()
    portability = data.get("portability_summary", {})
    print(f"targets_total: {portability.get('targets_total', 0)}")
    print(f"supports_cross_target_comparison: {portability.get('supports_cross_target_comparison', False)}")
    for item in portability.get("targets", []):
        print(
            f"- {item.get('target_name')} ({item.get('target_url')}): "
            f"runs={item.get('runs')}, judge_modes={item.get('judge_modes')}, profiles={item.get('profiles')}"
        )
    print()


def _print_external_baselines(data):
    print("# External Baseline Comparisons")
    print()
    rows = data.get("external_baseline_comparisons", [])
    if not rows:
        print("none")
        print()
        return
    for item in rows:
        print(f"[{item['judge_mode']} vs {item['tool']}]")
        print(json.dumps(item["delta_vs_baseline"], ensure_ascii=False))
        print()


def _print_logical_agents(batch_result):
    print("# Logical Agent Activity")
    print()
    rows = batch_result.get("batch_logical_agent_rows", [])
    for mode in MODE_ORDER:
        print(f"[{mode}]")
        for agent in AGENT_ORDER:
            row = next(
                (
                    item
                    for item in rows
                    if item.get("judge_mode") == mode and item.get("logical_agent_name") == agent
                ),
                None,
            )
            if not row:
                print(f"{agent}: not found")
                continue
            print(
                f"{agent}: "
                f"generated={row.get('generated_hypotheses')}, "
                f"selected={row.get('selected_hypotheses')}, "
                f"confirmed={row.get('confirmed_findings')}"
            )
        print()


def _print_markdown_table(data):
    print("# Markdown Table")
    print()
    header = (
        "| Judge mode | Findings total | Confirmed findings | Confirmed BOLA | "
        "Confirmed BOPLA | Confirmed Auth | Confirmation rate | Fallback count | "
        "Avg score | Stability index | Efficiency index |"
    )
    separator = "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    print(header)
    print(separator)
    rows = sorted(
        data["group_summary"].values(),
        key=lambda row: (
            row.get("target_name") or "",
            row.get("profile") or "",
            MODE_ORDER.index(row.get("judge_mode")) if row.get("judge_mode") in MODE_ORDER else 999,
        ),
    )
    for row in rows:
        mode = row.get("judge_mode", "")
        print(
            "| `{mode}` | {findings_total} | {confirmed_findings} | {confirmed_bola} | "
            "{confirmed_bopla} | {confirmed_auth_findings} | {confirmation_rate} | "
            "{fallback_count} | {avg_score} | {stability_index} | {efficiency_index} |".format(
                mode=mode,
                findings_total=row.get("findings_total", ""),
                confirmed_findings=row.get("confirmed_findings", ""),
                confirmed_bola=row.get("confirmed_bola", ""),
                confirmed_bopla=row.get("confirmed_bopla", ""),
                confirmed_auth_findings=row.get("confirmed_auth_findings", ""),
                confirmation_rate=row.get("confirmation_rate", ""),
                fallback_count=row.get("fallback_count", ""),
                avg_score=row.get("avg_score", ""),
                stability_index=row.get("stability_index", ""),
                efficiency_index=row.get("efficiency_index", ""),
            )
        )
    print()


def main():
    parser = argparse.ArgumentParser(
        description="Extract experiment metrics from a batch job artifact directory."
    )
    parser.add_argument(
        "--job-dir",
        type=str,
        help=(
            "Path to a specific backend/exports/jobs/batch-* directory, "
            "a batch-* directory name, a bare batch id suffix, or a session id"
        ),
    )
    parser.add_argument(
        "--jobs-root",
        type=Path,
        default=Path("backend/exports/jobs"),
        help="Root directory that contains batch-* job folders",
    )
    args = parser.parse_args()

    job_dir = _resolve_job_dir(args.job_dir, args.jobs_root)
    comparison_report = _load_json(job_dir / "comparison_report.json")
    batch_result = _load_json(job_dir / "batch_result.json")

    print(f"# Job Directory: {job_dir}")
    print()
    _print_group_summary(comparison_report)
    _print_markdown_table(comparison_report)
    _print_pairwise(comparison_report)
    _print_portability(comparison_report)
    _print_external_baselines(comparison_report)
    _print_logical_agents(batch_result)


if __name__ == "__main__":
    main()
