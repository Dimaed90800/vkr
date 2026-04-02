def _safe_int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _safe_run_agent_summary(run):
    if isinstance(run, dict):
        return run.get("agent_summary") or {}
    return getattr(run, "agent_summary", None) or {}


def build_experiment_group_summary(runs, by_experiment_id):
    summary = {}
    included_runs = 0

    for run in runs:
        result = by_experiment_id.get(run.id)
        if not result:
            continue

        included_runs += 1
        profile = getattr(run, "profile", "mixed")
        key = f"{run.judge_mode}:{profile}"

        summary.setdefault(key, {
            "judge_mode": run.judge_mode,
            "profile": profile,
            "runs": 0,
            "findings_total": 0,
            "bola_findings": 0,
            "bopla_findings": 0,
            "auth_findings": 0,
            "auth_boundary_signals": 0,
            "confirmed_findings": 0,
            "confirmed_bola": 0,
            "confirmed_bopla": 0,
            "confirmed_auth_findings": 0,
            "confirmed_auth_boundary_signals": 0,
            "judge_decisions": 0,
            "fallback_count": 0,
            "avg_score_sum": 0.0,
        })

        item = summary[key]
        item["runs"] += 1
        item["findings_total"] += _safe_int(result.findings_total)
        item["bola_findings"] += _safe_int(result.bola_findings)
        item["bopla_findings"] += _safe_int(result.bopla_findings)
        item["auth_findings"] += _safe_int(getattr(result, "auth_findings", 0))
        item["auth_boundary_signals"] += _safe_int(getattr(result, "auth_boundary_signals", 0))
        item["confirmed_findings"] += _safe_int(getattr(result, "confirmed_findings", 0))
        item["confirmed_bola"] += _safe_int(getattr(result, "confirmed_bola", 0))
        item["confirmed_bopla"] += _safe_int(getattr(result, "confirmed_bopla", 0))
        item["confirmed_auth_findings"] += _safe_int(getattr(result, "confirmed_auth_findings", 0))
        item["confirmed_auth_boundary_signals"] += _safe_int(getattr(result, "confirmed_auth_boundary_signals", 0))
        item["judge_decisions"] += _safe_int(getattr(result, "judge_decisions", 0))
        item["fallback_count"] += _safe_int(getattr(result, "fallback_count", 0))
        item["avg_score_sum"] += _safe_float(getattr(result, "avg_score", 0))

    for item in summary.values():
        runs_count = item["runs"] or 1
        item["avg_score"] = item["avg_score_sum"] / runs_count
        item["avg_findings_per_run"] = item["findings_total"] / runs_count
        item["avg_confirmed_per_run"] = item["confirmed_findings"] / runs_count
        item["avg_fallbacks_per_run"] = item["fallback_count"] / runs_count
        item["confirmation_rate"] = (
            item["confirmed_findings"] / item["findings_total"]
            if item["findings_total"] else 0.0
        )
        item["stability_index"] = 1.0 / (1.0 + item["avg_fallbacks_per_run"])
        item["efficiency_index"] = (
            item["avg_confirmed_per_run"] / item["avg_fallbacks_per_run"]
            if item["avg_fallbacks_per_run"] > 0 else item["avg_confirmed_per_run"]
        )
        del item["avg_score_sum"]

    return {
        "candidate_runs": len(runs),
        "included_runs": included_runs,
        "by_mode_profile": summary,
    }


def build_logical_agent_group_summary(runs) -> dict:
    summary = {}

    for run in runs:
        agent_summary = _safe_run_agent_summary(run)
        logical_effectiveness = (agent_summary.get("logical_agent_effectiveness_summary") or {}).get("logical_agents", [])
        if not logical_effectiveness:
            continue

        judge_mode = getattr(run, "judge_mode", None) if not isinstance(run, dict) else run.get("judge_mode")
        profile = getattr(run, "profile", "mixed") if not isinstance(run, dict) else run.get("profile", "mixed")
        for item in logical_effectiveness:
            logical_agent_name = item.get("logical_agent_name")
            if not logical_agent_name:
                continue
            key = f"{judge_mode}:{profile}:{logical_agent_name}"
            summary.setdefault(
                key,
                {
                    "judge_mode": judge_mode,
                    "profile": profile,
                    "logical_agent_name": logical_agent_name,
                    "title": item.get("title"),
                    "implementation_scope": item.get("implementation_scope"),
                    "implementation_layers": item.get("implementation_layers", []),
                    "runs": 0,
                    "generated_hypotheses": 0,
                    "selected_hypotheses": 0,
                    "linked_findings": 0,
                    "confirmed_findings": 0,
                    "candidate_findings": 0,
                    "rejected_findings": 0,
                },
            )
            entry = summary[key]
            entry["runs"] += 1
            entry["generated_hypotheses"] += _safe_int(item.get("generated_hypotheses"))
            entry["selected_hypotheses"] += _safe_int(item.get("selected_hypotheses"))
            entry["linked_findings"] += _safe_int(item.get("linked_findings"))
            entry["confirmed_findings"] += _safe_int(item.get("confirmed_findings"))
            entry["candidate_findings"] += _safe_int(item.get("candidate_findings"))
            entry["rejected_findings"] += _safe_int(item.get("rejected_findings"))

    for item in summary.values():
        runs_count = item["runs"] or 1
        generated = item["generated_hypotheses"]
        selected = item["selected_hypotheses"]
        linked_findings = item["linked_findings"]
        item["avg_generated_per_run"] = round(generated / runs_count, 4)
        item["avg_selected_per_run"] = round(selected / runs_count, 4)
        item["avg_confirmed_per_run"] = round(item["confirmed_findings"] / runs_count, 4)
        item["selection_rate"] = round(selected / generated, 4) if generated else 0.0
        item["finding_yield"] = round(linked_findings / selected, 4) if selected else 0.0
        item["confirmation_rate"] = round(item["confirmed_findings"] / linked_findings, 4) if linked_findings else 0.0

    return summary


def build_run_batch_logical_agent_summary(runs) -> dict:
    summary = {}

    for run in runs:
        logical_summary = {}
        if isinstance(run, dict):
            logical_summary = run.get("logical_agent_summary") or {}
        logical_effectiveness = (logical_summary.get("logical_agent_effectiveness_summary") or {}).get("logical_agents", [])
        if not logical_effectiveness:
            continue

        judge_mode = run.get("judge_mode") if isinstance(run, dict) else getattr(run, "judge_mode", None)
        profile = run.get("profile", "mixed") if isinstance(run, dict) else getattr(run, "profile", "mixed")
        for item in logical_effectiveness:
            logical_agent_name = item.get("logical_agent_name")
            if not logical_agent_name:
                continue

            key = f"{judge_mode}:{profile}:{logical_agent_name}"
            summary.setdefault(
                key,
                {
                    "judge_mode": judge_mode,
                    "profile": profile,
                    "logical_agent_name": logical_agent_name,
                    "title": item.get("title"),
                    "implementation_scope": item.get("implementation_scope"),
                    "implementation_layers": item.get("implementation_layers", []),
                    "runs": 0,
                    "generated_hypotheses": 0,
                    "selected_hypotheses": 0,
                    "linked_findings": 0,
                    "confirmed_findings": 0,
                    "candidate_findings": 0,
                    "rejected_findings": 0,
                },
            )
            entry = summary[key]
            entry["runs"] += 1
            entry["generated_hypotheses"] += _safe_int(item.get("generated_hypotheses"))
            entry["selected_hypotheses"] += _safe_int(item.get("selected_hypotheses"))
            entry["linked_findings"] += _safe_int(item.get("linked_findings"))
            entry["confirmed_findings"] += _safe_int(item.get("confirmed_findings"))
            entry["candidate_findings"] += _safe_int(item.get("candidate_findings"))
            entry["rejected_findings"] += _safe_int(item.get("rejected_findings"))

    for item in summary.values():
        runs_count = item["runs"] or 1
        generated = item["generated_hypotheses"]
        selected = item["selected_hypotheses"]
        linked_findings = item["linked_findings"]
        item["avg_generated_per_run"] = round(generated / runs_count, 4)
        item["avg_selected_per_run"] = round(selected / runs_count, 4)
        item["avg_confirmed_per_run"] = round(item["confirmed_findings"] / runs_count, 4)
        item["selection_rate"] = round(selected / generated, 4) if generated else 0.0
        item["finding_yield"] = round(linked_findings / selected, 4) if selected else 0.0
        item["confirmation_rate"] = round(item["confirmed_findings"] / linked_findings, 4) if linked_findings else 0.0

    return summary


def build_run_batch_logical_agent_rows(runs) -> list[dict]:
    summary = build_run_batch_logical_agent_summary(runs)
    return sorted(
        summary.values(),
        key=lambda item: (item["profile"], item["judge_mode"], item["logical_agent_name"]),
    )


def _winner_label(rule_value, dify_value, *, lower_is_better=False) -> str:
    if rule_value == dify_value:
        return "tie"
    if lower_is_better:
        return "rule_based" if rule_value < dify_value else "dify"
    return "rule_based" if rule_value > dify_value else "dify"


def _comparison_metrics(left: dict, right: dict) -> dict:
    return {
        "findings_total": right["findings_total"] - left["findings_total"],
        "confirmed_findings": right["confirmed_findings"] - left["confirmed_findings"],
        "bola_findings": right["bola_findings"] - left["bola_findings"],
        "bopla_findings": right["bopla_findings"] - left["bopla_findings"],
        "auth_findings": right.get("auth_findings", 0) - left.get("auth_findings", 0),
        "confirmed_auth_findings": right.get("confirmed_auth_findings", 0) - left.get("confirmed_auth_findings", 0),
        "fallback_count": right["fallback_count"] - left["fallback_count"],
        "avg_score": round(right["avg_score"] - left["avg_score"], 4),
        "confirmation_rate": round(right["confirmation_rate"] - left["confirmation_rate"], 4),
        "stability_index": round(right["stability_index"] - left["stability_index"], 4),
        "efficiency_index": round(right["efficiency_index"] - left["efficiency_index"], 4),
    }


def _winner_by_metric(left_mode: str, left: dict, right_mode: str, right: dict) -> dict:
    def _label(left_value, right_value, *, lower_is_better=False):
        if left_value == right_value:
            return "tie"
        if lower_is_better:
            return left_mode if left_value < right_value else right_mode
        return left_mode if left_value > right_value else right_mode

    return {
        "findings_total": _label(left["findings_total"], right["findings_total"]),
        "confirmed_findings": _label(left["confirmed_findings"], right["confirmed_findings"]),
        "bola_findings": _label(left["bola_findings"], right["bola_findings"]),
        "bopla_findings": _label(left["bopla_findings"], right["bopla_findings"]),
        "auth_findings": _label(left.get("auth_findings", 0), right.get("auth_findings", 0)),
        "confirmed_auth_findings": _label(left.get("confirmed_auth_findings", 0), right.get("confirmed_auth_findings", 0)),
        "fallback_count": _label(left["fallback_count"], right["fallback_count"], lower_is_better=True),
        "avg_score": _label(left["avg_score"], right["avg_score"]),
        "confirmation_rate": _label(left["confirmation_rate"], right["confirmation_rate"]),
        "stability_index": _label(left["stability_index"], right["stability_index"]),
        "efficiency_index": _label(left["efficiency_index"], right["efficiency_index"]),
    }


def _build_pairwise_profile_comparisons(by_mode_profile: dict) -> list[dict]:
    profiles = sorted({item["profile"] for item in by_mode_profile.values()})
    comparisons = []
    canonical_pairs = [
        ("rule_based", "dify"),
        ("rule_based", "unified"),
        ("dify", "unified"),
    ]

    for profile in profiles:
        for left_mode, right_mode in canonical_pairs:
            left = by_mode_profile.get(f"{left_mode}:{profile}")
            right = by_mode_profile.get(f"{right_mode}:{profile}")
            if not left or not right:
                continue

            comparisons.append(
                {
                    "profile": profile,
                    "left_mode": left_mode,
                    "right_mode": right_mode,
                    "left": left,
                    "right": right,
                    "delta_right_minus_left": _comparison_metrics(left, right),
                    "winner_by_metric": _winner_by_metric(left_mode, left, right_mode, right),
                }
            )

    return comparisons


def build_experiment_comparison_report(*, runs, by_experiment_id, filters: dict):
    grouped = build_experiment_group_summary(runs, by_experiment_id)
    by_mode_profile = grouped["by_mode_profile"]
    logical_agent_group_summary = build_logical_agent_group_summary(runs)
    pairwise_profile_comparisons = _build_pairwise_profile_comparisons(by_mode_profile)
    profile_comparisons = [
        {
            "profile": item["profile"],
            "rule_based": item["left"],
            "dify": item["right"],
            "delta_dify_minus_rule_based": item["delta_right_minus_left"],
            "winner_by_metric": item["winner_by_metric"],
        }
        for item in pairwise_profile_comparisons
        if item["left_mode"] == "rule_based" and item["right_mode"] == "dify"
    ]

    headline_parts = []
    for item in pairwise_profile_comparisons:
        winner = item["winner_by_metric"]["confirmed_findings"]
        stability_winner = item["winner_by_metric"]["stability_index"]
        left_mode = item["left_mode"]
        right_mode = item["right_mode"]
        if winner == "tie":
            sentence = (
                f"Для профиля '{item['profile']}' режимы `{left_mode}` и `{right_mode}` показали сопоставимое число подтверждённых находок."
            )
        elif winner == right_mode:
            sentence = (
                f"Для профиля '{item['profile']}' режим `{right_mode}` дал больше подтверждённых находок, чем `{left_mode}`."
            )
        else:
            sentence = (
                f"Для профиля '{item['profile']}' режим `{left_mode}` дал больше подтверждённых находок, чем `{right_mode}`."
            )
        if stability_winner == "tie":
            sentence += " По устойчивости режимы оказались сопоставимы."
        elif stability_winner == right_mode:
            sentence += f" При этом `{right_mode}` показал лучшую устойчивость."
        else:
            sentence += f" При этом `{left_mode}` показал лучшую устойчивость."
        headline_parts.append(sentence)

    if not headline_parts:
        headline_parts.append(
            "Недостаточно данных для прямого сравнения judge-режимов в одних и тех же профилях."
        )

    return {
        "filters": filters,
        "totals": {
            "candidate_runs": grouped["candidate_runs"],
            "included_runs": grouped["included_runs"],
            "profiles_compared": len(profile_comparisons),
            "pairwise_comparisons": len(pairwise_profile_comparisons),
        },
        "group_summary": by_mode_profile,
        "logical_agent_group_summary": logical_agent_group_summary,
        "profile_comparisons": profile_comparisons,
        "pairwise_profile_comparisons": pairwise_profile_comparisons,
        "executive_summary": {
            "headline": "Сравнение judge-режимов для дипломной практики",
            "message": " ".join(headline_parts),
        },
    }


def build_experiment_comparison_markdown(report: dict) -> str:
    lines = [
        "# Experiment Comparison Report",
        "",
        f"- Candidate runs: {report['totals']['candidate_runs']}",
        f"- Included runs: {report['totals']['included_runs']}",
        f"- Profiles compared: {report['totals']['profiles_compared']}",
        "",
        "## Executive Summary",
        "",
        report["executive_summary"]["message"],
        "",
        "## Group Summary",
        "",
    ]

    if not report["group_summary"]:
        lines.extend(["No grouped experiment data available.", ""])
    else:
        for item in sorted(report["group_summary"].values(), key=lambda x: (x["profile"], x["judge_mode"])):
            lines.extend([
                f"### {item['judge_mode']} / {item['profile']}",
                "",
                f"- Runs: {item['runs']}",
                f"- Total findings: {item['findings_total']}",
                f"- Confirmed findings: {item['confirmed_findings']}",
                f"- BOLA findings: {item['bola_findings']}",
                f"- BOPLA findings: {item['bopla_findings']}",
                f"- Fallback count: {item['fallback_count']}",
                f"- Avg score: {item['avg_score']:.4f}",
                f"- Avg findings per run: {item['avg_findings_per_run']:.2f}",
                f"- Avg confirmed per run: {item['avg_confirmed_per_run']:.2f}",
                f"- Confirmation rate: {item['confirmation_rate']:.2%}",
                f"- Stability index: {item['stability_index']:.4f}",
                f"- Efficiency index: {item['efficiency_index']:.4f}",
                "",
            ])

    lines.extend(["## Pairwise Profile Comparisons", ""])
    if not report.get("pairwise_profile_comparisons"):
        lines.extend(["No direct pairwise judge-mode comparisons available.", ""])
    else:
        for item in report["pairwise_profile_comparisons"]:
            delta = item["delta_right_minus_left"]
            left_mode = item["left_mode"]
            right_mode = item["right_mode"]
            lines.extend([
                f"### Profile: {item['profile']} ({left_mode} vs {right_mode})",
                "",
                f"- Confirmed findings delta ({right_mode} - {left_mode}): {delta['confirmed_findings']}",
                f"- Total findings delta ({right_mode} - {left_mode}): {delta['findings_total']}",
                f"- BOLA delta ({right_mode} - {left_mode}): {delta['bola_findings']}",
                f"- BOPLA delta ({right_mode} - {left_mode}): {delta['bopla_findings']}",
                f"- Fallback delta ({right_mode} - {left_mode}): {delta['fallback_count']}",
                f"- Avg score delta ({right_mode} - {left_mode}): {delta['avg_score']:.4f}",
                f"- Confirmation rate delta ({right_mode} - {left_mode}): {delta['confirmation_rate']:.4f}",
                f"- Stability index delta ({right_mode} - {left_mode}): {delta['stability_index']:.4f}",
                f"- Efficiency index delta ({right_mode} - {left_mode}): {delta['efficiency_index']:.4f}",
                f"- Winner by confirmed findings: {item['winner_by_metric']['confirmed_findings']}",
                f"- Winner by fallback count: {item['winner_by_metric']['fallback_count']}",
                f"- Winner by stability index: {item['winner_by_metric']['stability_index']}",
                f"- Winner by efficiency index: {item['winner_by_metric']['efficiency_index']}",
                "",
            ])

    lines.extend(["## Logical Agent Summary", ""])
    if not report.get("logical_agent_group_summary"):
        lines.extend(["No logical-agent experiment data available.", ""])
    else:
        for item in sorted(
            report["logical_agent_group_summary"].values(),
            key=lambda x: (x["profile"], x["judge_mode"], x["logical_agent_name"]),
        ):
            lines.extend([
                f"### {item['judge_mode']} / {item['profile']} / {item['logical_agent_name']}",
                "",
                f"- Runs: {item['runs']}",
                f"- Generated hypotheses: {item['generated_hypotheses']}",
                f"- Selected hypotheses: {item['selected_hypotheses']}",
                f"- Linked findings: {item['linked_findings']}",
                f"- Confirmed findings: {item['confirmed_findings']}",
                f"- Avg generated per run: {item['avg_generated_per_run']:.2f}",
                f"- Avg selected per run: {item['avg_selected_per_run']:.2f}",
                f"- Avg confirmed per run: {item['avg_confirmed_per_run']:.2f}",
                f"- Selection rate: {item['selection_rate']:.4f}",
                f"- Finding yield: {item['finding_yield']:.4f}",
                f"- Confirmation rate: {item['confirmation_rate']:.4f}",
                "",
            ])

    return "\n".join(lines)
