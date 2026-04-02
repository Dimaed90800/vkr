import unittest
from types import SimpleNamespace

from backend.app.services.experiment_report_service import (
    build_experiment_comparison_report,
    build_run_batch_logical_agent_rows,
    build_run_batch_logical_agent_summary,
)


class ExperimentReportServiceTests(unittest.TestCase):
    def test_report_includes_stability_and_efficiency_winners(self):
        runs = [
            SimpleNamespace(id=1, judge_mode="rule_based", profile="mixed"),
            SimpleNamespace(id=2, judge_mode="dify", profile="mixed"),
        ]
        by_experiment_id = {
            1: SimpleNamespace(
                findings_total=4,
                bola_findings=3,
                bopla_findings=1,
                auth_findings=0,
                auth_boundary_signals=0,
                confirmed_findings=2,
                confirmed_bola=1,
                confirmed_bopla=1,
                confirmed_auth_findings=0,
                confirmed_auth_boundary_signals=0,
                judge_decisions=10,
                fallback_count=0,
                avg_score=0.8,
            ),
            2: SimpleNamespace(
                findings_total=5,
                bola_findings=4,
                bopla_findings=1,
                auth_findings=2,
                auth_boundary_signals=2,
                confirmed_findings=3,
                confirmed_bola=2,
                confirmed_bopla=1,
                confirmed_auth_findings=1,
                confirmed_auth_boundary_signals=1,
                judge_decisions=10,
                fallback_count=6,
                avg_score=0.75,
            ),
        }

        report = build_experiment_comparison_report(
            runs=runs,
            by_experiment_id=by_experiment_id,
            filters={"target_name": "crapi"},
        )

        self.assertEqual(report["totals"]["profiles_compared"], 1)
        comparison = report["profile_comparisons"][0]
        self.assertIn("stability_index", comparison["delta_dify_minus_rule_based"])
        self.assertIn("efficiency_index", comparison["delta_dify_minus_rule_based"])
        self.assertEqual(comparison["delta_dify_minus_rule_based"]["auth_findings"], 2)
        self.assertEqual(comparison["winner_by_metric"]["auth_findings"], "dify")
        self.assertEqual(comparison["winner_by_metric"]["confirmed_findings"], "dify")
        self.assertEqual(comparison["winner_by_metric"]["stability_index"], "rule_based")
        self.assertEqual(comparison["winner_by_metric"]["efficiency_index"], "rule_based")

    def test_report_includes_unified_pairwise_comparisons(self):
        runs = [
            SimpleNamespace(id=1, judge_mode="rule_based", profile="mixed"),
            SimpleNamespace(id=2, judge_mode="dify", profile="mixed"),
            SimpleNamespace(id=3, judge_mode="unified", profile="mixed"),
        ]
        by_experiment_id = {
            1: SimpleNamespace(
                findings_total=4,
                bola_findings=2,
                bopla_findings=2,
                confirmed_findings=2,
                confirmed_bola=1,
                confirmed_bopla=1,
                judge_decisions=10,
                fallback_count=1,
                avg_score=0.72,
            ),
            2: SimpleNamespace(
                findings_total=5,
                bola_findings=3,
                bopla_findings=2,
                confirmed_findings=3,
                confirmed_bola=2,
                confirmed_bopla=1,
                judge_decisions=10,
                fallback_count=4,
                avg_score=0.77,
            ),
            3: SimpleNamespace(
                findings_total=6,
                bola_findings=3,
                bopla_findings=3,
                confirmed_findings=4,
                confirmed_bola=2,
                confirmed_bopla=2,
                judge_decisions=10,
                fallback_count=2,
                avg_score=0.81,
            ),
        }

        report = build_experiment_comparison_report(
            runs=runs,
            by_experiment_id=by_experiment_id,
            filters={"target_name": "crapi"},
        )

        self.assertEqual(report["totals"]["profiles_compared"], 1)
        self.assertEqual(report["totals"]["pairwise_comparisons"], 3)
        pairwise = report["pairwise_profile_comparisons"]
        self.assertEqual(len(pairwise), 3)
        self.assertTrue(
            any(
                item["left_mode"] == "rule_based" and item["right_mode"] == "unified"
                for item in pairwise
            )
        )
        self.assertTrue(
            any(
                item["left_mode"] == "dify" and item["right_mode"] == "unified"
                for item in pairwise
            )
        )
        self.assertIn("unified", report["executive_summary"]["message"])

    def test_report_includes_logical_agent_group_summary(self):
        runs = [
            SimpleNamespace(
                id=1,
                judge_mode="unified",
                profile="mixed",
                agent_summary={
                    "logical_agent_effectiveness_summary": {
                        "logical_agents": [
                            {
                                "logical_agent_name": "authorization_agent",
                                "title": "Authorization Agent",
                                "generated_hypotheses": 10,
                                "selected_hypotheses": 6,
                                "linked_findings": 4,
                                "confirmed_findings": 3,
                                "candidate_findings": 1,
                                "rejected_findings": 0,
                            }
                        ]
                    }
                },
            )
        ]
        by_experiment_id = {
            1: SimpleNamespace(
                findings_total=4,
                bola_findings=4,
                bopla_findings=0,
                confirmed_findings=3,
                confirmed_bola=3,
                confirmed_bopla=0,
                judge_decisions=10,
                fallback_count=1,
                avg_score=0.81,
            ),
        }

        report = build_experiment_comparison_report(
            runs=runs,
            by_experiment_id=by_experiment_id,
            filters={"target_name": "crapi"},
        )

        logical_summary = report["logical_agent_group_summary"]
        self.assertIn("unified:mixed:authorization_agent", logical_summary)
        item = logical_summary["unified:mixed:authorization_agent"]
        self.assertEqual(item["generated_hypotheses"], 10)
        self.assertEqual(item["selected_hypotheses"], 6)
        self.assertEqual(item["confirmed_findings"], 3)

    def test_run_batch_logical_agent_summary_uses_live_run_payload(self):
        runs = [
            {
                "judge_mode": "unified",
                "profile": "mixed",
                "logical_agent_summary": {
                    "logical_agent_effectiveness_summary": {
                        "logical_agents": [
                            {
                                "logical_agent_name": "authorization_agent",
                                "title": "Authorization Agent",
                                "generated_hypotheses": 12,
                                "selected_hypotheses": 7,
                                "linked_findings": 5,
                                "confirmed_findings": 4,
                                "candidate_findings": 1,
                                "rejected_findings": 0,
                            }
                        ]
                    }
                },
            }
        ]

        summary = build_run_batch_logical_agent_summary(runs)
        self.assertIn("unified:mixed:authorization_agent", summary)
        item = summary["unified:mixed:authorization_agent"]
        self.assertEqual(item["generated_hypotheses"], 12)
        self.assertEqual(item["selected_hypotheses"], 7)
        self.assertEqual(item["confirmed_findings"], 4)

    def test_run_batch_logical_agent_rows_are_sorted_and_flat(self):
        runs = [
            {
                "judge_mode": "unified",
                "profile": "mixed",
                "logical_agent_summary": {
                    "logical_agent_effectiveness_summary": {
                        "logical_agents": [
                            {
                                "logical_agent_name": "authorization_agent",
                                "title": "Authorization Agent",
                                "generated_hypotheses": 12,
                                "selected_hypotheses": 7,
                                "linked_findings": 5,
                                "confirmed_findings": 4,
                                "candidate_findings": 1,
                                "rejected_findings": 0,
                            }
                        ]
                    }
                },
            }
        ]

        rows = build_run_batch_logical_agent_rows(runs)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["logical_agent_name"], "authorization_agent")
        self.assertEqual(rows[0]["judge_mode"], "unified")
        self.assertEqual(rows[0]["confirmed_findings"], 4)


if __name__ == "__main__":
    unittest.main()
