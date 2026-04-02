import unittest

from backend.app.services.experiment_run_service import (
    extract_logical_agent_summary,
    normalize_judge_modes,
)


class ExperimentRunServiceTests(unittest.TestCase):
    def test_normalize_judge_modes_uses_default_matrix(self):
        self.assertEqual(
            normalize_judge_modes(None),
            ["rule_based", "dify", "unified"],
        )

    def test_normalize_judge_modes_deduplicates_and_filters_invalid_values(self):
        self.assertEqual(
            normalize_judge_modes(["dify", "rule_based", "dify", "invalid", "unified"]),
            ["dify", "rule_based", "unified"],
        )

    def test_extract_logical_agent_summary_keeps_only_logical_sections(self):
        summary = extract_logical_agent_summary(
            {
                "logical_agent_activity_summary": {"logical_agents_total": 3},
                "logical_agent_learning_summary": {"logical_agents_total": 2},
                "logical_agent_judge_feedback_summary": {"logical_agents_total": 1},
                "logical_agent_effectiveness_summary": {"logical_agents_total": 3},
                "agent_activity_summary": {"agents_total": 9},
            }
        )

        self.assertEqual(summary["logical_agent_activity_summary"]["logical_agents_total"], 3)
        self.assertEqual(summary["logical_agent_learning_summary"]["logical_agents_total"], 2)
        self.assertEqual(summary["logical_agent_judge_feedback_summary"]["logical_agents_total"], 1)
        self.assertEqual(summary["logical_agent_effectiveness_summary"]["logical_agents_total"], 3)
        self.assertNotIn("agent_activity_summary", summary)


if __name__ == "__main__":
    unittest.main()
