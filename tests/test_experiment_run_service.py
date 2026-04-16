import unittest

from backend.app.services.agent_registry_service import resolve_experiment_enabled_agents
from backend.app.services.experiment_run_service import (
    extract_logical_agent_summary,
    normalize_judge_modes,
)


class ExperimentRunServiceTests(unittest.TestCase):
    def test_normalize_judge_modes_uses_default_matrix(self):
        self.assertEqual(
            normalize_judge_modes(None),
            ["agentic", "dify"],
        )

    def test_normalize_judge_modes_deduplicates_and_filters_invalid_values(self):
        self.assertEqual(
            normalize_judge_modes(["dify", "agentic", "dify", "invalid", "unified"]),
            ["dify", "agentic", "unified"],
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

    def test_resolve_experiment_enabled_agents_supports_logical_ablation(self):
        enabled = resolve_experiment_enabled_agents(
            enabled_logical_agents=["authorization_agent", "exposure_agent"],
            disabled_logical_agents=["exposure_agent"],
        )

        self.assertIn("rule_based_bola_agent", enabled)
        self.assertIn("dify_bola_agent", enabled)
        self.assertNotIn("rule_based_bopla_agent", enabled)
        self.assertNotIn("rule_based_verifier_agent", enabled)


if __name__ == "__main__":
    unittest.main()
