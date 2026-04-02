import json
import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.services.agent_judge_feedback_service import (
    apply_judge_feedback_to_hypotheses,
    build_agent_judge_feedback_index,
    compute_judge_feedback_adjustment,
)
from backend.app.services.judge_service import serialize_hypothesis


class AgentJudgeFeedbackIntegrationTests(unittest.TestCase):
    def test_feedback_index_aggregates_by_agent_and_type(self):
        rows = [
            SimpleNamespace(agent_name="dify_bopla_agent", hypothesis_type="bopla_probe", was_selected=1),
            SimpleNamespace(agent_name="dify_bopla_agent", hypothesis_type="bopla_probe", was_selected=0),
            SimpleNamespace(agent_name="rule_based_probe_agent", hypothesis_type="authenticated_probe", was_selected=0),
        ]

        index = build_agent_judge_feedback_index(rows)

        self.assertEqual(index[("dify_bopla_agent", "bopla_probe")]["proposals_seen_by_judge"], 2)
        self.assertEqual(index[("dify_bopla_agent", "bopla_probe")]["selected_by_judge"], 1)
        self.assertEqual(index[("dify_bopla_agent", "bopla_probe")]["judge_selection_rate"], 0.5)

    def test_adjustment_rewards_selected_agents_and_penalizes_ignored_ones(self):
        positive = compute_judge_feedback_adjustment(
            {"proposals_seen_by_judge": 8, "selected_by_judge": 2, "judge_selection_rate": 0.25}
        )
        negative = compute_judge_feedback_adjustment(
            {"proposals_seen_by_judge": 20, "selected_by_judge": 0, "judge_selection_rate": 0.0}
        )

        self.assertGreater(positive, 0.0)
        self.assertLess(negative, 0.0)

    def test_serialize_hypothesis_includes_feedback_metadata(self):
        hypothesis = SimpleNamespace(
            id=10,
            agent_name="dify_bopla_agent",
            hypothesis_type="bopla_probe",
            target_endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            http_method="GET",
            description="Check excessive data exposure",
            confidence=0.95,
            coverage_gain=0.86,
            evidence_readiness=0.97,
            false_positive_risk=0.1,
            estimated_cost=0.3,
            payload_json=json.dumps(
                {
                    "candidate_key": "bopla_probe::877",
                    "judge_feedback_adjustment": 0.02,
                    "judge_feedback_stats": {
                        "proposals_seen_by_judge": 8,
                        "selected_by_judge": 2,
                        "judge_selection_rate": 0.25,
                    },
                    "agent_role_class": "primary_attacker",
                    "agent_provider": "dify",
                },
                ensure_ascii=False,
            ),
        )

        serialized = serialize_hypothesis(hypothesis)

        self.assertEqual(serialized["agent_name"], "dify_bopla_agent")
        self.assertEqual(serialized["judge_feedback_adjustment"], 0.02)
        self.assertEqual(serialized["agent_role_class"], "primary_attacker")
        self.assertEqual(serialized["agent_provider"], "dify")


if __name__ == "__main__":
    unittest.main()
