import json
import unittest
from types import SimpleNamespace

from backend.app.services.replay_service import replay_unified_for_session


class ReplayServiceTests(unittest.TestCase):
    def test_replay_unified_reconstructs_rounds_and_counts_overrides(self):
        session_obj = SimpleNamespace(
            id=77,
            target_name="crapi",
            target_url="http://target",
            status="stopped",
        )
        candidate_a = SimpleNamespace(
            id=101,
            hypothesis_type="compare_roles",
            target_endpoint="http://target/a",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.9,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            description="Compare role responses",
            payload_json=json.dumps({"candidate_key": "compare_roles::a"}),
        )
        candidate_b = SimpleNamespace(
            id=102,
            hypothesis_type="bola_probe",
            target_endpoint="http://target/b",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.6,
            coverage_gain=0.5,
            evidence_readiness=0.55,
            false_positive_risk=0.2,
            estimated_cost=1.5,
            description="Probe object access",
            payload_json=json.dumps({"candidate_key": "bola_probe::vehicle::x::user_a::user_b"}),
        )

        judge_decisions = [
            SimpleNamespace(
                round_no=1,
                selected_hypothesis_id=101,
                resolution_mode="unified_rule_based_override",
                raw_selected_key="bola_probe::vehicle::x::user_a::user_b",
                raw_score=0.97,
                raw_reason="Highest evidence readiness among candidates.",
                created_at=2,
            ),
            SimpleNamespace(
                round_no=2,
                selected_hypothesis_id=101,
                resolution_mode="unified_no_dify_fallback",
                raw_selected_key=None,
                raw_score=None,
                raw_reason="Could not extract selected_key from Dify workflow outputs: {}",
                created_at=3,
            ),
        ]
        observations = [
            SimpleNamespace(id=1, endpoint="http://target/a", method="GET", role_name="user_a", created_at=1),
            SimpleNamespace(id=2, endpoint="http://target/b", method="GET", role_name="user_b", created_at=2),
        ]
        feedback_rows = [
            SimpleNamespace(round_no=1, hypothesis_id=101),
            SimpleNamespace(round_no=1, hypothesis_id=102),
            SimpleNamespace(round_no=2, hypothesis_id=101),
            SimpleNamespace(round_no=2, hypothesis_id=102),
        ]

        replay = replay_unified_for_session(
            session_obj=session_obj,
            judge_decisions=judge_decisions,
            observations=observations,
            hypotheses=[candidate_a, candidate_b],
            agent_judge_feedback_rows=feedback_rows,
        )

        self.assertEqual(replay["summary"]["replayed_rounds"], 2)
        self.assertEqual(replay["summary"]["fallback_count"], 1)
        self.assertEqual(replay["summary"]["rule_based_override_count"], 1)
        self.assertEqual(len(replay["rounds"]), 2)
        self.assertEqual(replay["rounds"][0]["round_no"], 1)
        self.assertIn("replay_resolution_mode", replay["rounds"][0])


if __name__ == "__main__":
    unittest.main()
