import unittest
from types import SimpleNamespace

from backend.app.services.unified_judge_service import choose_unified_candidate


class UnifiedJudgeServiceTests(unittest.TestCase):
    def test_unified_accepts_matching_dify_nomination_when_blended_is_close(self):
        candidate_a = SimpleNamespace(
            id=1,
            hypothesis_type="bopla_probe",
            target_endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            http_method="GET",
            agent_name="dify_bopla_agent",
            confidence=0.95,
            coverage_gain=0.86,
            evidence_readiness=0.97,
            false_positive_risk=0.1,
            estimated_cost=0.3,
            payload_json="{}",
        )
        candidate_b = SimpleNamespace(
            id=2,
            hypothesis_type="authenticated_probe",
            target_endpoint="http://host.docker.internal:8888/workshop/api/shop/products",
            http_method="GET",
            agent_name="rule_based_probe_agent",
            confidence=0.9,
            coverage_gain=0.9,
            evidence_readiness=0.93,
            false_positive_risk=0.12,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "bopla_probe::877", "type": "bopla_probe"},
            {"candidate_key": "authenticated_probe::x", "type": "authenticated_probe"},
        ]
        dify_response = {"selected_key": "bopla_probe::877", "score": 0.95, "reason": "BOPLA signal is strongest."}

        selected, score, resolution_mode, _ = choose_unified_candidate(
            [candidate_a, candidate_b],
            hypotheses_json,
            dify_response,
            recent_observations=[],
        )

        self.assertEqual(selected.id, 1)
        self.assertTrue(score > 0)
        self.assertTrue(resolution_mode.startswith("unified_"))

    def test_unified_falls_back_to_rule_based_when_no_dify_match(self):
        candidate_a = SimpleNamespace(
            id=1,
            hypothesis_type="verify_bopla",
            target_endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            http_method="GET",
            agent_name="rule_based_verifier_agent",
            confidence=0.99,
            coverage_gain=0.95,
            evidence_readiness=0.99,
            false_positive_risk=0.03,
            estimated_cost=0.2,
            payload_json="{}",
        )
        hypotheses_json = [
            {"candidate_key": "verify_bopla::194", "type": "verify_bopla"},
        ]
        dify_response = {"selected_key": "unknown_candidate", "score": 0.6, "reason": "Unknown."}

        selected, _, resolution_mode, _ = choose_unified_candidate(
            [candidate_a],
            hypotheses_json,
            dify_response,
            recent_observations=[],
        )

        self.assertEqual(selected.id, 1)
        self.assertEqual(resolution_mode, "unified_invalid_selection_fallback")

    def test_unified_marks_missing_dify_response_separately(self):
        candidate_a = SimpleNamespace(
            id=1,
            hypothesis_type="verify_bopla",
            target_endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            http_method="GET",
            agent_name="rule_based_verifier_agent",
            confidence=0.99,
            coverage_gain=0.95,
            evidence_readiness=0.99,
            false_positive_risk=0.03,
            estimated_cost=0.2,
            payload_json="{}",
        )
        hypotheses_json = [
            {"candidate_key": "verify_bopla::194", "type": "verify_bopla"},
        ]

        selected, _, resolution_mode, note = choose_unified_candidate(
            [candidate_a],
            hypotheses_json,
            None,
            recent_observations=[],
        )

        self.assertEqual(selected.id, 1)
        self.assertEqual(resolution_mode, "unified_no_dify_fallback")
        self.assertIn("unavailable", note.lower())

    def test_unified_prefers_strong_dify_attack_over_support_action(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="compare_roles",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.93,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json="{}",
        )
        attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.9,
            coverage_gain=0.88,
            evidence_readiness=0.92,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "compare_roles::x", "type": "compare_roles"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness and confidence among candidates.",
        }

        selected, _, resolution_mode, _ = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
        )

        self.assertEqual(selected.id, 2)
        self.assertTrue(resolution_mode.startswith("unified_"))
        self.assertNotEqual(resolution_mode, "unified_rule_based_override")

    def test_unified_still_overrides_weak_dify_attack(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="compare_roles",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.93,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json="{}",
        )
        weak_attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.65,
            coverage_gain=0.6,
            evidence_readiness=0.62,
            false_positive_risk=0.18,
            estimated_cost=1.2,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "compare_roles::x", "type": "compare_roles"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness among candidates.",
        }

        selected, _, resolution_mode, _ = choose_unified_candidate(
            [support_candidate, weak_attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
        )

        self.assertEqual(selected.id, 1)
        self.assertEqual(resolution_mode, "unified_rule_based_override")

    def test_unified_penalizes_repeated_dify_nomination(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="compare_roles",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.93,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json="{}",
        )
        attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.82,
            coverage_gain=0.8,
            evidence_readiness=0.84,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "compare_roles::x", "type": "compare_roles"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness among candidates.",
        }

        baseline_selected, _, baseline_resolution_mode, _ = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[],
        )
        repeated_selected, _, repeated_resolution_mode, repeated_note = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
            ],
        )

        self.assertEqual(baseline_selected.id, 2)
        self.assertNotEqual(baseline_resolution_mode, "unified_rule_based_override")
        self.assertEqual(repeated_selected.id, 1)
        self.assertEqual(repeated_resolution_mode, "unified_rule_based_override")
        self.assertIn("repeat_penalty", repeated_note)

    def test_unified_penalizes_repeated_support_winner(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="compare_roles",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.93,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json="{}",
        )
        attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.66,
            coverage_gain=0.68,
            evidence_readiness=0.72,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "compare_roles::x", "type": "compare_roles"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness among candidates.",
        }

        baseline_selected, _, baseline_resolution_mode, _ = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[],
            recent_selected_hypothesis_types=[],
        )
        repeated_selected, _, repeated_resolution_mode, repeated_note = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[],
            recent_selected_hypothesis_types=[
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
            ],
        )

        self.assertEqual(baseline_selected.id, 1)
        self.assertEqual(baseline_resolution_mode, "unified_rule_based_override")
        self.assertEqual(repeated_selected.id, 2)
        self.assertNotEqual(repeated_resolution_mode, "unified_rule_based_override")
        self.assertIn("top_rule_penalty", repeated_note)

    def test_unified_late_round_prefers_attack_over_repeated_support(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="compare_roles",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="rule_based_analysis_agent",
            confidence=0.92,
            coverage_gain=0.85,
            evidence_readiness=0.93,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json="{}",
        )
        attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.55,
            coverage_gain=0.6,
            evidence_readiness=0.68,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "compare_roles::x", "type": "compare_roles"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness among candidates.",
        }

        baseline_selected, _, baseline_resolution_mode, _ = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[],
            recent_selected_hypothesis_types=[
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
            ],
        )
        late_round_selected, _, late_round_resolution_mode, late_round_note = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
            ],
            recent_selected_hypothesis_types=[
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "compare_roles",
            ],
        )

        self.assertEqual(baseline_selected.id, 2)
        self.assertNotEqual(baseline_resolution_mode, "unified_rule_based_override")
        self.assertEqual(late_round_selected.id, 2)
        self.assertNotEqual(late_round_resolution_mode, "unified_rule_based_override")
        self.assertIn("late_round_bonus", late_round_note)

    def test_unified_penalizes_support_chain_in_very_late_rounds(self):
        support_candidate = SimpleNamespace(
            id=1,
            hypothesis_type="authenticated_probe",
            target_endpoint="http://host.docker.internal:8888/workshop/api/shop/products",
            http_method="GET",
            agent_name="rule_based_probe_agent",
            confidence=0.9,
            coverage_gain=0.9,
            evidence_readiness=0.93,
            false_positive_risk=0.12,
            estimated_cost=1.0,
            payload_json='{"role_name":"user_a"}',
        )
        attack_candidate = SimpleNamespace(
            id=2,
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4/location",
            http_method="GET",
            agent_name="dify_bola_agent",
            confidence=0.7,
            coverage_gain=0.7,
            evidence_readiness=0.8,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        hypotheses_json = [
            {"candidate_key": "authenticated_probe::x", "type": "authenticated_probe"},
            {"candidate_key": "bola_probe::vehicle::4::user_a::user_b", "type": "bola_probe"},
        ]
        dify_response = {
            "selected_key": "bola_probe::vehicle::4::user_a::user_b",
            "score": 0.97,
            "reason": "Highest evidence readiness among candidates.",
        }

        baseline_selected, _, baseline_resolution_mode, _ = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
            ],
            recent_selected_hypothesis_types=[
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "discovery",
                "compare_roles",
                "discovery",
                "compare_roles",
                "compare_roles",
                "discovery",
                "compare_roles",
                "compare_roles",
                "discovery",
            ],
        )
        very_late_selected, _, very_late_resolution_mode, very_late_note = choose_unified_candidate(
            [support_candidate, attack_candidate],
            hypotheses_json,
            dify_response,
            recent_observations=[],
            recent_selected_keys=[
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
                "bola_probe::vehicle::4::user_a::user_b",
            ],
            recent_selected_hypothesis_types=[
                "compare_roles",
                "compare_roles",
                "compare_roles",
                "discovery",
                "compare_roles",
                "discovery",
                "compare_roles",
                "compare_roles",
                "discovery",
                "compare_roles",
                "compare_roles",
                "discovery",
                "authenticated_probe",
            ],
        )

        self.assertEqual(baseline_selected.id, 1)
        self.assertEqual(baseline_resolution_mode, "unified_rule_based_override")
        self.assertEqual(very_late_selected.id, 2)
        self.assertNotEqual(very_late_resolution_mode, "unified_rule_based_override")
        self.assertIn("support_chain_penalty", very_late_note)
        self.assertIn("support_chain_bonus", very_late_note)


if __name__ == "__main__":
    unittest.main()
