import unittest

from backend.app.services.terminal_reverification_service import rank_verifier_candidates


class TerminalReverificationServiceTests(unittest.TestCase):
    def test_rank_verifier_candidates_prioritizes_bola_then_bopla_then_auth(self):
        candidates = [
            {
                "hypothesis_type": "verify_auth_boundary",
                "evidence_readiness": 0.99,
                "confidence": 0.99,
                "false_positive_risk": 0.01,
            },
            {
                "hypothesis_type": "verify_bopla",
                "evidence_readiness": 0.7,
                "confidence": 0.7,
                "false_positive_risk": 0.1,
            },
            {
                "hypothesis_type": "verify_bola",
                "evidence_readiness": 0.6,
                "confidence": 0.6,
                "false_positive_risk": 0.1,
            },
        ]

        ranked = rank_verifier_candidates(candidates)

        self.assertEqual(ranked[0]["hypothesis_type"], "verify_bola")
        self.assertEqual(ranked[1]["hypothesis_type"], "verify_bopla")
        self.assertEqual(ranked[2]["hypothesis_type"], "verify_auth_boundary")


if __name__ == "__main__":
    unittest.main()
