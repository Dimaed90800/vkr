import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.services.agent_memory_service import (
    apply_agent_memory_to_hypotheses,
    compute_agent_adjustment,
)


class AgentMemoryServiceTests(unittest.TestCase):
    def test_compute_agent_adjustment_rewards_confirmed_patterns(self):
        row = SimpleNamespace(
            attempts=10,
            confirmed_count=5,
            rejected_count=1,
        )
        adjustment = compute_agent_adjustment(row)
        self.assertGreater(adjustment, 0)

    def test_apply_agent_memory_to_hypotheses_adjusts_confidence(self):
        row = SimpleNamespace(
            agent_name="rule_based_bola_agent",
            context_signature="vehicle_location",
            pattern_type="bola_object_access",
            attempts=10,
            confirmed_count=6,
            rejected_count=1,
            last_result="confirmed",
        )
        hypotheses = [
            {
                "candidate_key": "bola_probe::1",
                "agent_name": "rule_based_bola_agent",
                "hypothesis_type": "bola_probe",
                "target_endpoint": "http://host/identity/api/v2/vehicle/abc/location",
                "http_method": "GET",
                "description": "Probe",
                "payload": {},
                "confidence": 0.7,
                "estimated_cost": 1.0,
                "false_positive_risk": 0.1,
                "coverage_gain": 0.9,
                "evidence_readiness": 0.9,
            }
        ]
        with patch(
            "backend.app.services.agent_memory_service.build_agent_memory_index",
            return_value={
                ("rule_based_bola_agent", "vehicle_location", "bola_object_access"): row
            },
        ):
            adjusted = apply_agent_memory_to_hypotheses(db=None, session_id=1, hypotheses=hypotheses)

        self.assertGreater(adjusted[0]["confidence"], 0.7)
        self.assertIn("agent_memory_adjustment", adjusted[0]["payload"])


if __name__ == "__main__":
    unittest.main()
