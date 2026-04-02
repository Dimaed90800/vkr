import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.services.agent_runtime_service import run_agent_cycle_for_session


class AgentRuntimeServiceTests(unittest.TestCase):
    def test_run_agent_cycle_tracks_agent_invocations_and_selected_pool(self):
        session_obj = SimpleNamespace(
            id=69,
            last_strategy_json=(
                '{"enabled_agents": ["rule_based_auth_agent", "rule_based_bola_agent"]}'
            ),
            allowed_test_classes_json='["bola"]',
        )
        context = {
            "session": session_obj,
            "inventory_items": [],
            "api_items": [],
            "observations": [],
            "roles": [],
            "authenticated_roles": [],
            "findings": [],
        }
        specs = [
            {
                "agent_name": "rule_based_auth_agent",
                "title": "Auth Agent",
                "responsibility": "Produces BOLA hypotheses.",
                "implementation_type": "rule_based",
                "provider": "local",
                "adapter_key": "auth",
            },
            {
                "agent_name": "rule_based_bola_agent",
                "title": "BOLA Agent",
                "responsibility": "Produces BOLA hypotheses.",
                "implementation_type": "rule_based",
                "provider": "local",
                "adapter_key": "bola",
            },
        ]
        generated_by_agent = {
            "rule_based_auth_agent": [
                {
                    "candidate_key": "bola_probe::1",
                    "agent_name": "rule_based_auth_agent",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": "/a",
                    "http_method": "GET",
                    "description": "A",
                    "payload": {},
                    "confidence": 0.9,
                    "estimated_cost": 1.0,
                    "false_positive_risk": 0.1,
                    "coverage_gain": 0.9,
                    "evidence_readiness": 0.9,
                }
            ],
            "rule_based_bola_agent": [
                {
                    "candidate_key": "bola_probe::2",
                    "agent_name": "rule_based_bola_agent",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": "/b",
                    "http_method": "GET",
                    "description": "B",
                    "payload": {},
                    "confidence": 0.9,
                    "estimated_cost": 1.0,
                    "false_positive_risk": 0.1,
                    "coverage_gain": 0.9,
                    "evidence_readiness": 0.9,
                }
            ],
        }

        with patch("backend.app.services.agent_runtime_service.build_session_context", return_value=context):
            with patch("backend.app.services.agent_runtime_service.get_runtime_agent_specs", return_value=specs):
                with patch(
                    "backend.app.services.agent_runtime_service.generate_hypotheses_for_agent",
                    side_effect=lambda spec, _context: generated_by_agent[spec["agent_name"]],
                ):
                    runtime = run_agent_cycle_for_session(db=None, session_id=69)

        self.assertEqual(
            runtime["enabled_agents"],
            ["rule_based_auth_agent", "rule_based_bola_agent"],
        )
        self.assertEqual(len(runtime["hypotheses"]), 2)
        self.assertEqual(runtime["agent_invocations"][0]["eligible_hypotheses"], 1)
        self.assertTrue(runtime["agent_invocations"][0]["participated"])
        self.assertEqual(runtime["agent_invocations"][1]["eligible_hypotheses"], 1)
        self.assertTrue(runtime["agent_invocations"][1]["participated"])
        self.assertEqual(
            runtime["enabled_logical_agents"],
            ["authentication_agent", "authorization_agent"],
        )
        logical_agents = {
            item["logical_agent_name"]: item
            for item in runtime["logical_agent_summary"]["logical_agents"]
        }
        self.assertEqual(logical_agents["authentication_agent"]["generated_hypotheses"], 1)
        self.assertEqual(logical_agents["authorization_agent"]["generated_hypotheses"], 1)
        self.assertEqual(logical_agents["authentication_agent"]["eligible_hypotheses"], 1)
        self.assertEqual(logical_agents["authorization_agent"]["eligible_hypotheses"], 1)
        self.assertEqual(logical_agents["authentication_agent"]["implementation_scope"], "backend_plus_dify")
        self.assertEqual(logical_agents["authorization_agent"]["implementation_scope"], "backend_plus_dify")


if __name__ == "__main__":
    unittest.main()
