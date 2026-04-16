import os
import unittest
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

from backend.app.services.agentic_orchestrator_service import (
    build_orchestrator_plan,
    get_orchestrator_agent_catalog,
)


class AgenticOrchestratorServiceTests(unittest.TestCase):
    def test_catalog_marks_current_active_agents_and_available_tools(self):
        catalog = {item["agent_name"]: item for item in get_orchestrator_agent_catalog()}

        self.assertIn("access_control_agent", catalog)
        self.assertIn("discover_openapi", catalog["discovery_agent"]["tools_available"])
        self.assertIn("zap_active_scan", catalog["dast_agent"]["tools_available"])
        self.assertEqual(catalog["ssrf_agent"]["status"], "planned")

    def test_build_orchestrator_plan_for_find_all_selects_core_agents(self):
        session_obj = SimpleNamespace(
            id=10,
            target_name="crapi",
            target_url="http://target",
            allowed_test_classes_json='["discovery","bola","bopla","auth"]',
            last_strategy_json='{"user_prompt":"Найди все уязвимости API"}',
        )

        plan = build_orchestrator_plan(session_obj)

        self.assertEqual(
            plan["selected_agent_names"][:5],
            [
                "replay_auth_agent",
                "discovery_agent",
                "access_control_agent",
                "dast_agent",
                "judge_agent",
            ],
        )
        worker_families = [item["worker_family"] for item in plan["execution_plan"] if item.get("worker_family")]
        self.assertIn("auth", worker_families)
        self.assertIn("probe", worker_families)
        self.assertIn("bola", worker_families)
        self.assertIn("bopla", worker_families)

    def test_build_orchestrator_plan_for_bola_bopla_selects_access_control(self):
        session_obj = SimpleNamespace(
            id=11,
            target_name="crapi",
            target_url="http://target",
            allowed_test_classes_json='["bola","bopla"]',
            last_strategy_json='{"user_prompt":"Find confirmed BOLA and BOPLA vulnerabilities"}',
        )

        plan = build_orchestrator_plan(session_obj)

        self.assertIn("access_control_agent", plan["selected_agent_names"])
        self.assertNotIn("dast_agent", plan["selected_agent_names"])


if __name__ == "__main__":
    unittest.main()
