import unittest
from types import SimpleNamespace

from backend.app.services.agent_registry_service import (
    DEFAULT_ENABLED_AGENTS,
    build_session_agent_plan,
    get_agent_catalog_map,
    normalize_enabled_agents,
)


class AgentRegistryServiceTests(unittest.TestCase):
    def test_normalize_enabled_agents_filters_unknown_values(self):
        normalized = normalize_enabled_agents(
            ["rule_based_auth_agent", "unknown_agent", "rule_based_auth_agent"]
        )
        self.assertEqual(normalized, ["rule_based_auth_agent"])

    def test_build_session_agent_plan_uses_session_strategy_state(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            last_strategy_json='{"enabled_agents": ["rule_based_auth_agent", "dify_bola_agent"]}',
        )
        plan = build_session_agent_plan(session_obj)
        self.assertEqual(plan["enabled_agents_total"], 2)
        self.assertEqual(
            plan["enabled_agent_names"],
            ["rule_based_auth_agent", "dify_bola_agent"],
        )

    def test_non_implemented_future_agents_are_not_enabled_by_default(self):
        self.assertNotIn("dify_bopla_agent", DEFAULT_ENABLED_AGENTS)
        self.assertNotIn("rule_based_business_logic_agent", DEFAULT_ENABLED_AGENTS)
        self.assertIn("dify_auth_agent", DEFAULT_ENABLED_AGENTS)

    def test_catalog_contains_adapter_metadata(self):
        catalog = get_agent_catalog_map()
        self.assertEqual(catalog["rule_based_bola_agent"]["implementation_type"], "rule_based")
        self.assertEqual(catalog["dify_bola_agent"]["implementation_type"], "dify")
        self.assertEqual(catalog["dify_bopla_agent"]["adapter_key"], "dify_bopla")


if __name__ == "__main__":
    unittest.main()
