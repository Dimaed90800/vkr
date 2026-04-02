import unittest
from types import SimpleNamespace

from backend.app.services.report_service import build_session_report


class ReportServiceTests(unittest.TestCase):
    def test_build_session_report_includes_selected_agent_name(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="running",
            created_at="2026-03-24",
            rounds_completed=1,
            max_rounds=10,
            budget_requests_used=3,
            budget_requests_total=100,
            stop_reason=None,
            last_strategy_json=(
                '{"enabled_agents":["rule_based_auth_agent","rule_based_bola_agent"],'
                '"agents_invoked":["rule_based_auth_agent","rule_based_bola_agent"],'
                '"active_agents":["rule_based_bola_agent"],'
                '"selected_agent":"rule_based_bola_agent"}'
            ),
        )
        decision = SimpleNamespace(
            id=10,
            round_no=1,
            decision_type="attack",
            selected_hypothesis_id=100,
            priority_score=0.8,
            resolution_mode="rule_based_direct",
            raw_selected_key=None,
            raw_score=0.8,
            raw_reason="selected",
            reasoning_summary="selected",
            required_evidence_json="[]",
            stop_condition_json="{}",
            created_at="2026-03-24",
        )
        hypothesis = SimpleNamespace(id=100, agent_name="rule_based_bola_agent")

        report = build_session_report(
            session_obj=session_obj,
            roles=[],
            findings=[],
            judge_decisions=[decision],
            observations=[],
            hypotheses=[hypothesis],
            agent_memory_rows=[
                SimpleNamespace(
                    agent_name="rule_based_bola_agent",
                    attempts=2,
                    selected_count=2,
                    confirmed_count=1,
                    rejected_count=0,
                    avg_cost=1.5,
                )
            ],
            agent_judge_feedback_rows=[
                SimpleNamespace(
                    session_id=1,
                    round_no=1,
                    agent_name="rule_based_bola_agent",
                    was_selected=1,
                )
            ],
        )

        self.assertEqual(
            report["recent_judge_decisions"][0]["selected_agent_name"],
            "rule_based_bola_agent",
        )
        self.assertEqual(
            report["agent_orchestration"]["selected_agent"],
            "rule_based_bola_agent",
        )
        self.assertEqual(
            report["agent_orchestration"]["selected_logical_agent"],
            "authorization_agent",
        )
        self.assertEqual(
            report["agent_orchestration"]["enabled_logical_agents"],
            ["authentication_agent", "authorization_agent"],
        )
        self.assertEqual(
            report["recent_judge_decisions"][0]["selected_logical_agent_name"],
            "authorization_agent",
        )
        self.assertEqual(report["agent_learning_summary"]["agents_total"], 1)
        self.assertEqual(
            report["agent_learning_summary"]["agents"][0]["agent_name"],
            "rule_based_bola_agent",
        )
        self.assertEqual(report["agent_effectiveness_summary"]["primary_attackers_total"], 1)
        self.assertEqual(
            report["agent_effectiveness_summary"]["agents"][0]["role_class"],
            "primary_attacker",
        )
        self.assertEqual(report["agent_judge_feedback_summary"]["agents_total"], 1)
        self.assertEqual(
            report["agent_judge_feedback_summary"]["agents"][0]["selected_by_judge"],
            1,
        )

    def test_judge_trace_summary_separates_rule_based_overrides_from_fallbacks(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="running",
            created_at="2026-03-24",
            rounds_completed=2,
            max_rounds=10,
            budget_requests_used=3,
            budget_requests_total=100,
            stop_reason=None,
            last_strategy_json="{}",
        )
        override_decision = SimpleNamespace(
            id=10,
            round_no=1,
            decision_type="attack",
            selected_hypothesis_id=100,
            priority_score=0.8,
            resolution_mode="unified_rule_based_override",
            raw_selected_key="bola_probe::x",
            raw_score=0.97,
            raw_reason="Highest evidence readiness among candidates.",
            reasoning_summary="Unified mode kept rule-based winner over Dify nomination.",
            required_evidence_json="[]",
            stop_condition_json="{}",
            created_at="2026-03-24",
        )
        fallback_decision = SimpleNamespace(
            id=11,
            round_no=2,
            decision_type="attack",
            selected_hypothesis_id=101,
            priority_score=0.75,
            resolution_mode="unified_no_dify_fallback",
            raw_selected_key=None,
            raw_score=None,
            raw_reason="Could not extract selected_key from Dify workflow outputs: {}",
            reasoning_summary="Unified mode fallback to rule-based scoring because Dify judge response was unavailable.",
            required_evidence_json="[]",
            stop_condition_json="{}",
            created_at="2026-03-24",
        )

        report = build_session_report(
            session_obj=session_obj,
            roles=[],
            findings=[],
            judge_decisions=[override_decision, fallback_decision],
            observations=[],
            hypotheses=[],
            agent_memory_rows=[],
            agent_judge_feedback_rows=[],
        )

        self.assertEqual(report["judge_trace_summary"]["rule_based_overrides"], 1)
        self.assertEqual(report["judge_trace_summary"]["fallbacks"], 1)


if __name__ == "__main__":
    unittest.main()
