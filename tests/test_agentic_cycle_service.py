import unittest
from types import SimpleNamespace

from backend.app.services.agentic_cycle_service import (
    build_agentic_strategy_update,
    choose_agentic_candidate,
    judge_agentic_execution,
)


class _FakeQuery:
    def __init__(self, items):
        self._items = items

    def filter(self, *args, **kwargs):
        return self

    def all(self):
        return list(self._items)


class _FakeDb:
    def __init__(self, findings):
        self._findings = findings

    def query(self, model):
        return _FakeQuery(self._findings)


class AgenticCycleServiceTests(unittest.TestCase):
    def test_choose_agentic_candidate_prioritizes_prompt_and_verify_actions(self):
        verify_candidate = SimpleNamespace(
            id=2,
            agent_name="rule_based_verifier_agent",
            hypothesis_type="verify_bola",
            confidence=0.7,
            coverage_gain=0.6,
            evidence_readiness=0.95,
            false_positive_risk=0.1,
            estimated_cost=0.2,
            payload_json='{"candidate_key": "verify_bola::7"}',
        )
        bola_candidate = SimpleNamespace(
            id=1,
            agent_name="rule_based_bola_agent",
            hypothesis_type="bola_probe",
            confidence=0.95,
            coverage_gain=0.95,
            evidence_readiness=0.9,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json='{"candidate_key": "bola_probe::1"}',
        )

        selected, trace = choose_agentic_candidate(
            [bola_candidate, verify_candidate],
            user_prompt="Найди подтвержденную BOLA и сразу верифицируй эксплуатацию",
            allowed_test_classes=["bola"],
            strategy_state={"agentic_state": {"candidate_retry_counts": {}, "logical_agent_attempt_counts": {}}},
        )

        self.assertEqual(selected.hypothesis_type, "verify_bola")
        self.assertEqual(trace["logical_agent_name"], "exposure_agent")

    def test_judge_marks_candidate_evidence_as_retry_until_confirmed(self):
        selected = SimpleNamespace(
            id=11,
            agent_name="rule_based_bola_agent",
            hypothesis_type="bola_probe",
            payload_json='{"candidate_key": "bola_probe::11"}',
        )
        findings = [
            SimpleNamespace(id=5, verification_status="candidate", related_hypothesis_id=11),
        ]

        verdict = judge_agentic_execution(
            _FakeDb(findings),
            1,
            selected,
            {"action_executed": "bola_probe", "generated_finding_status": "candidate"},
        )

        self.assertEqual(verdict["status"], "needs_retry")
        self.assertEqual(verdict["follow_up_hypothesis_type"], "verify_bola")

    def test_strategy_update_accumulates_confirmed_findings(self):
        selected = SimpleNamespace(
            id=7,
            agent_name="rule_based_bola_agent",
            hypothesis_type="verify_bola",
            payload_json='{"candidate_key": "verify_bola::7"}',
        )
        update = build_agentic_strategy_update(
            previous_state={"agentic_state": {"confirmed_finding_ids": [1]}},
            selected=selected,
            router_trace={"candidate_key": "verify_bola::7", "logical_agent_name": "authorization_agent"},
            judge_verdict={"status": "confirmed", "resolution_mode": "agentic_judge_confirmed", "confirmed_finding_ids": [2]},
        )

        self.assertEqual(update["agentic_state"]["confirmed_finding_ids"], [1, 2])


if __name__ == "__main__":
    unittest.main()
