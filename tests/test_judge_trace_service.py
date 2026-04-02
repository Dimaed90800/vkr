import unittest

from backend.app.services.judge_trace_service import classify_dify_issue


class JudgeTraceServiceTests(unittest.TestCase):
    def test_classifies_credit_limit(self):
        issue = classify_dify_issue(
            "dify_exception_fallback",
            raw_reason="API request failed with status code 402: can only afford 0.001",
            reasoning_summary="",
        )
        self.assertEqual(issue, "provider_credit_limit")

    def test_classifies_invalid_candidate_key(self):
        issue = classify_dify_issue(
            "dify_rule_based_fallback",
            raw_reason="",
            reasoning_summary="",
        )
        self.assertEqual(issue, "invalid_candidate_key")

    def test_classifies_semantic_recovery(self):
        issue = classify_dify_issue(
            "dify_reason_bopla_recovery",
            raw_reason="",
            reasoning_summary="",
        )
        self.assertEqual(issue, "semantic_recovery")

    def test_classifies_unified_invalid_selection_as_invalid_candidate_key(self):
        issue = classify_dify_issue(
            "unified_invalid_selection_fallback",
            raw_reason="unknown candidate",
            reasoning_summary="",
        )
        self.assertEqual(issue, "invalid_candidate_key")

    def test_classifies_unified_provider_failure(self):
        issue = classify_dify_issue(
            "unified_no_dify_fallback",
            raw_reason="API request failed with status code 402: can only afford 0.001",
            reasoning_summary="",
        )
        self.assertEqual(issue, "provider_credit_limit")

    def test_classifies_unified_rule_based_override_separately(self):
        issue = classify_dify_issue(
            "unified_rule_based_override",
            raw_reason="",
            reasoning_summary="Unified mode kept rule-based winner over Dify nomination.",
        )
        self.assertEqual(issue, "rule_based_override")


if __name__ == "__main__":
    unittest.main()
