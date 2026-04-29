import unittest
import os
from types import SimpleNamespace

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import backend.app.services.report_service as report_service_module
from backend.app.services.report_service import build_final_session_report, build_session_markdown_report, build_session_report


class ReportServiceTests(unittest.TestCase):
    @staticmethod
    def _base_final_report() -> dict:
        return {
            "session": {"id": 1, "target_name": "crapi", "target_url": "http://target", "status": "finished"},
            "executive_summary": {"headline": "h", "message": "m"},
            "summary_text": "summary",
            "risk_summary": {
                "total_findings": 0,
                "confirmed_findings": 0,
                "candidate_findings": 0,
                "bola_findings": 0,
                "bopla_findings": 0,
                "severity_breakdown": {"high": 0, "medium": 0, "low": 0},
            },
            "top_findings": [],
            "candidate_findings_for_review": [],
            "judge_trace_summary": {"direct_matches": 0, "recoveries": 0, "fallbacks": 0},
            "logical_agent_activity_summary": {"logical_agents": []},
            "logical_agent_learning_summary": {"logical_agents": []},
            "logical_agent_judge_feedback_summary": {"logical_agents": []},
            "logical_agent_effectiveness_summary": {"logical_agents": []},
        }

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

    def test_build_session_report_exposes_runtime_summaries(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="finished",
            created_at="2026-03-24",
            rounds_completed=15,
            max_rounds=15,
            budget_requests_used=24,
            budget_requests_total=200,
            stop_reason="max_rounds_reached",
            last_strategy_json=(
                '{"enabled_agents":["rule_based_auth_agent","rule_based_bola_agent"],'
                '"exploitation_queue_summary":{"enabled":true,"promoted_total":2,"promoted_candidate_keys":["a","b"]},'
                '"terminal_reverification_summary":{"executed":true,"attempted":2,"completed":1,"results":[{"hypothesis_id":5}]}}'
            ),
        )
        findings = [
            SimpleNamespace(
                id=1,
                finding_type="possible_bola",
                severity="high",
                title="Confirmed BOLA",
                description="confirmed issue",
                endpoint="http://target/identity/api/v2/vehicle/123/location",
                verification_status="confirmed",
                related_hypothesis_id=None,
                related_observation_ids="[]",
                evidence_json="{}",
                created_at="2026-03-24",
            )
        ]
        observations = [
            SimpleNamespace(
                id=11,
                endpoint="http://target/identity/api/v2/vehicle/123/location",
                method="GET",
                role_name="user_a",
                status_code=200,
                body_preview='{"ok":true}',
                created_at="2026-03-24",
            )
        ]

        report = build_session_report(
            session_obj=session_obj,
            roles=[],
            findings=findings,
            judge_decisions=[],
            observations=observations,
            hypotheses=[],
            agent_memory_rows=[],
            agent_judge_feedback_rows=[],
        )

        self.assertEqual(report["exploitation_queue_summary"]["promoted_total"], 2)
        self.assertTrue(report["terminal_reverification_summary"]["executed"])
        self.assertEqual(report["terminal_reverification_summary"]["completed"], 1)
        self.assertEqual(report["coverage_summary"]["observation_buckets"]["object_access"], 1)
        self.assertEqual(report["coverage_summary"]["finding_buckets"]["object_access_findings"], 1)

    def test_final_report_keeps_main_findings_confirmed_only(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="finished",
            created_at="2026-03-24",
            rounds_completed=2,
            max_rounds=10,
            budget_requests_used=3,
            budget_requests_total=100,
            stop_reason=None,
            last_strategy_json="{}",
        )
        confirmed = SimpleNamespace(
            id=1,
            finding_type="possible_bola",
            severity="high",
            title="Confirmed BOLA",
            description="confirmed issue",
            endpoint="http://target/a",
            verification_status="confirmed",
            related_hypothesis_id=None,
            related_observation_ids="[]",
            evidence_json='{"signals":["matched"]}',
            created_at="2026-03-24",
        )
        candidate = SimpleNamespace(
            id=2,
            finding_type="possible_bopla",
            severity="medium",
            title="Candidate BOPLA",
            description="candidate issue",
            endpoint="http://target/b",
            verification_status="candidate",
            related_hypothesis_id=None,
            related_observation_ids="[]",
            evidence_json='{"exposed_fields":["email"]}',
            created_at="2026-03-24",
        )

        report = build_final_session_report(
            session_obj=session_obj,
            roles=[],
            findings=[candidate, confirmed],
            judge_decisions=[],
            observations=[],
            hypotheses=[],
            agent_memory_rows=[],
            agent_judge_feedback_rows=[],
        )

        self.assertEqual(len(report["top_findings"]), 1)
        self.assertEqual(report["top_findings"][0]["title"], "Confirmed BOLA")
        self.assertEqual(len(report["candidate_findings_for_review"]), 1)
        self.assertEqual(report["candidate_findings_for_review"][0]["title"], "Candidate BOPLA")
        self.assertIn("evidence_bundle", report["top_findings"][0])

    def test_markdown_report_has_separate_candidate_section(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="finished",
            created_at="2026-03-24",
            rounds_completed=2,
            max_rounds=10,
            budget_requests_used=3,
            budget_requests_total=100,
            stop_reason=None,
            last_strategy_json="{}",
        )
        confirmed = SimpleNamespace(
            id=1,
            finding_type="possible_bola",
            severity="high",
            title="Confirmed BOLA",
            description="confirmed issue",
            endpoint="http://target/a",
            verification_status="confirmed",
            related_hypothesis_id=None,
            related_observation_ids="[]",
            evidence_json='{"signals":["matched"]}',
            created_at="2026-03-24",
        )
        candidate = SimpleNamespace(
            id=2,
            finding_type="possible_bopla",
            severity="medium",
            title="Candidate BOPLA",
            description="candidate issue",
            endpoint="http://target/b",
            verification_status="candidate",
            related_hypothesis_id=None,
            related_observation_ids="[]",
            evidence_json='{"exposed_fields":["email"]}',
            created_at="2026-03-24",
        )

        markdown = build_session_markdown_report(
            session_obj=session_obj,
            roles=[],
            findings=[candidate, confirmed],
            judge_decisions=[],
            observations=[],
            hypotheses=[],
            agent_memory_rows=[],
            agent_judge_feedback_rows=[],
        )

        self.assertIn("## Top Findings", markdown)
        self.assertIn("Confirmed BOLA", markdown)
        self.assertIn("## Candidate Findings Requiring Manual Review", markdown)
        self.assertIn("Candidate BOPLA", markdown)

    def test_final_report_builds_replayable_evidence_bundle_and_masks_tokens(self):
        session_obj = SimpleNamespace(
            id=1,
            target_name="crapi",
            target_url="http://target",
            status="finished",
            created_at="2026-03-24",
            rounds_completed=2,
            max_rounds=10,
            budget_requests_used=3,
            budget_requests_total=100,
            stop_reason=None,
            last_strategy_json="{}",
        )
        confirmed = SimpleNamespace(
            id=1,
            finding_type="possible_bola",
            severity="high",
            title="Confirmed BOLA",
            description="confirmed issue",
            endpoint="http://target/a",
            verification_status="confirmed",
            related_hypothesis_id=None,
            related_observation_ids="[11,12]",
            evidence_json=(
                '{"signals":["same_endpoint_targeted","identical_json_response"],'
                '"owner_role":"user_a","other_role":"user_b","status_owner":200,"status_other":200}'
            ),
            created_at="2026-03-24",
        )
        observations = [
            SimpleNamespace(
                id=11,
                role_name="user_a",
                method="GET",
                endpoint="http://target/a",
                status_code=200,
                request_headers='{"Authorization":"Bearer secret-a","Accept":"application/json"}',
                request_params="{}",
                request_body="{}",
                response_headers="{}",
                body_preview='{"id":"obj-1"}',
                created_at="2026-03-24",
            ),
            SimpleNamespace(
                id=12,
                role_name="user_b",
                method="GET",
                endpoint="http://target/a",
                status_code=200,
                request_headers='{"Authorization":"Bearer secret-b"}',
                request_params="{}",
                request_body="{}",
                response_headers="{}",
                body_preview='{"id":"obj-1"}',
                created_at="2026-03-24",
            ),
        ]

        report = build_final_session_report(
            session_obj=session_obj,
            roles=[],
            findings=[confirmed],
            judge_decisions=[],
            observations=observations,
            hypotheses=[],
            agent_memory_rows=[],
            agent_judge_feedback_rows=[],
        )

        evidence_bundle = report["top_findings"][0]["evidence_bundle"]
        self.assertEqual(evidence_bundle["observation_ids"], [11, 12])
        self.assertEqual(len(evidence_bundle["replay_requests"]), 2)
        self.assertEqual(
            evidence_bundle["replay_requests"][0]["request_headers"]["Authorization"],
            "Bearer <USER_A_TOKEN>",
        )
        self.assertTrue(evidence_bundle["reproducibility"]["has_replay_requests"])
        self.assertTrue(evidence_bundle["reproducibility"]["has_comparison_roles"])

    def test_markdown_report_renders_api7_ssrf_candidates(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "confirmed_findings_count": 0,
                "ssrf_candidate_signal_count": 1,
                "ssrf_candidate_operations_count": 1,
                "ssrf_candidate_fields_count": 1,
                "ssrf_probe_result_count": 0,
                "ssrf_probe_callback_received_count": 0,
                "ssrf_probe_target_non_2xx_count": 0,
                "ssrf_probe_probe_error_count": 0,
                "ssrf_probe_schema_synthesized_count": 0,
                "ssrf_probe_llm_composed_count": 0,
                "ssrf_candidates": [
                    {
                        "operation_id": "op_POST_/api/contact",
                        "method": "POST",
                        "path": "/api/contact",
                        "field_name": "callback_url",
                        "field_path": "$.callback_url",
                        "schema_type": "string",
                        "schema_format": "uri",
                        "confidence": "high",
                        "reason_codes": ["schema_format_uri"],
                    }
                ],
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("## Детали API7 Server-Side Request Forgery", markdown)
        self.assertIn("### SSRF Candidates", markdown)
        self.assertIn("op_POST_/api/contact", markdown)
        self.assertIn("$.callback_url", markdown)

    def test_markdown_report_renders_ssrf_probe_results(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "confirmed_findings_count": 0,
                "ssrf_candidate_signal_count": 1,
                "ssrf_candidate_operations_count": 1,
                "ssrf_candidate_fields_count": 1,
                "ssrf_probe_result_count": 1,
                "ssrf_probe_callback_received_count": 0,
                "ssrf_probe_target_non_2xx_count": 1,
                "ssrf_probe_probe_error_count": 0,
                "ssrf_probe_schema_synthesized_count": 1,
                "ssrf_probe_llm_composed_count": 0,
                "ssrf_probe_results": [
                    {
                        "operation_id": "op_POST_/api/contact",
                        "method": "POST",
                        "path": "/api/contact",
                        "field_name": "callback_url",
                        "field_path": "$.callback_url",
                        "auth_mode": "authenticated",
                        "auth_profile_id": "authprof_1",
                        "role_hint": "owner",
                        "result": "target_non_2xx",
                        "target_status_code": 400,
                        "callback_received": False,
                        "callback_received_effective": True,
                        "late_callback_reconciled": True,
                        "callback_store_received": True,
                        "callback_method": "GET",
                        "evidence_strength": "high",
                        "request_composer": "deterministic",
                        "request_draft_validated": True,
                        "payload_synthesis_result": "schema_synthesized",
                        "filled_required_fields_count": 2,
                        "missing_required_fields_count": 1,
                        "rejected_fields_count": 0,
                        "synthesized_field_count": 3,
                        "schema_summary_source": "api_graph",
                        "reason_codes": ["target_non_2xx"],
                    }
                ],
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("### SSRF Probe Results", markdown)
        self.assertIn("Target Status Code", markdown)
        self.assertIn("schema_synthesized", markdown)
        self.assertIn("Filled Required", markdown)
        self.assertIn("Callback Received Raw", markdown)
        self.assertIn("Callback Received Effective", markdown)
        self.assertIn("Late Callback Reconciled", markdown)
        self.assertIn("Callback Store Received", markdown)
        self.assertIn("Field Name", markdown)
        self.assertIn("Auth Mode", markdown)
        self.assertIn("Auth Profile ID", markdown)
        self.assertIn("Role Hint", markdown)
        self.assertIn("Callback Method", markdown)
        self.assertIn("Evidence Strength", markdown)

    def test_markdown_api7_confirmed_status_and_summary_are_consistent(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "confirmed",
                "confirmed_findings_count": 1,
                "summary_text": "SSRF подтвержден: целевое приложение выполнило исходящий запрос на контролируемый callback URL.",
                "ssrf_candidate_signal_count": 1,
                "ssrf_candidate_operations_count": 1,
                "ssrf_candidate_fields_count": 1,
                "ssrf_probe_result_count": 1,
                "ssrf_probe_callback_received_count": 1,
                "ssrf_probe_target_non_2xx_count": 0,
                "ssrf_probe_probe_error_count": 1,
                "ssrf_probe_schema_synthesized_count": 0,
                "ssrf_probe_llm_composed_count": 1,
                "confirmed_ssrf_evidence": [
                    {
                        "finding_id": "finding_ssrf_1",
                        "evidence_id": "evp_ssrf_1",
                        "operation_id": "op_POST_/service/contact",
                        "method": "POST",
                        "endpoint": "/service/contact",
                        "field_path": "$.callback_url",
                        "callback_received_effective": True,
                        "late_callback_reconciled": True,
                        "callback_store_received": True,
                        "evidence_strength": "high",
                        "judge_verdict": "confirmed",
                        "reason_codes": ["controlled_callback_received", "late_callback_reconciled"],
                    }
                ],
                "ssrf_probe_results": [],
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("- Status: `confirmed`", markdown)
        self.assertIn("SSRF подтвержден", markdown)
        self.assertNotIn("подтверждённых SSRF-уязвимостей нет", markdown)
        self.assertIn("### Confirmed SSRF Evidence", markdown)
        self.assertIn("finding_ssrf_1", markdown)
        self.assertIn("evp_ssrf_1", markdown)
        self.assertIn("$.callback_url", markdown)

    def test_markdown_api7_keeps_diagnostic_text_when_no_confirmed(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "confirmed_findings_count": 0,
                "summary_text": "Диагностические SSRF-кандидаты обнаружены; подтверждение требует controlled callback proof.",
                "ssrf_candidate_signal_count": 1,
                "ssrf_candidate_operations_count": 1,
                "ssrf_candidate_fields_count": 1,
                "ssrf_probe_result_count": 0,
                "ssrf_probe_callback_received_count": 0,
                "ssrf_probe_target_non_2xx_count": 0,
                "ssrf_probe_probe_error_count": 0,
                "ssrf_probe_schema_synthesized_count": 0,
                "ssrf_probe_llm_composed_count": 0,
                "ssrf_candidates": [],
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("- Status: `diagnostic`", markdown)
        self.assertIn("Диагностические SSRF-кандидаты обнаружены", markdown)

    def test_markdown_report_renders_api7_planning_diagnostics_when_no_probe_results(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "ssrf_candidate_signal_count": 2,
                "ssrf_probe_result_count": 0,
                "api7_planning_diagnostics": {
                    "ssrf_candidate_signal_count": 2,
                    "ssrf_probe_ready_count": 0,
                    "ssrf_probe_blocked_count": 1,
                    "ssrf_probe_deprioritized_count": 1,
                    "top_candidate_operation_id": "op_POST_/api/contact",
                    "top_candidate_field_path": "$.callback_url",
                    "top_candidate_status": "blocked",
                    "top_candidate_blocked_reason": "kind_cap_reached",
                    "kind_cap_remaining": 0,
                    "api7_already_confirmed": False,
                    "reason": "kind_cap_reached",
                },
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("### API7 Planning Diagnostics", markdown)
        self.assertIn("top_candidate_operation_id", markdown)
        self.assertIn("top_candidate_status", markdown)
        self.assertIn("kind_cap_reached", markdown)

    def test_markdown_report_renders_api7_pipeline_trace(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "ssrf_candidate_signal_count": 1,
                "ssrf_probe_result_count": 0,
                "api7_ssrf_pipeline_trace": {
                    "last_failure_stage": "observation_persistence",
                    "adapter_called": True,
                    "ssrf_probe_result_persisted": False,
                },
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertIn("### API7 SSRF Pipeline Trace", markdown)
        self.assertIn("last_failure_stage", markdown)
        self.assertIn("adapter_called", markdown)
        self.assertIn("ssrf_probe_result_persisted", markdown)

    def test_markdown_report_does_not_leak_ssrf_raw_body_headers_or_secrets(self):
        session_obj = SimpleNamespace(id=1, last_strategy_json="{}")
        secret_token = "super-secret-token"
        final_report = self._base_final_report()
        final_report["owasp_coverage"] = {
            "API7_SERVER_SIDE_REQUEST_FORGERY": {
                "status": "diagnostic",
                "ssrf_candidate_signal_count": 1,
                "ssrf_probe_result_count": 1,
                "ssrf_candidates": [
                    {
                        "operation_id": "op_POST_/api/contact",
                        "method": "POST",
                        "path": "/api/contact",
                        "field_name": "callback_url",
                        "field_path": "$.callback_url",
                        "schema_type": "string",
                        "schema_format": "uri",
                        "confidence": "high",
                        "reason_codes": [],
                        "raw_request_body": {"password": "bad"},
                        "Authorization": f"Bearer {secret_token}",
                    }
                ],
                "ssrf_probe_results": [
                    {
                        "operation_id": "op_POST_/api/contact",
                        "method": "POST",
                        "path": "/api/contact",
                        "field_path": "$.callback_url",
                        "result": "target_non_2xx",
                        "target_status_code": 400,
                        "callback_received": False,
                        "request_composer": "deterministic",
                        "request_draft_validated": True,
                        "payload_synthesis_result": "schema_synthesized",
                        "filled_required_fields_count": 1,
                        "missing_required_fields_count": 0,
                        "rejected_fields_count": 0,
                        "synthesized_field_count": 1,
                        "schema_summary_source": "api_graph",
                        "reason_codes": [],
                        "raw_response_body": {"access_token": "bad"},
                        "Cookie": "SESSION=bad",
                        "password": "bad",
                    }
                ],
            }
        }
        original = report_service_module.build_final_session_report
        report_service_module.build_final_session_report = lambda **_: final_report
        try:
            markdown = build_session_markdown_report(session_obj, [], [], [], [])
        finally:
            report_service_module.build_final_session_report = original
        self.assertNotIn(secret_token, markdown)
        self.assertNotIn("raw_request_body", markdown)
        self.assertNotIn("raw_response_body", markdown)
        self.assertNotIn("Authorization", markdown)
        self.assertNotIn("Cookie", markdown)
        self.assertNotIn("access_token", markdown)
        self.assertNotIn("password", markdown)


if __name__ == "__main__":
    unittest.main()
