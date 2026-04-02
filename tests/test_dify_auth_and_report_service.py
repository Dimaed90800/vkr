import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from backend.app.services.dify_service import call_dify_auth_agent, call_dify_report_agent
from backend.app.services.llm_report_service import build_session_llm_report


class DifyAuthAndReportServiceTests(unittest.TestCase):
    def test_call_dify_auth_agent_normalizes_probe_candidates(self):
        fake_response = Mock()
        fake_response.status_code = 200
        fake_response.json.return_value = {
            "data": {
                "outputs": {
                    "candidates": [
                        {
                            "hypothesis_type": "auth_boundary_probe",
                            "target_endpoint": "/identity/api/v2/user/dashboard",
                            "http_method": "GET",
                            "description": "Probe dashboard with invalid token",
                            "payload": {
                                "source_role": "user_a",
                            },
                        },
                        {
                            "hypothesis_type": "verify_auth_boundary",
                            "target_endpoint": "http://host.docker.internal:8888/workshop/api/mechanic/mechanics",
                            "payload": {
                                "finding_id": 501,
                                "expected_status_code": 404,
                            },
                        },
                    ]
                }
            }
        }

        with patch("backend.app.services.dify_service.AUTH_AGENT_DIFY_API_KEY", "test-key"):
            with patch("backend.app.services.dify_service.requests.post", return_value=fake_response):
                candidates = call_dify_auth_agent(
                    session_id=1,
                    roles_compact=[{"role_name": "user_a"}],
                    recent_observations_compact=[],
                    candidate_findings_compact=[
                        {
                            "id": 501,
                            "endpoint": "http://host.docker.internal:8888/workshop/api/mechanic/mechanics",
                            "expected_status_code": 404,
                        }
                    ],
                    target_base_url="http://host.docker.internal:8888",
                )

        self.assertEqual(len(candidates), 2)
        self.assertEqual(candidates[0]["hypothesis_type"], "auth_boundary_probe")
        self.assertEqual(
            candidates[0]["target_endpoint"],
            "http://host.docker.internal:8888/identity/api/v2/user/dashboard",
        )
        self.assertEqual(
            candidates[0]["payload"]["headers"]["Authorization"],
            "Bearer invalid-auth-boundary-token",
        )
        self.assertEqual(candidates[1]["hypothesis_type"], "verify_auth_boundary")
        self.assertEqual(candidates[1]["payload"]["finding_id"], 501)
        self.assertEqual(candidates[1]["payload"]["expected_status_code"], 404)

    def test_call_dify_report_agent_extracts_textual_report(self):
        fake_response = Mock()
        fake_response.status_code = 200
        fake_response.json.return_value = {
            "data": {
                "outputs": {
                    "report_markdown": "# Report\n\nCritical BOLA found.\n\nFix server-side ownership checks."
                }
            }
        }

        with patch("backend.app.services.dify_service.REPORT_AGENT_DIFY_API_KEY", "report-key"):
            with patch("backend.app.services.dify_service.requests.post", return_value=fake_response):
                result = call_dify_report_agent(
                    session_id=1,
                    target_name="crapi",
                    target_url="http://target",
                    executive_summary={"risk_level": "high"},
                    risk_summary={"total_findings": 1},
                    key_conclusion={"status": "security_issue_candidates_found"},
                    top_findings=[],
                )

        self.assertEqual(result["provider"], "dify")
        self.assertIn("Critical BOLA found", result["report_text"])

    def test_call_dify_auth_agent_drops_invalid_verify_auth_boundary_finding_id(self):
        fake_response = Mock()
        fake_response.status_code = 200
        fake_response.json.return_value = {
            "data": {
                "outputs": {
                    "candidates": [
                        {
                            "hypothesis_type": "verify_auth_boundary",
                            "target_endpoint": "/identity/api/v2/user/dashboard",
                            "payload": {
                                "finding_id": 307,
                                "expected_status_code": 404,
                            },
                        }
                    ]
                }
            }
        }

        with patch("backend.app.services.dify_service.AUTH_AGENT_DIFY_API_KEY", "test-key"):
            with patch("backend.app.services.dify_service.requests.post", return_value=fake_response):
                candidates = call_dify_auth_agent(
                    session_id=1,
                    roles_compact=[{"role_name": "user_a"}],
                    recent_observations_compact=[],
                    candidate_findings_compact=[],
                    target_base_url="http://host.docker.internal:8888",
                )

        self.assertEqual(candidates, [])

    def test_build_session_llm_report_falls_back_to_local_report(self):
        session_obj = SimpleNamespace(
            id=77,
            target_name="crapi",
            target_url="http://host.docker.internal:8888",
            status="stopped",
            created_at="2026-04-02",
            rounds_completed=4,
            max_rounds=10,
            budget_requests_used=12,
            budget_requests_total=100,
            stop_reason="completed",
            last_strategy_json="{}",
        )
        finding = SimpleNamespace(
            id=1,
            finding_type="possible_bola",
            severity="high",
            endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
            related_hypothesis_id=1,
            related_observation_ids="[]",
            title="Possible BOLA on vehicle location",
            description="Cross-role access returned equivalent vehicle location data.",
            evidence_json='{"owner_role":"user_a","other_role":"user_b","status_owner":200,"status_other":200}',
            verification_status="confirmed",
            created_at="2026-04-02",
        )

        with TemporaryDirectory() as tmpdir:
            with patch(
                "backend.app.services.llm_report_service.call_dify_report_agent",
                side_effect=Exception("REPORT_AGENT_DIFY_API_KEY is not configured"),
            ):
                result = build_session_llm_report(
                    session_obj=session_obj,
                    roles=[],
                    findings=[finding],
                    judge_decisions=[],
                    observations=[],
                    hypotheses=[],
                    agent_memory_rows=[],
                    agent_judge_feedback_rows=[],
                    export_root=Path(tmpdir),
                )

            self.assertTrue(result["used_fallback"])
            self.assertEqual(result["provider"], "local_fallback")
            self.assertIn("Possible BOLA on vehicle location", result["report_text"])
            self.assertIn("Recommended remediation", result["report_text"])
            self.assertTrue(Path(result["saved_report_path"]).exists())


if __name__ == "__main__":
    unittest.main()
