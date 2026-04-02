import unittest

from backend.app.services.dify_service import (
    _extract_candidate_list,
    _normalize_bopla_candidate,
)


class DifyBoplaNormalizationTests(unittest.TestCase):
    def test_extract_candidate_list_accepts_structured_output_wrapper(self):
        candidates = _extract_candidate_list(
            {
                "structured_output": {
                    "candidates": [
                        {
                            "agent_name": "dify_bopla_agent",
                            "hypothesis_type": "bopla_probe",
                        }
                    ]
                }
            },
            agent_label="BOPLA Agent",
        )

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["hypothesis_type"], "bopla_probe")

    def test_bopla_probe_prefers_observation_endpoint_and_fields(self):
        candidate = {
            "agent_name": "dify_bopla_agent",
            "hypothesis_type": "bopla_probe",
            "target_endpoint": "",
            "http_method": "GET",
            "description": "",
            "payload": {
                "observation_id": 797,
            },
        }

        normalized = _normalize_bopla_candidate(
            candidate,
            candidate_findings_compact=[],
            recent_observations_compact=[
                {
                    "id": 797,
                    "endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                    "suspected_fields": ["posts.author.email"],
                }
            ],
        )

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["payload"]["observation_id"], 797)
        self.assertEqual(
            normalized["target_endpoint"],
            "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
        )
        self.assertEqual(normalized["payload"]["suspected_fields"], ["posts.author.email"])
        self.assertTrue(normalized["description"])

    def test_verify_bopla_prefers_endpoint_match_for_finding_id(self):
        candidate = {
            "agent_name": "dify_bopla_agent",
            "hypothesis_type": "verify_bopla",
            "target_endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            "http_method": "GET",
            "candidate_key": "verify_bopla::15",
            "description": "",
        }

        normalized = _normalize_bopla_candidate(
            candidate,
            candidate_findings_compact=[
                {
                    "id": 179,
                    "endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                    "exposed_fields": ["posts.author.email"],
                }
            ],
            recent_observations_compact=[],
        )

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["payload"]["finding_id"], 179)
        self.assertEqual(normalized["candidate_key"], "verify_bopla::179")
        self.assertEqual(normalized["payload"]["expected_fields"], ["posts.author.email"])
        self.assertTrue(normalized["description"])

    def test_verify_bopla_without_finding_context_is_dropped(self):
        candidate = {
            "agent_name": "dify_bopla_agent",
            "hypothesis_type": "verify_bopla",
            "target_endpoint": "http://host.docker.internal:8888/identity/api/auth/login",
            "http_method": "POST",
            "description": "Verify token exposure in login response",
            "payload": {
                "observation_id": 856,
                "suspected_fields": ["token"],
            },
        }

        normalized = _normalize_bopla_candidate(
            candidate,
            candidate_findings_compact=[],
            recent_observations_compact=[],
        )

        self.assertIsNone(normalized)

    def test_bopla_probe_on_login_token_is_dropped_as_expected_auth(self):
        candidate = {
            "agent_name": "dify_bopla_agent",
            "hypothesis_type": "bopla_probe",
            "target_endpoint": "http://host.docker.internal:8888/identity/api/auth/login",
            "http_method": "POST",
            "description": "Check for excessive exposure of token during login",
            "payload": {
                "observation_id": 872,
                "suspected_fields": ["token"],
            },
        }

        normalized = _normalize_bopla_candidate(
            candidate,
            candidate_findings_compact=[],
            recent_observations_compact=[],
        )

        self.assertIsNone(normalized)


if __name__ == "__main__":
    unittest.main()
