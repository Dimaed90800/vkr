import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.agent_hypothesis_service import generate_auth_agent_hypotheses
from backend.app.services.campaign_execution_service import execute_hypothesis


class AuthenticationAgentServiceTests(unittest.TestCase):
    def test_generate_auth_agent_adds_boundary_and_tokenless_probes(self):
        observations = [
            SimpleNamespace(
                id=101,
                endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                method="GET",
                role_name="user_a",
                status_code=200,
                request_params="{}",
                request_body="{}",
            )
        ]

        hypotheses = generate_auth_agent_hypotheses([], observations)
        hypothesis_types = {item["hypothesis_type"] for item in hypotheses}

        self.assertIn("anonymous_probe", hypothesis_types)
        self.assertIn("tokenless_replay_probe", hypothesis_types)
        self.assertIn("auth_boundary_probe", hypothesis_types)

    def test_generate_auth_agent_uses_api_items_to_expand_surface(self):
        api_items = [
            SimpleNamespace(
                path="http://host.docker.internal:8888/identity/api/v2/user/dashboard",
                method="GET",
            )
        ]

        hypotheses = generate_auth_agent_hypotheses(
            [],
            [],
            api_items=api_items,
            target_url="http://host.docker.internal:8888",
        )

        endpoints = {item["target_endpoint"] for item in hypotheses}
        self.assertIn("http://host.docker.internal:8888/identity/api/v2/user/dashboard", endpoints)
        self.assertTrue(any(item["candidate_key"].startswith("auth_boundary_probe::") for item in hypotheses))

    def test_generate_auth_agent_spreads_across_multiple_high_value_targets(self):
        api_items = [
            SimpleNamespace(
                path="http://host.docker.internal:8888/identity/api/v2/user/dashboard",
                method="GET",
            ),
            SimpleNamespace(
                path="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                method="GET",
            ),
            SimpleNamespace(
                path="http://host.docker.internal:8888/workshop/api/shop/products",
                method="GET",
            ),
        ]

        hypotheses = generate_auth_agent_hypotheses(
            [],
            [],
            api_items=api_items,
            target_url="http://host.docker.internal:8888",
        )

        auth_probe_endpoints = {
            item["target_endpoint"]
            for item in hypotheses
            if item["hypothesis_type"] in {"anonymous_probe", "tokenless_replay_probe", "auth_boundary_probe"}
        }

        self.assertIn("http://host.docker.internal:8888/identity/api/v2/user/dashboard", auth_probe_endpoints)
        self.assertIn("http://host.docker.internal:8888/community/api/v2/community/posts/recent", auth_probe_endpoints)
        self.assertIn("http://host.docker.internal:8888/workshop/api/shop/products", auth_probe_endpoints)

    def test_generate_auth_agent_skips_recent_duplicate_probe_modes(self):
        endpoint = "http://host.docker.internal:8888/community/api/v2/community/posts/recent"
        observations = [
            SimpleNamespace(
                id=101,
                endpoint=endpoint,
                method="GET",
                role_name="user_a",
                status_code=200,
                request_params="{}",
                request_body="{}",
                request_headers='{"Authorization":"Bearer valid-token"}',
            ),
            SimpleNamespace(
                id=102,
                endpoint=endpoint,
                method="GET",
                role_name=None,
                status_code=401,
                request_params="{}",
                request_body="{}",
                request_headers='{"Content-Type":"application/json"}',
            ),
            SimpleNamespace(
                id=103,
                endpoint=endpoint,
                method="GET",
                role_name=None,
                status_code=401,
                request_params="{}",
                request_body="{}",
                request_headers='{"Authorization":"Bearer invalid-auth-boundary-token","Content-Type":"application/json"}',
            ),
        ]

        hypotheses = generate_auth_agent_hypotheses([], observations)
        endpoint_hypotheses = [item for item in hypotheses if item["target_endpoint"] == endpoint]
        hypothesis_types = {item["hypothesis_type"] for item in endpoint_hypotheses}

        self.assertNotIn("anonymous_probe", hypothesis_types)
        self.assertNotIn("tokenless_replay_probe", hypothesis_types)
        self.assertNotIn("auth_boundary_probe", hypothesis_types)

    def test_generate_auth_agent_prefers_fresh_targets_over_repeat_boundary_probe(self):
        repeated_endpoint = "http://host.docker.internal:8888/community/api/v2/community/posts/recent"
        fresh_endpoint = "http://host.docker.internal:8888/identity/api/v2/user/dashboard"
        observations = [
            SimpleNamespace(
                id=101,
                endpoint=repeated_endpoint,
                method="GET",
                role_name="user_a",
                status_code=200,
                request_params="{}",
                request_body="{}",
                request_headers='{"Authorization":"Bearer valid-token"}',
            ),
            SimpleNamespace(
                id=102,
                endpoint=repeated_endpoint,
                method="GET",
                role_name=None,
                status_code=401,
                request_params="{}",
                request_body="{}",
                request_headers='{"Content-Type":"application/json"}',
            ),
            SimpleNamespace(
                id=103,
                endpoint=repeated_endpoint,
                method="GET",
                role_name=None,
                status_code=401,
                request_params="{}",
                request_body="{}",
                request_headers='{"Authorization":"Bearer invalid-auth-boundary-token","Content-Type":"application/json"}',
            ),
        ]
        api_items = [SimpleNamespace(path=fresh_endpoint, method="GET")]

        hypotheses = generate_auth_agent_hypotheses(
            [],
            observations,
            api_items=api_items,
            target_url="http://host.docker.internal:8888",
        )

        fresh_hypothesis = next(
            item
            for item in hypotheses
            if item["target_endpoint"] == fresh_endpoint and item["hypothesis_type"] == "auth_boundary_probe"
        )

        self.assertFalse(
            any(
                item["target_endpoint"] == repeated_endpoint and item["hypothesis_type"] == "auth_boundary_probe"
                for item in hypotheses
            )
        )
        self.assertGreaterEqual(fresh_hypothesis["confidence"], 0.85)

    def test_generate_auth_agent_adds_verify_hypothesis_for_auth_boundary_signal(self):
        findings = [
            SimpleNamespace(
                id=501,
                finding_type="auth_boundary_signal",
                verification_status="candidate",
                endpoint="http://host.docker.internal:8888/workshop/api/merchant/contact_mechanic",
                evidence_json='{"status_code":405,"action_executed":"auth_boundary_probe"}',
            )
        ]

        hypotheses = generate_auth_agent_hypotheses([], [], findings=findings)

        verify_hypothesis = next(
            item for item in hypotheses if item["hypothesis_type"] == "verify_auth_boundary"
        )
        self.assertEqual(
            verify_hypothesis["target_endpoint"],
            "http://host.docker.internal:8888/workshop/api/merchant/contact_mechanic",
        )
        self.assertEqual(verify_hypothesis["payload"]["expected_status_code"], 405)

    def test_execute_auth_boundary_probe_uses_generic_http_execution(self):
        selected = SimpleNamespace(
            hypothesis_type="auth_boundary_probe",
            target_endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            http_method="GET",
            payload_json='{"headers":{"Authorization":"Bearer invalid-auth-boundary-token","Content-Type":"application/json"},"params":{},"json_body":{},"source_role":"user_a"}',
            status="candidate",
        )
        session_obj = SimpleNamespace(id=77, target_url="http://host.docker.internal:8888", status="active")

        class DummyDB:
            def add(self, _obj):
                return None

            def commit(self):
                return None

            def refresh(self, obj):
                setattr(obj, "id", 555)

        with patch("backend.app.services.campaign_execution_service.send_request", return_value={
            "status_code": 401,
            "headers": {},
            "text": "unauthorized",
        }):
            result, request_count = execute_hypothesis(DummyDB(), session_obj, selected)

        self.assertEqual(request_count, 1)
        self.assertEqual(result["action_executed"], "auth_boundary_probe")
        self.assertEqual(result["status_code"], 401)
        self.assertEqual(result["source_role"], "user_a")


if __name__ == "__main__":
    unittest.main()
