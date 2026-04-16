import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.agentic_tool_service import execute_agentic_tool_command, get_allowed_agentic_tools


def _fake_observation(obs_id=1, endpoint="http://target/api/items", method="GET", role_name="user_a", status_code=200):
    return SimpleNamespace(
        id=obs_id,
        endpoint=endpoint,
        method=method,
        role_name=role_name,
        status_code=status_code,
        body_preview='{"ok":true}',
    )


class AgenticToolServiceTests(unittest.TestCase):
    def test_allowed_tools_include_mutation_and_timing_tools(self):
        tools = get_allowed_agentic_tools()
        self.assertIn("discover_openapi", tools)
        self.assertIn("replay_with_param_override", tools)
        self.assertIn("replay_with_body_override", tools)
        self.assertIn("replay_with_payloads", tools)
        self.assertIn("measure_timing_delta", tools)
        self.assertIn("zap_spider", tools)
        self.assertIn("zap_ajax_spider", tools)
        self.assertIn("zap_active_scan", tools)
        self.assertIn("zap_baseline_scan", tools)

    @patch("backend.app.services.agentic_tool_service._store_observation")
    @patch("backend.app.services.agentic_tool_service.send_request")
    @patch("backend.app.services.agentic_tool_service._get_role")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_replay_with_param_override_applies_query_override_and_auth(
        self,
        mock_get_session,
        mock_get_role,
        mock_send_request,
        mock_store_observation,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10)
        mock_get_role.return_value = SimpleNamespace(role_name="user_a", access_token="abc", token_type="Bearer")
        mock_send_request.return_value = {
            "status_code": 200,
            "text": '{"ok":true}',
            "headers": {"Content-Type": "application/json"},
            "elapsed_ms": 12.0,
        }
        mock_store_observation.return_value = _fake_observation()

        result = execute_agentic_tool_command(
            object(),
            tool_name="replay_with_param_override",
            arguments={
                "session_id": 10,
                "endpoint": "http://target/api/items",
                "method": "GET",
                "role_name": "user_a",
                "use_role_token": True,
                "params": {"page": "1"},
                "param_overrides": {"url": "http://callback.local"},
            },
        )

        _, kwargs = mock_send_request.call_args
        self.assertEqual(kwargs["params"]["page"], "1")
        self.assertEqual(kwargs["params"]["url"], "http://callback.local")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc")
        self.assertEqual(result["applied_overrides"]["url"], "http://callback.local")

    @patch("backend.app.services.agentic_tool_service._store_observation")
    @patch("backend.app.services.agentic_tool_service.send_request")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_replay_with_body_override_applies_nested_override(
        self,
        mock_get_session,
        mock_send_request,
        mock_store_observation,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10)
        mock_send_request.return_value = {
            "status_code": 200,
            "text": '{"ok":true}',
            "headers": {"Content-Type": "application/json"},
            "elapsed_ms": 10.0,
        }
        mock_store_observation.return_value = _fake_observation(method="POST")

        execute_agentic_tool_command(
            object(),
            tool_name="replay_with_body_override",
            arguments={
                "session_id": 10,
                "endpoint": "http://target/api/import",
                "method": "POST",
                "json_body": {"profile": {"avatar_url": "http://safe.local"}},
                "body_overrides": {"profile.avatar_url": "http://169.254.169.254/latest/meta-data"},
            },
        )

        _, kwargs = mock_send_request.call_args
        self.assertEqual(
            kwargs["json_body"]["profile"]["avatar_url"],
            "http://169.254.169.254/latest/meta-data",
        )

    @patch("backend.app.services.agentic_tool_service._store_observation")
    @patch("backend.app.services.agentic_tool_service.send_request")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_replay_with_payloads_collects_anomaly_signals(
        self,
        mock_get_session,
        mock_send_request,
        mock_store_observation,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10)
        mock_send_request.side_effect = [
            {
                "status_code": 200,
                "text": "normal response",
                "headers": {},
                "elapsed_ms": 8.0,
            },
            {
                "status_code": 500,
                "text": "SQL syntax error near '",
                "headers": {},
                "elapsed_ms": 9.0,
            },
        ]
        mock_store_observation.side_effect = [
            _fake_observation(obs_id=1),
            _fake_observation(obs_id=2, status_code=500),
        ]

        result = execute_agentic_tool_command(
            object(),
            tool_name="replay_with_payloads",
            arguments={
                "session_id": 10,
                "endpoint": "http://target/api/search",
                "method": "GET",
                "injection_location": "params",
                "injection_key": "q",
                "payloads": ["test", "' OR 1=1 --"],
            },
        )

        self.assertEqual(result["analysis"]["payloads_total"], 2)
        self.assertIn("server_error_observed", result["analysis"]["signals"])
        self.assertEqual(result["analysis"]["inference"], "possible_injection_signal")

    @patch("backend.app.services.agentic_tool_service._store_observation")
    @patch("backend.app.services.agentic_tool_service.send_request")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_measure_timing_delta_reports_time_based_signal(
        self,
        mock_get_session,
        mock_send_request,
        mock_store_observation,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10)
        mock_send_request.side_effect = [
            {
                "status_code": 200,
                "text": "fast",
                "headers": {},
                "elapsed_ms": 40.0,
            },
            {
                "status_code": 200,
                "text": "slow",
                "headers": {},
                "elapsed_ms": 2240.0,
            },
        ]
        mock_store_observation.side_effect = [
            _fake_observation(obs_id=1),
            _fake_observation(obs_id=2),
        ]

        result = execute_agentic_tool_command(
            object(),
            tool_name="measure_timing_delta",
            arguments={
                "session_id": 10,
                "endpoint": "http://target/api/search",
                "method": "GET",
                "injection_location": "params",
                "injection_key": "q",
                "control_value": "abc",
                "payload_value": "abc'||pg_sleep(2)--",
                "threshold_ms": 1000,
            },
        )

        self.assertAlmostEqual(result["analysis"]["delta_ms"], 2200.0)
        self.assertIn("time_delay_signal", result["analysis"]["signals"])
        self.assertEqual(result["analysis"]["inference"], "possible_time_based_injection")

    @patch("backend.app.services.agentic_tool_service.parse_openapi_spec")
    @patch("backend.app.services.agentic_tool_service.find_openapi_document")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_discover_openapi_returns_parsed_inventory(
        self,
        mock_get_session,
        mock_find_openapi_document,
        mock_parse_openapi_spec,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10, target_url="http://target")
        mock_find_openapi_document.return_value = ("http://target/openapi.json", {"paths": {"/orders": {}}})
        mock_parse_openapi_spec.return_value = [{"path": "/orders", "method": "GET"}]

        result = execute_agentic_tool_command(
            object(),
            tool_name="discover_openapi",
            arguments={"session_id": 10},
        )

        self.assertTrue(result["discovered"])
        self.assertEqual(result["endpoints_total"], 1)
        self.assertEqual(result["openapi_url"], "http://target/openapi.json")

    @patch("backend.app.services.agentic_tool_service.run_spider_and_wait")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_zap_spider_tool_uses_session_target(
        self,
        mock_get_session,
        mock_run_spider_and_wait,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10, target_url="http://target")
        mock_run_spider_and_wait.return_value = {"urls": ["http://target/api/orders", "http://target/api/users"]}

        result = execute_agentic_tool_command(
            object(),
            tool_name="zap_spider",
            arguments={"session_id": 10, "max_wait_sec": 15},
        )

        mock_run_spider_and_wait.assert_called_once_with("http://target", max_wait_sec=15)
        self.assertEqual(result["urls_total"], 2)

    @patch("backend.app.services.agentic_tool_service.run_ajax_spider_and_wait")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_zap_ajax_spider_tool_uses_session_target(
        self,
        mock_get_session,
        mock_run_ajax_spider_and_wait,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10, target_url="http://target")
        mock_run_ajax_spider_and_wait.return_value = {"urls": ["http://target/api/dashboard"]}

        result = execute_agentic_tool_command(
            object(),
            tool_name="zap_ajax_spider",
            arguments={"session_id": 10, "max_wait_sec": 20},
        )

        mock_run_ajax_spider_and_wait.assert_called_once_with("http://target", max_wait_sec=20)
        self.assertEqual(result["urls_total"], 1)

    @patch("backend.app.services.agentic_tool_service.run_active_scan_and_wait")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_zap_active_scan_tool_returns_scan_payload(
        self,
        mock_get_session,
        mock_run_active_scan_and_wait,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10, target_url="http://target")
        mock_run_active_scan_and_wait.return_value = {"scan_id": "7", "status": {"status": "100"}}

        result = execute_agentic_tool_command(
            object(),
            tool_name="zap_active_scan",
            arguments={"session_id": 10, "max_wait_sec": 25, "recurse": False},
        )

        mock_run_active_scan_and_wait.assert_called_once_with(
            "http://target",
            max_wait_sec=25,
            recurse=False,
        )
        self.assertEqual(result["scan"]["scan_id"], "7")

    @patch("backend.app.services.agentic_tool_service.run_zap_baseline")
    @patch("backend.app.services.agentic_tool_service._get_session")
    def test_zap_baseline_scan_tool_returns_baseline_result(
        self,
        mock_get_session,
        mock_run_zap_baseline,
    ):
        mock_get_session.return_value = SimpleNamespace(id=10, target_name="crapi", target_url="http://target")
        mock_run_zap_baseline.return_value = {"tool": "zap", "findings_total": 3}

        result = execute_agentic_tool_command(
            object(),
            tool_name="zap_baseline_scan",
            arguments={
                "session_id": 10,
                "profile": "mixed",
                "max_spider_sec": 10,
                "max_active_sec": 20,
                "use_ajax_spider": True,
                "import_openapi": True,
            },
        )

        mock_run_zap_baseline.assert_called_once_with(
            target_name="crapi",
            target_url="http://target",
            profile="mixed",
            max_spider_sec=10,
            max_active_sec=20,
            use_ajax_spider=True,
            import_openapi=True,
        )
        self.assertEqual(result["result"]["tool"], "zap")


if __name__ == "__main__":
    unittest.main()
