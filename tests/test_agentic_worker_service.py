import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.agentic_worker_service import (
    build_auth_worker_tasks,
    build_bola_worker_tasks,
    build_bopla_worker_tasks,
    build_dast_worker_tasks,
    build_discovery_worker_tasks,
    build_probe_worker_tasks,
    build_worker_task_bundle,
)


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._result


class _FakeDB:
    def __init__(self, session_obj):
        self._session_obj = session_obj

    def query(self, *_args, **_kwargs):
        return _FakeQuery(self._session_obj)


class AgenticWorkerServiceTests(unittest.TestCase):
    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_bola_worker_tasks_filters_and_maps_candidates(self, mock_runtime):
        mock_runtime.return_value = {
            "hypotheses": [
                {
                    "candidate_key": "bola_probe::inventory::endpoint::user_a::user_b",
                    "agent_name": "rule_based_bola_agent",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": "http://target/api/orders/1",
                    "http_method": "GET",
                    "description": "Probe object across roles",
                    "payload": {
                        "owner_role": "user_a",
                        "other_role": "user_b",
                        "source_observation_id": 10,
                    },
                },
                {
                    "candidate_key": "verify_bola::7",
                    "agent_name": "rule_based_verifier_agent",
                    "hypothesis_type": "verify_bola",
                    "target_endpoint": "http://target/api/orders/1",
                    "http_method": "GET",
                    "description": "Verify BOLA candidate",
                    "payload": {
                        "owner_role": "user_a",
                        "other_role": "user_b",
                        "finding_id": 7,
                    },
                },
                {
                    "candidate_key": "auth_boundary_probe::1",
                    "agent_name": "rule_based_auth_agent",
                    "hypothesis_type": "auth_boundary_probe",
                    "target_endpoint": "http://target/api/me",
                    "http_method": "GET",
                    "description": "Ignore auth boundary",
                    "payload": {},
                },
            ]
        }

        tasks = build_bola_worker_tasks(db=object(), session_id=12, limit=10)

        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["worker_type"], "replay_agent")
        self.assertEqual(tasks[0]["vulnerability_class"], "BOLA")
        self.assertIn("probe_same_object_across_roles", tasks[0]["allowed_tools"])
        self.assertEqual(tasks[1]["worker_type"], "comparison_agent")
        self.assertIn("compare_observations", tasks[1]["allowed_tools"])

    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_bola_worker_tasks_skips_completed_task_ids(self, mock_runtime):
        mock_runtime.return_value = {
            "hypotheses": [
                {
                    "candidate_key": "bola_probe::one",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": "http://target/api/orders/1",
                    "http_method": "GET",
                    "description": "Probe one",
                    "payload": {"owner_role": "user_a", "other_role": "user_b"},
                },
                {
                    "candidate_key": "bola_probe::two",
                    "hypothesis_type": "bola_probe",
                    "target_endpoint": "http://target/api/orders/2",
                    "http_method": "GET",
                    "description": "Probe two",
                    "payload": {"owner_role": "user_a", "other_role": "user_b"},
                },
            ]
        }
        fake_db = _FakeDB(
            SimpleNamespace(
                last_strategy_json='{"completed_worker_tasks":{"bola":["bola_probe::one"]}}'
            )
        )

        tasks = build_bola_worker_tasks(db=fake_db, session_id=12, limit=10)

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["task_id"], "bola_probe::two")

    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_worker_task_bundle_wraps_bola_tasks(self, mock_runtime):
        mock_runtime.return_value = {"hypotheses": []}
        fake_db = _FakeDB(SimpleNamespace(last_strategy_json='{"completed_worker_tasks":{"bola":["bola_probe::x"]}}'))

        bundle = build_worker_task_bundle(db=fake_db, session_id=99, worker_family="bola")

        self.assertEqual(bundle["worker_family"], "bola")
        self.assertEqual(bundle["tasks_total"], 0)
        self.assertEqual(bundle["tasks"], [])
        self.assertEqual(bundle["completed_task_ids"], ["bola_probe::x"])

    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_auth_worker_tasks_maps_bootstrap_register_login(self, mock_runtime):
        mock_runtime.return_value = {
            "hypotheses": [
                {
                    "candidate_key": "bootstrap_roles::default_pair",
                    "hypothesis_type": "bootstrap_roles",
                    "description": "Create default roles",
                    "payload": {"role_names": ["user_a", "user_b"]},
                },
                {
                    "candidate_key": "register_role::user_a",
                    "hypothesis_type": "register_role",
                    "description": "Register role user_a",
                    "payload": {"role_name": "user_a"},
                },
                {
                    "candidate_key": "login_role::user_a",
                    "hypothesis_type": "login_role",
                    "description": "Login role user_a",
                    "payload": {"role_name": "user_a"},
                },
            ]
        }

        tasks = build_auth_worker_tasks(db=object(), session_id=55, limit=10)

        self.assertEqual(len(tasks), 3)
        self.assertEqual(tasks[0]["allowed_tools"], ["bootstrap_roles", "list_roles"])
        self.assertEqual(tasks[1]["allowed_tools"], ["register_role", "list_roles"])
        self.assertEqual(tasks[2]["allowed_tools"], ["login_role", "list_roles"])

    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_probe_worker_tasks_maps_authenticated_probe(self, mock_runtime):
        mock_runtime.return_value = {
            "hypotheses": [
                {
                    "candidate_key": "authenticated_probe::user_a::GET::http://target/api/items",
                    "hypothesis_type": "authenticated_probe",
                    "target_endpoint": "http://target/api/items",
                    "http_method": "GET",
                    "description": "Probe API endpoint as role user_a",
                    "payload": {
                        "role_name": "user_a",
                        "use_role_token": True,
                        "headers": {"Content-Type": "application/json"},
                    },
                }
            ]
        }

        tasks = build_probe_worker_tasks(db=object(), session_id=77, limit=10)

        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["worker_type"], "replay_agent")
        self.assertEqual(tasks[0]["allowed_tools"], ["replay_request", "list_observations"])

    @patch("backend.app.services.agentic_worker_service.generate_hypotheses_runtime_for_session")
    def test_build_bopla_worker_tasks_maps_probe_and_verify(self, mock_runtime):
        mock_runtime.return_value = {
            "hypotheses": [
                {
                    "candidate_key": "bopla_probe::101",
                    "hypothesis_type": "bopla_probe",
                    "target_endpoint": "http://target/api/dashboard",
                    "http_method": "GET",
                    "description": "Check excessive data exposure",
                    "payload": {
                        "observation_id": 101,
                        "suspected_fields": ["email", "role"],
                    },
                },
                {
                    "candidate_key": "verify_bopla::7",
                    "hypothesis_type": "verify_bopla",
                    "target_endpoint": "http://target/api/dashboard",
                    "http_method": "GET",
                    "description": "Verify BOPLA candidate",
                    "payload": {
                        "finding_id": 7,
                        "observation_id": 101,
                        "expected_fields": ["email", "role"],
                    },
                },
            ]
        }

        tasks = build_bopla_worker_tasks(db=object(), session_id=77, limit=10)

        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["worker_type"], "exposure_agent")
        self.assertEqual(tasks[0]["allowed_tools"], ["infer_bopla", "list_observations"])
        self.assertEqual(tasks[1]["worker_type"], "replay_agent")
        self.assertEqual(tasks[1]["allowed_tools"], ["replay_request", "infer_bopla", "list_observations"])

    def test_build_discovery_worker_tasks_returns_openapi_and_zap_steps(self):
        fake_db = _FakeDB(SimpleNamespace(last_strategy_json="{}"))

        tasks = build_discovery_worker_tasks(db=fake_db, session_id=88, limit=10)

        self.assertEqual(len(tasks), 3)
        self.assertEqual(tasks[0]["allowed_tools"], ["discover_openapi"])
        self.assertEqual(tasks[1]["allowed_tools"], ["zap_spider"])
        self.assertEqual(tasks[2]["allowed_tools"], ["zap_ajax_spider"])
        self.assertEqual(tasks[0]["worker_type"], "discovery_agent")

    def test_build_dast_worker_tasks_returns_zap_scan_steps(self):
        fake_db = _FakeDB(SimpleNamespace(last_strategy_json="{}"))

        tasks = build_dast_worker_tasks(db=fake_db, session_id=89, limit=10)

        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["allowed_tools"], ["zap_baseline_scan"])
        self.assertEqual(tasks[1]["allowed_tools"], ["zap_active_scan"])
        self.assertEqual(tasks[0]["worker_type"], "dast_agent")
        self.assertEqual(tasks[0]["inputs"]["max_spider_sec"], 20)
        self.assertEqual(tasks[0]["inputs"]["max_active_sec"], 45)
        self.assertEqual(tasks[1]["inputs"]["max_wait_sec"], 45)
        self.assertFalse(tasks[1]["inputs"]["recurse"])

    def test_build_worker_task_bundle_supports_discovery_family(self):
        fake_db = _FakeDB(SimpleNamespace(last_strategy_json='{"completed_worker_tasks":{"discovery":["discovery::openapi_inventory"]}}'))

        bundle = build_worker_task_bundle(db=fake_db, session_id=91, worker_family="discovery")

        self.assertEqual(bundle["worker_family"], "discovery")
        self.assertEqual(bundle["completed_task_ids"], ["discovery::openapi_inventory"])
        self.assertEqual(bundle["tasks_total"], 2)

    def test_build_worker_task_bundle_supports_dast_family(self):
        fake_db = _FakeDB(SimpleNamespace(last_strategy_json="{}"))

        bundle = build_worker_task_bundle(db=fake_db, session_id=92, worker_family="dast")

        self.assertEqual(bundle["worker_family"], "dast")
        self.assertEqual(bundle["tasks_total"], 2)


if __name__ == "__main__":
    unittest.main()
