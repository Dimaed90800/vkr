import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.agentic_auth_service import prepare_auth_state


class _FakeQuery:
    def __init__(self, session_obj=None, roles=None):
        self._session_obj = session_obj
        self._roles = roles or []
        self._model = None

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._session_obj

    def all(self):
        return list(self._roles)

    def order_by(self, *args, **kwargs):
        return self


class _FakeDb:
    def __init__(self, session_obj, roles):
        self._session_obj = session_obj
        self._roles = roles

    def query(self, model):
        name = getattr(model, "__name__", "")
        if name == "TestSession":
            return _FakeQuery(session_obj=self._session_obj)
        return _FakeQuery(roles=self._roles)

    def commit(self):
        return None


class AgenticAuthServiceTests(unittest.TestCase):
    @patch("backend.app.services.agentic_auth_service.execute_agentic_tool_command")
    @patch("backend.app.services.agentic_auth_service.build_auth_worker_tasks")
    def test_prepare_auth_state_reports_ready_when_two_tokens_exist(self, mock_tasks, mock_execute):
        session_obj = SimpleNamespace(id=1, status="created")
        roles = [
            SimpleNamespace(role_name="user_a", status="authenticated", access_token="a", last_auth_status=200),
            SimpleNamespace(role_name="user_b", status="authenticated", access_token="b", last_auth_status=200),
        ]
        db = _FakeDb(session_obj, roles)

        result = prepare_auth_state(db, 1, max_steps=4)

        self.assertTrue(result["ready"])
        self.assertEqual(result["reason"], "two_authenticated_roles_available")
        mock_tasks.assert_not_called()
        mock_execute.assert_not_called()

    @patch("backend.app.services.agentic_auth_service.execute_agentic_tool_command")
    @patch("backend.app.services.agentic_auth_service.build_auth_worker_tasks")
    def test_prepare_auth_state_executes_first_available_auth_task(self, mock_tasks, mock_execute):
        session_obj = SimpleNamespace(id=1, status="created")
        roles = [
            SimpleNamespace(role_name="user_a", status="created", access_token=None, last_auth_status=None),
        ]
        db = _FakeDb(session_obj, roles)
        mock_tasks.side_effect = [
            [
                {
                    "task_id": "register_role::user_a",
                    "goal": "Register role user_a",
                    "inputs": {"role_name": "user_a"},
                    "allowed_tools": ["register_role", "list_roles"],
                }
            ],
            [],
        ]
        mock_execute.return_value = {"session_id": 1, "role": {"role_name": "user_a", "status": "registered"}}

        result = prepare_auth_state(db, 1, max_steps=2)

        self.assertFalse(result["ready"])
        self.assertEqual(len(result["executed_steps"]), 1)
        self.assertEqual(result["executed_steps"][0]["tool_name"], "register_role")


if __name__ == "__main__":
    unittest.main()
