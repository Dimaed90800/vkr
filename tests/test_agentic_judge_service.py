import json
import unittest
from types import SimpleNamespace

from backend.app.services.agentic_judge_service import apply_judge_verdict, ingest_worker_result


class _FakeQuery:
    def __init__(self, item):
        self._item = item

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._item


class _FakeDb:
    def __init__(self, finding):
        self._finding = finding

    def query(self, model):
        return _FakeQuery(self._finding)

    def commit(self):
        return None

    def refresh(self, item):
        return None


class AgenticJudgeServiceTests(unittest.TestCase):
    def test_apply_judge_verdict_confirms_finding(self):
        finding = SimpleNamespace(
            id=5,
            session_id=1,
            finding_type="possible_bola",
            title="Possible Broken Object Level Authorization",
            endpoint="http://target/api/object/1",
            severity="high",
            verification_status="candidate",
            description="desc",
            evidence_json=json.dumps({"analysis": {"inference": "possible_bola"}}),
        )

        result = apply_judge_verdict(
            _FakeDb(finding),
            session_id=1,
            finding_id=5,
            status="confirmed",
            reason="Evidence confirms cross-role access.",
            finding_type="BOLA",
            next_action="save_finding",
        )

        self.assertEqual(result["finding"]["verification_status"], "confirmed")
        self.assertEqual(result["judge_verdict"]["status"], "confirmed")

    def test_ingest_worker_result_creates_bopla_candidate(self):
        session_obj = SimpleNamespace(id=12, last_strategy_json="{}")
        finding_store = []

        class _SessionQuery:
            def filter(self, *args, **kwargs):
                return self

            def first(self):
                return session_obj

        class _FindingQuery:
            def filter(self, *args, **kwargs):
                return self

            def all(self):
                return []

            def first(self):
                return None

        class _Db:
            def query(self, model):
                if getattr(model, "__name__", "") == "TestSession":
                    return _SessionQuery()
                if getattr(model, "__name__", "") == "Finding":
                    return _FindingQuery()
                raise AssertionError(f"Unexpected model query: {getattr(model, '__name__', model)}")

            def add(self, obj):
                obj.id = 99
                finding_store.append(obj)

            def commit(self):
                return None

            def refresh(self, item):
                return None

        result = ingest_worker_result(
            _Db(),
            session_id=12,
            worker_type="exposure_agent",
            tool_name="infer_bopla",
            result={
                "observation": {
                    "id": 101,
                    "endpoint": "http://target/api/dashboard",
                    "status_code": 200,
                },
                "analysis": {
                    "observation_id": 101,
                    "endpoint": "http://target/api/dashboard",
                    "status_code": 200,
                    "exposed_fields": ["email", "role"],
                    "inference": "possible_bopla",
                },
            },
            task_id="bopla_probe::101",
            vulnerability_class="BOPLA",
        )

        self.assertEqual(len(finding_store), 1)
        self.assertEqual(finding_store[0].finding_type, "possible_bopla")
        self.assertEqual(result["candidate_finding"]["type"], "possible_bopla")
        self.assertEqual(result["evidence_summary"]["observation_id"], 101)


if __name__ == "__main__":
    unittest.main()
