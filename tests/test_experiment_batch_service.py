import unittest
from types import SimpleNamespace
from unittest.mock import patch

from backend.app.services.experiment_batch_service import build_run_batch_response


class ExperimentBatchServiceTests(unittest.TestCase):
    @patch("backend.app.services.experiment_batch_service.build_run_batch_logical_agent_rows", return_value=[])
    @patch("backend.app.services.experiment_batch_service.build_run_batch_logical_agent_summary", return_value={})
    @patch("backend.app.services.experiment_batch_service.build_experiment_comparison_report")
    @patch("backend.app.services.experiment_batch_service.run_experiment_scenario")
    @patch("backend.app.services.experiment_batch_service.run_zap_baseline")
    def test_build_run_batch_response_appends_zap_baseline(
        self,
        zap_baseline_mock,
        run_experiment_mock,
        comparison_mock,
        _logical_summary_mock,
        _logical_rows_mock,
    ):
        zap_baseline_mock.return_value = {
            "tool": "zap",
            "name": "OWASP ZAP Baseline",
            "profile": "mixed",
            "target_name": "crapi",
            "findings_total": 4,
            "confirmed_findings": 0,
            "confirmed_bola": 0,
            "confirmed_bopla": 0,
            "confirmed_auth_findings": 0,
            "requests_used": 80,
            "time_used": 120,
        }
        run_experiment_mock.return_value = {
            "experiment_id": 1,
            "session_id": 10,
            "judge_mode": "rule_based",
            "profile": "mixed",
            "target_name": "crapi",
            "target_url": "http://target",
            "result": {
                "findings_total": 2,
                "confirmed_findings": 2,
                "confirmed_bola": 0,
                "confirmed_bopla": 1,
                "confirmed_auth_findings": 1,
                "fallback_count": 0,
                "avg_score": 0.8,
            },
        }
        comparison_mock.return_value = {
            "totals": {},
            "group_summary": {},
            "logical_agent_group_summary": {},
            "profile_comparisons": [],
            "pairwise_profile_comparisons": [],
            "finding_stability_summary": {"stable_findings_count": 0, "stable_findings": [], "per_mode": {}},
            "portability_summary": {"targets_total": 1, "targets": [], "supports_cross_target_comparison": False, "grouped_rows": []},
            "external_baseline_comparisons": [],
            "executive_summary": {"headline": "", "message": ""},
        }
        fake_db = _FakeDB()

        response = build_run_batch_response(
            db=fake_db,
            payload={
                "target_name": "crapi",
                "target_url": "http://target",
                "profile": "mixed",
                "judge_modes": ["rule_based"],
                "max_rounds": 5,
                "zap_baseline": {"enabled": True, "use_ajax_spider": True},
            },
        )

        self.assertEqual(response["batch"]["external_baselines"][0]["tool"], "zap")
        zap_baseline_mock.assert_called_once()
        comparison_filters = comparison_mock.call_args.kwargs["filters"]
        self.assertEqual(comparison_filters["external_baselines"][0]["tool"], "zap")


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *_args, **_kwargs):
        return self

    def all(self):
        return list(self._rows)


class _FakeDB:
    def query(self, model):
        return _FakeQuery([])
