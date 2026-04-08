import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from backend.app.services.experiment_batch_service import export_batch_job_artifacts


class AutomationJobAssetTests(unittest.TestCase):
    def test_export_batch_job_artifacts_writes_expected_files(self):
        batch_result = {
            "batch": {
                "target_name": "crapi",
                "target_url": "http://host.docker.internal:8888",
                "profile": "mixed",
                "judge_modes": ["rule_based", "dify"],
                "runs_total": 2,
            },
            "comparison_report": {"executive_summary": {"headline": "summary"}},
            "session_reports": [
                {
                    "session_id": 111,
                    "judge_mode": "rule_based",
                    "saved_report_path": "/app/exports/jobs/job-1/reports/session_111_llm_report.md",
                    "provider": "dify",
                    "used_fallback": False,
                }
            ],
        }

        with TemporaryDirectory() as tmpdir:
            artifact_paths = export_batch_job_artifacts(
                job_id="job-1",
                batch_result=batch_result,
                export_root=Path(tmpdir),
            )

            self.assertTrue(Path(artifact_paths["batch_result_json"]).exists())
            self.assertTrue(Path(artifact_paths["comparison_report_json"]).exists())
            self.assertTrue(Path(artifact_paths["session_reports_json"]).exists())
            self.assertTrue(Path(artifact_paths["summary_markdown"]).exists())

            summary_text = Path(artifact_paths["summary_markdown"]).read_text(encoding="utf-8")
            self.assertIn("Automation Job job-1", summary_text)

            session_reports = json.loads(Path(artifact_paths["session_reports_json"]).read_text(encoding="utf-8"))
            self.assertEqual(session_reports[0]["session_id"], 111)


if __name__ == "__main__":
    unittest.main()
