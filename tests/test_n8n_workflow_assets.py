import json
import unittest
from pathlib import Path


class N8nWorkflowAssetTests(unittest.TestCase):
    def test_run_batch_with_reports_workflow_exists_and_targets_backend_endpoint(self):
        workflow_path = Path("n8n/workflows/run_batch_with_reports.json")

        self.assertTrue(workflow_path.exists())

        workflow = json.loads(workflow_path.read_text(encoding="utf-8"))
        self.assertEqual(workflow["name"], "Batch Experiments With Reports")

        nodes = workflow.get("nodes", [])
        node_names = {node.get("name") for node in nodes}
        self.assertIn("Manual Trigger", node_names)
        self.assertIn("Run Batch With Reports", node_names)

        http_nodes = [node for node in nodes if node.get("name") == "Run Batch With Reports"]
        self.assertEqual(len(http_nodes), 1)
        self.assertEqual(
            http_nodes[0]["parameters"]["url"],
            "http://host.docker.internal:8000/experiments/run-batch-with-reports",
        )

    def test_run_batch_job_polling_workflow_exists_and_targets_automation_endpoints(self):
        workflow_path = Path("n8n/workflows/run_batch_job_polling.json")

        self.assertTrue(workflow_path.exists())

        workflow = json.loads(workflow_path.read_text(encoding="utf-8"))
        self.assertEqual(workflow["name"], "Batch Job Runner (Polling)")

        nodes = workflow.get("nodes", [])
        node_names = {node.get("name") for node in nodes}
        self.assertIn("Manual Trigger", node_names)
        self.assertIn("Start Batch Job", node_names)
        self.assertIn("Get Job Status", node_names)
        self.assertIn("If Finished", node_names)
        self.assertIn("Build Job Summary", node_names)

        start_nodes = [node for node in nodes if node.get("name") == "Start Batch Job"]
        self.assertEqual(len(start_nodes), 1)
        self.assertEqual(
            start_nodes[0]["parameters"]["url"],
            "http://host.docker.internal:8000/automation/run-batch-job",
        )

        status_nodes = [node for node in nodes if node.get("name") == "Get Job Status"]
        self.assertEqual(len(status_nodes), 1)
        self.assertEqual(
            status_nodes[0]["parameters"]["url"],
            "={{ 'http://host.docker.internal:8000/automation/jobs/' + $json.job_id }}",
        )


if __name__ == "__main__":
    unittest.main()
