import unittest
from unittest.mock import patch

from backend.app.services.zap_baseline_service import run_zap_baseline


class ZapBaselineServiceTests(unittest.TestCase):
    @patch("backend.app.services.zap_baseline_service.time.time", side_effect=[100.0, 115.0])
    @patch("backend.app.services.zap_baseline_service.list_alerts")
    @patch("backend.app.services.zap_baseline_service.run_active_scan_and_wait")
    @patch("backend.app.services.zap_baseline_service.run_ajax_spider_and_wait")
    @patch("backend.app.services.zap_baseline_service.run_spider_and_wait")
    @patch("backend.app.services.zap_baseline_service.import_openapi_url")
    @patch("backend.app.services.zap_baseline_service.find_openapi_document")
    @patch("backend.app.services.zap_baseline_service.number_of_messages")
    def test_run_zap_baseline_returns_normalized_external_baseline(
        self,
        messages_mock,
        find_openapi_mock,
        import_openapi_mock,
        spider_mock,
        ajax_mock,
        active_mock,
        alerts_mock,
        _time_mock,
    ):
        messages_mock.side_effect = [
            {"numberOfMessages": "10"},
            {"numberOfMessages": "37"},
        ]
        find_openapi_mock.return_value = ("http://target/openapi.json", {"openapi": "3.0.0"})
        alerts_mock.return_value = {
            "alerts": [
                {
                    "pluginId": "1",
                    "url": "http://target/a",
                    "param": "id",
                    "alertRef": "ref-a",
                    "risk": "High",
                },
                {
                    "pluginId": "1",
                    "url": "http://target/a",
                    "param": "id",
                    "alertRef": "ref-a",
                    "risk": "High",
                },
                {
                    "pluginId": "2",
                    "url": "http://target/b",
                    "param": "",
                    "alertRef": "ref-b",
                    "risk": "Medium",
                },
            ]
        }

        result = run_zap_baseline(
            target_name="crapi",
            target_url="http://target",
            profile="mixed",
            use_ajax_spider=False,
        )

        self.assertEqual(result["tool"], "zap")
        self.assertEqual(result["findings_total"], 2)
        self.assertEqual(result["confirmed_findings"], 0)
        self.assertEqual(result["requests_used"], 27)
        self.assertEqual(result["time_used"], 15)
        self.assertEqual(result["notes"]["risk_counts"]["high"], 1)
        self.assertEqual(result["notes"]["risk_counts"]["medium"], 1)
        self.assertTrue(result["notes"]["openapi_imported"])
        import_openapi_mock.assert_called_once()
        spider_mock.assert_called_once()
        ajax_mock.assert_not_called()
        active_mock.assert_called_once()

    @patch("backend.app.services.zap_baseline_service.time.time", side_effect=[200.0, 205.0])
    @patch("backend.app.services.zap_baseline_service.list_alerts", return_value={"alerts": []})
    @patch("backend.app.services.zap_baseline_service.run_active_scan_and_wait")
    @patch("backend.app.services.zap_baseline_service.run_ajax_spider_and_wait")
    @patch("backend.app.services.zap_baseline_service.run_spider_and_wait")
    @patch("backend.app.services.zap_baseline_service.find_openapi_document", return_value=(None, None))
    @patch("backend.app.services.zap_baseline_service.number_of_messages")
    def test_run_zap_baseline_can_use_ajax_spider(
        self,
        messages_mock,
        _find_openapi_mock,
        spider_mock,
        ajax_mock,
        active_mock,
        _alerts_mock,
        _time_mock,
    ):
        messages_mock.side_effect = [
            {"numberOfMessages": "0"},
            {"numberOfMessages": "5"},
        ]

        result = run_zap_baseline(
            target_name="crapi",
            target_url="http://target",
            profile="mixed",
            use_ajax_spider=True,
            import_openapi=False,
        )

        self.assertEqual(result["requests_used"], 5)
        self.assertEqual(result["notes"]["use_ajax_spider"], True)
        spider_mock.assert_called_once()
        ajax_mock.assert_called_once()
        active_mock.assert_called_once()
