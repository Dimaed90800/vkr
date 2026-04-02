import unittest

from backend.app.services.evidence_service import build_auth_probe_interpretation


class EvidenceServiceTests(unittest.TestCase):
    def test_build_auth_probe_interpretation_detects_success_on_high_value_endpoint(self):
        finding = build_auth_probe_interpretation(
            action_executed="auth_boundary_probe",
            status_code=200,
            endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
        )

        self.assertEqual(finding["finding_type"], "possible_authentication_bypass")
        self.assertEqual(finding["severity"], "high")

    def test_build_auth_probe_interpretation_creates_low_severity_signal_for_known_route_404_405(self):
        finding = build_auth_probe_interpretation(
            action_executed="auth_boundary_probe",
            status_code=405,
            endpoint="http://host.docker.internal:8888/workshop/api/merchant/contact_mechanic",
            source_observation_id=101,
        )

        self.assertEqual(finding["finding_type"], "auth_boundary_signal")
        self.assertEqual(finding["severity"], "low")

    def test_build_auth_probe_interpretation_ignores_auth_endpoints_and_unsuccessful_responses(self):
        self.assertEqual(
            build_auth_probe_interpretation(
                action_executed="anonymous_probe",
                status_code=200,
                endpoint="http://host.docker.internal:8888/identity/api/auth/login",
            ),
            {},
        )
        self.assertEqual(
            build_auth_probe_interpretation(
                action_executed="tokenless_replay_probe",
                status_code=401,
                endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            ),
            {},
        )
        self.assertEqual(
            build_auth_probe_interpretation(
                action_executed="auth_boundary_probe",
                status_code=404,
                endpoint="http://host.docker.internal:8888/workshop/api/mechanic/mechanics",
            )["finding_type"],
            "auth_boundary_signal",
        )


if __name__ == "__main__":
    unittest.main()
