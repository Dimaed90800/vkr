import unittest
from types import SimpleNamespace

from backend.app.services.judge_service import calculate_dynamic_priority


class JudgeServiceCoverageTests(unittest.TestCase):
    def test_dynamic_priority_rewards_undercovered_object_access_bucket(self):
        candidate = SimpleNamespace(
            hypothesis_type="bola_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
            http_method="GET",
            confidence=0.8,
            coverage_gain=0.8,
            evidence_readiness=0.8,
            false_positive_risk=0.1,
            estimated_cost=1.0,
            payload_json="{}",
        )

        unrelated_observations = [
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                method="GET",
                role_name="user_a",
            )
        ]
        object_observations = [
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
                method="GET",
                role_name="user_a",
            ),
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location",
                method="GET",
                role_name="user_b",
            ),
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location",
                method="GET",
                role_name="user_b",
            ),
        ]

        undercovered_score = calculate_dynamic_priority(candidate, recent_observations=unrelated_observations)
        covered_score = calculate_dynamic_priority(candidate, recent_observations=object_observations)

        self.assertGreater(undercovered_score, covered_score)

    def test_dynamic_priority_rewards_undercovered_auth_boundary_bucket(self):
        candidate = SimpleNamespace(
            hypothesis_type="auth_boundary_probe",
            target_endpoint="http://host.docker.internal:8888/identity/api/v2/user/dashboard",
            http_method="GET",
            confidence=0.7,
            coverage_gain=0.7,
            evidence_readiness=0.7,
            false_positive_risk=0.1,
            estimated_cost=0.5,
            payload_json="{}",
        )

        no_auth_observations = [
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                method="GET",
                role_name="user_a",
            )
        ]
        auth_observations = [
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/identity/api/v2/user/dashboard",
                method="GET",
                role_name=None,
            ),
            SimpleNamespace(
                endpoint="http://host.docker.internal:8888/identity/api/v2/user/dashboard",
                method="GET",
                role_name="user_a",
            ),
        ]

        undercovered_score = calculate_dynamic_priority(candidate, recent_observations=no_auth_observations)
        covered_score = calculate_dynamic_priority(candidate, recent_observations=auth_observations)

        self.assertGreater(undercovered_score, covered_score)


if __name__ == "__main__":
    unittest.main()
