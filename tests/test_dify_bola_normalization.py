import unittest

from backend.app.services.dify_service import _normalize_bola_candidate


class DifyBolaNormalizationTests(unittest.TestCase):
    def test_bola_probe_prefers_full_object_id_from_endpoint(self):
        candidate = {
            "agent_name": "dify_bola_agent",
            "hypothesis_type": "bola_probe",
            "target_endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
            "http_method": "GET",
            "description": "",
            "payload": {
                "owner_role": "user_a",
                "other_role": "user_b",
                "object_type": "vehicle",
                "object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5",
            },
        }

        normalized = _normalize_bola_candidate(
            candidate,
            target_base_url="http://host.docker.internal:8888",
            roles_compact=["user_a", "user_b"],
            known_object_ids=[],
            candidate_findings_compact=[],
        )

        self.assertIsNotNone(normalized)
        self.assertEqual(
            normalized["payload"]["object_id"],
            "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
        )
        self.assertEqual(
            normalized["candidate_key"],
            "bola_probe::vehicle::4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5::user_a::user_b",
        )
        self.assertTrue(normalized["description"])

    def test_verify_bola_prefers_endpoint_match_for_finding_id(self):
        candidate = {
            "agent_name": "dify_bola_agent",
            "hypothesis_type": "verify_bola",
            "target_endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location",
            "http_method": "GET",
            "candidate_key": "verify_bola::515",
            "description": "",
        }

        normalized = _normalize_bola_candidate(
            candidate,
            target_base_url="http://host.docker.internal:8888",
            roles_compact=["user_a", "user_b"],
            known_object_ids=[],
            candidate_findings_compact=[
                {
                    "id": 181,
                    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/cd515c12-0fc1-48ae-8b61-9230b70a845b/location",
                }
            ],
        )

        self.assertIsNotNone(normalized)
        self.assertEqual(normalized["payload"]["finding_id"], 181)
        self.assertEqual(normalized["candidate_key"], "verify_bola::181")
        self.assertTrue(normalized["description"])

    def test_bola_probe_with_non_location_endpoint_is_dropped(self):
        candidate = {
            "agent_name": "dify_bola_agent",
            "hypothesis_type": "bola_probe",
            "target_endpoint": "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            "http_method": "GET",
            "description": "Probe a non-object endpoint as BOLA",
            "payload": {
                "owner_role": "user_a",
                "other_role": "user_b",
            },
        }

        normalized = _normalize_bola_candidate(
            candidate,
            target_base_url="http://host.docker.internal:8888",
            roles_compact=["user_a", "user_b"],
            known_object_ids=[],
            candidate_findings_compact=[],
        )

        self.assertIsNone(normalized)

    def test_bola_probe_requires_distinct_roles(self):
        candidate = {
            "agent_name": "dify_bola_agent",
            "hypothesis_type": "bola_probe",
            "target_endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
            "http_method": "GET",
            "payload": {
                "owner_role": "user_a",
                "other_role": "user_a",
                "object_type": "vehicle",
                "object_id": "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5",
            },
        }

        normalized = _normalize_bola_candidate(
            candidate,
            target_base_url="http://host.docker.internal:8888",
            roles_compact=["user_a", "user_b"],
            known_object_ids=[],
            candidate_findings_compact=[],
        )

        self.assertIsNone(normalized)


if __name__ == "__main__":
    unittest.main()
