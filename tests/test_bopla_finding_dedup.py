import json
import unittest
from types import SimpleNamespace

from backend.app.services.finding_dedup_service import (
    matching_bopla_finding,
    merge_related_observation_ids,
)


class BoplaFindingDedupTests(unittest.TestCase):
    def test_matching_bopla_finding_reuses_confirmed_same_fields(self):
        finding = SimpleNamespace(
            finding_type="possible_bopla",
            endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            verification_status="confirmed",
            evidence_json=json.dumps({"exposed_fields": ["posts.author.email"]}, ensure_ascii=False),
        )

        matched = matching_bopla_finding(
            [finding],
            "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            {"exposed_fields": ["posts.author.email"]},
        )

        self.assertIs(matched, finding)

    def test_matching_bopla_finding_keeps_distinct_field_sets_separate(self):
        finding = SimpleNamespace(
            finding_type="possible_bopla",
            endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            verification_status="confirmed",
            evidence_json=json.dumps({"exposed_fields": ["posts.author.email"]}, ensure_ascii=False),
        )

        matched = matching_bopla_finding(
            [finding],
            "http://host.docker.internal:8888/community/api/v2/community/posts/recent",
            {"exposed_fields": ["posts.author.email", "posts.author.phone"]},
        )

        self.assertIsNone(matched)

    def test_merge_related_observation_ids_appends_without_duplicates(self):
        merged = merge_related_observation_ids(json.dumps([877, 878]), [878, 879])
        self.assertEqual(json.loads(merged), [877, 878, 879])


if __name__ == "__main__":
    unittest.main()
