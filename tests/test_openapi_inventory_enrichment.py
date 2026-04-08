import unittest
from types import SimpleNamespace

from backend.app.services.agent_hypothesis_service import (
    generate_bola_agent_hypotheses,
    generate_probe_agent_hypotheses,
)
from backend.app.services.openapi_service import parse_openapi_spec


class OpenAPIInventoryEnrichmentTests(unittest.TestCase):
    def test_parse_openapi_spec_extracts_path_params_and_sensitive_response_fields(self):
        spec = {
            "openapi": "3.0.0",
            "paths": {
                "/identity/api/v2/vehicle/{vehicleId}/location": {
                    "get": {
                        "parameters": [{"name": "vehicleId", "in": "path"}],
                        "responses": {
                            "200": {
                                "content": {
                                    "application/json": {
                                        "schema": {
                                            "type": "object",
                                            "properties": {
                                                "email": {"type": "string"},
                                                "location": {
                                                    "type": "object",
                                                    "properties": {"lat": {"type": "number"}},
                                                },
                                            },
                                        }
                                    }
                                }
                            }
                        },
                    }
                }
            },
        }

        endpoints = parse_openapi_spec(spec)
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0]["path_parameters"], ["vehicleId"])
        self.assertTrue(endpoints[0]["has_path_params"])
        self.assertIn("email", endpoints[0]["sensitive_response_fields"])

    def test_generate_probe_agent_normalizes_relative_inventory_paths(self):
        api_items = [
            SimpleNamespace(
                path="/identity/api/v2/user/dashboard",
                method="GET",
                raw_json='{"sensitive_response_fields":["email","role"]}',
            )
        ]
        authenticated_roles = [SimpleNamespace(role_name="user_a", access_token="token")]

        hypotheses = generate_probe_agent_hypotheses(
            api_items,
            observations=[],
            authenticated_roles=authenticated_roles,
            target_url="http://host.docker.internal:8888",
        )

        self.assertTrue(hypotheses)
        self.assertEqual(
            hypotheses[0]["target_endpoint"],
            "http://host.docker.internal:8888/identity/api/v2/user/dashboard",
        )

    def test_generate_bola_agent_uses_inventory_path_templates_with_observed_ids(self):
        observations = [
            SimpleNamespace(
                id=1,
                endpoint="http://host.docker.internal:8888/community/api/v2/community/posts/recent",
                method="GET",
                role_name="user_a",
                status_code=200,
                body_preview='{"posts":[{"vehicleId":"4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"}]}',
            )
        ]
        api_items = [
            SimpleNamespace(
                path="/identity/api/v2/vehicle/{vehicleId}/location",
                method="GET",
                raw_json='{"has_path_params":true,"path_parameters":["vehicleId"]}',
            )
        ]
        authenticated_roles = [
            SimpleNamespace(role_name="user_a", access_token="a"),
            SimpleNamespace(role_name="user_b", access_token="b"),
        ]

        hypotheses = generate_bola_agent_hypotheses(
            observations,
            findings=[],
            authenticated_roles=authenticated_roles,
            api_items=api_items,
            target_url="http://host.docker.internal:8888",
        )

        endpoints = {item["target_endpoint"] for item in hypotheses}
        self.assertIn(
            "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
            endpoints,
        )


if __name__ == "__main__":
    unittest.main()
