import json

from backend.models.api_surface import AuthSignals, NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
from backend.models.testing import ExecutionContext
from backend.services.capability_inference_service import CapabilityInferenceService
from backend.services.task_generator import TaskGenerator


def test_capability_inference_detects_auth_and_surface_sources() -> None:
    capabilities = CapabilityInferenceService().infer(
        execution_context=ExecutionContext(
            target_url="http://host.docker.internal:8888",
            roles=[
                {"name": "user_a", "token": "a"},
                {"name": "user_b", "token": "b"},
            ],
            openapi_spec_text="{}",
        ),
        normalized_surface=NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{id}/location",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                    auth_required=True,
                    auth_signals=AuthSignals(has_auth_header=True, header_names=["Authorization"]),
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    sources=["openapi", "traffic"],
                )
            ]
        ),
    )

    assert capabilities["has_openapi"] is True
    assert capabilities["has_traffic_surface"] is True
    assert capabilities["has_multi_role_auth"] is True
    assert capabilities["has_object_candidates"] is True


def test_authorization_task_gates_to_preparation_when_roles_missing() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{id}/location",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[],
        capabilities={
            "has_auth_profiles": False,
            "has_multi_role_auth": False,
            "has_register_endpoint": True,
            "has_login_endpoint": True,
            "has_object_candidates": True,
        },
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["readiness"] == "needs_preparation"
    assert task["allowed_tools"] == ["auto_provision"]
    assert task["hypothesis_family"] == "object_authorization"
    assert "cross_user_2xx" in task["expected_evidence"]
    assert task["recommended_next_step"] == "auto_provision"


def test_authorization_task_uses_auth_probe_when_auth_missing_and_only_surface_exists() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/workshop/api",
                    method="GET",
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[],
        capabilities={
            "has_auth_profiles": False,
            "has_multi_role_auth": False,
            "has_register_endpoint": False,
            "has_login_endpoint": False,
            "has_api_surface": True,
            "has_auth_entrypoint_candidates": True,
        },
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["readiness"] == "needs_preparation"
    assert task["allowed_tools"] == ["auth_probe_entrypoints"]


def test_authorization_task_selects_create_object_when_object_missing() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/orders/{id}",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=[],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": False,
            "has_api_surface": True,
        },
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["readiness"] == "needs_preparation"
    assert task["allowed_tools"] == ["create_test_object"]


def test_injection_task_uses_input_shape_probe_when_shape_missing() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/search",
                    method="GET",
                    candidate_classes=["injection"],
                )
            ]
        ),
        roles=[],
        capabilities={"has_api_surface": True, "has_input_shape": False},
    )

    task = next(item for item in tasks if item["class"] == "injection")
    assert task["readiness"] == "needs_preparation"
    assert task["allowed_tools"] == ["input_shape_probe"]


def test_business_logic_task_uses_workflow_probe_when_hints_missing() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/orders/approve",
                    method="POST",
                    candidate_classes=["business_logic"],
                )
            ]
        ),
        roles=[],
        capabilities={"has_api_surface": True, "has_workflow_hints": False},
    )

    task = next(item for item in tasks if item["class"] == "business_logic")
    assert task["readiness"] == "needs_preparation"
    assert task["allowed_tools"] == ["workflow_probe"]


def test_backward_compatible_bola_ready_to_test_flow() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{id}/location",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": True,
            "has_api_surface": True,
        },
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["readiness"] == "ready_to_test"
    assert task["allowed_tools"] == ["auth_test_access"]
    assert task["subtype"] == "bola"
    assert task["hypothesis_family"] == "object_authorization"
    assert task["recommended_next_step"] == "auth_test_access"
    assert task["evidence_feasibility"] > 0.0
    assert task["noise_risk"] >= 0.0


def test_self_profile_endpoint_gets_lower_auth_priority() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_required=True,
                    candidate_classes=["authorization"],
                ),
                NormalizedEndpoint(
                    path="/workshop/api/management/users/all",
                    method="GET",
                    query_params=["limit", "offset"],
                    auth_required=True,
                    candidate_classes=["authorization"],
                ),
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": False,
            "has_api_surface": True,
        },
    )

    dashboard_priority = max(task["priority"] for task in tasks if task["endpoint"] == "/identity/api/v2/user/dashboard")
    management_priority = max(task["priority"] for task in tasks if task["endpoint"] == "/workshop/api/management/users/all")
    assert dashboard_priority < management_priority


def test_management_or_all_endpoints_get_higher_auth_priority() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/workshop/api/shop/orders/all",
                    method="GET",
                    query_params=["limit", "offset"],
                    auth_required=True,
                    candidate_classes=["authorization"],
                ),
                NormalizedEndpoint(
                    path="/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_required=True,
                    candidate_classes=["authorization"],
                ),
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": False,
            "has_api_surface": True,
        },
    )

    dashboard_tasks = [task for task in tasks if task["endpoint"] == "/identity/api/v2/user/dashboard"]
    order_tasks = [task for task in tasks if task["endpoint"] == "/workshop/api/shop/orders/all"]
    dashboard_top = max(dashboard_tasks, key=lambda item: item["priority"])
    order_top = max(order_tasks, key=lambda item: item["priority"])
    assert order_top["priority"] > dashboard_top["priority"]
    assert dashboard_top["subtype"] in {"generic_access_control", "horizontal_privilege"}
    assert order_top["subtype"] in {"horizontal_privilege", "vertical_privilege", "generic_access_control", "function_level_authorization"}


def test_property_level_auth_mutation_task_generation() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/user/change-email",
                    method="POST",
                    body_fields=["old_email", "new_email", "role"],
                    auth_required=True,
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_api_surface": True,
        },
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["subtype"] == "property_level_authorization"
    assert task["allowed_tools"] == ["property_mutation_test"]
    assert task["hypothesis_family"] == "property_level_authorization"
    assert task["recommended_next_step"] == "property_mutation_test"


def test_excessive_data_exposure_task_generation() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_required=True,
                    candidate_classes=["business_logic"],
                )
            ]
        ),
        roles=[],
        capabilities={"has_api_surface": True},
    )

    exposure_tasks = [task for task in tasks if task["class"] == "business_logic"]
    assert exposure_tasks
    assert exposure_tasks[0]["subtype"] == "excessive_data_exposure"
    assert exposure_tasks[0]["allowed_tools"] == ["data_exposure_test"]
    assert exposure_tasks[0]["hypothesis_family"] == "excessive_data_exposure"
    assert "sensitive_keys_exposed" in exposure_tasks[0]["expected_evidence"]


def test_object_like_crapi_auth_target_outranks_dashboard() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{id}/location",
                    method="GET",
                    path_params=["id"],
                    object_id_candidates=["veh-123"],
                    auth_required=True,
                    resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                    candidate_classes=["authorization"],
                ),
                NormalizedEndpoint(
                    path="/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_required=True,
                    candidate_classes=["authorization"],
                ),
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_object_candidates": True,
            "has_api_surface": True,
        },
    )

    dashboard_priority = max(task["priority"] for task in tasks if task["endpoint"] == "/identity/api/v2/user/dashboard")
    object_priority = max(task["priority"] for task in tasks if task["endpoint"] == "/identity/api/v2/vehicle/{id}/location")
    assert object_priority > dashboard_priority


def test_rate_abuse_task_generation() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/auth/login",
                    method="POST",
                    body_fields=["email", "password"],
                    candidate_classes=["business_logic"],
                )
            ]
        ),
        roles=[],
        capabilities={"has_api_surface": True},
    )

    abuse_tasks = [task for task in tasks if task["class"] == "business_logic"]
    assert abuse_tasks
    assert abuse_tasks[0]["subtype"] == "rate_abuse"
    assert abuse_tasks[0]["allowed_tools"] == ["resource_abuse_test"]
    assert abuse_tasks[0]["hypothesis_family"] == "resource_abuse_rate_limit"


def test_management_global_endpoint_ranks_above_self_dashboard_by_provability() -> None:
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_required=True,
                ),
                NormalizedEndpoint(
                    path="/workshop/api/management/users/all",
                    method="GET",
                    query_params=["limit", "offset"],
                    auth_required=True,
                ),
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={
            "has_auth_profiles": True,
            "has_multi_role_auth": True,
            "has_api_surface": True,
        },
    )

    by_endpoint = {}
    for task in tasks:
        by_endpoint.setdefault(task["endpoint"], []).append(task)

    dashboard_top = max(by_endpoint["/identity/api/v2/user/dashboard"], key=lambda item: item["priority"])
    management_top = max(by_endpoint["/workshop/api/management/users/all"], key=lambda item: item["priority"])

    assert dashboard_top["priority"] < management_top["priority"]
    assert management_top["hypothesis_family"] in {"privileged_function_access", "collection_access_control"}


def test_spec_support_adds_resource_family_and_creator_hints() -> None:
    spec_text = json.dumps(
        {
            "openapi": "3.0.1",
            "paths": {
                "/identity/api/v2/vehicle/{vehicleId}/location": {
                    "get": {
                        "tags": ["Identity / Vehicle"],
                        "parameters": [{"in": "path", "name": "vehicleId", "required": True, "schema": {"type": "string"}}],
                    }
                },
                "/identity/api/v2/vehicle/add_vehicle": {
                    "post": {
                        "operationId": "addVehicle",
                        "tags": ["Identity / Vehicle"],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {"vin": {"type": "string"}, "pincode": {"type": "string"}},
                                    }
                                }
                            }
                        },
                    }
                },
            },
        }
    )
    tasks = TaskGenerator().generate(
        NormalizedApiSurface(
            endpoints=[
                NormalizedEndpoint(
                    path="/identity/api/v2/vehicle/{vehicleId}/location",
                    method="GET",
                    path_params=["vehicleId"],
                    auth_required=True,
                    candidate_classes=["authorization"],
                )
            ]
        ),
        roles=[{"name": "user_a", "token": "a"}, {"name": "user_b", "token": "b"}],
        capabilities={"has_auth_profiles": True, "has_multi_role_auth": True, "has_api_surface": True},
        openapi_spec_text=spec_text,
    )

    task = next(item for item in tasks if item["class"] == "authorization")
    assert task["context_hints"]["resource_family"] == "vehicle"
    assert task["context_hints"]["spec_baseline_available"] is True
    assert any(item["path"] == "/identity/api/v2/vehicle/add_vehicle" for item in task["context_hints"]["spec_creator_candidates"])
