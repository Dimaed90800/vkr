from backend.models.api_surface import CandidateScores, NormalizedApiSurface, NormalizedEndpoint, ResourceSignals
from backend.models.planning import TaskPlanningRequest
from backend.models.synthesized_context import SynthesizedSecurityContext
from backend.models.testing import ExecutionContext
from backend.services.task_planner import TaskPlanner


def _ctx(roles=None) -> ExecutionContext:
    return ExecutionContext(
        target_url="http://host.docker.internal:8888",
        roles=roles or [],
        allowed_hosts=["host.docker.internal:8888"],
        max_requests=20,
        max_duration_sec=300,
        max_retries_per_task=1,
    )


def test_synthesized_context_parsing_and_planner_integration() -> None:
    synthesized = SynthesizedSecurityContext.model_validate(
        {
            "authorization": {
                "candidate_targets": ["/identity/api/auth/signup", "/identity/api/auth/login"],
                "likely_subtypes": ["auth_bootstrap"],
                "missing_prerequisites": ["has_auth_profiles"],
                "candidate_bootstrap_endpoints": {
                    "register": ["/identity/api/auth/signup"],
                    "login": ["/identity/api/auth/login"],
                    "profile": [],
                    "create_resource": [],
                },
                "preparation_suggestions": ["auto_provision"],
                "priority_hint": 0.95,
                "confidence": 0.91,
            },
            "injection": {
                "candidate_targets": [],
                "likely_subtypes": [],
                "missing_prerequisites": [],
                "candidate_bootstrap_endpoints": {"shape_probe": [], "reflection_probe": [], "path_probe": []},
                "preparation_suggestions": [],
                "priority_hint": 0.0,
                "confidence": 0.0,
            },
            "business_logic": {
                "candidate_targets": [],
                "likely_subtypes": [],
                "missing_prerequisites": [],
                "candidate_bootstrap_endpoints": {"workflow_roots": [], "create": [], "transition": []},
                "preparation_suggestions": [],
                "priority_hint": 0.0,
                "confidence": 0.0,
            },
            "global_notes": ["Use auth bootstrap first when roles are missing."],
            "global_priority_order": ["authorization", "injection", "business_logic"],
        }
    )
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(path="/identity/api/auth/signup", method="POST"),
            NormalizedEndpoint(path="/identity/api/auth/login", method="POST"),
        ]
    )

    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx([]),
            normalized_surface=surface,
            synthesized_security_context=synthesized,
            routing_mode="hybrid",
        )
    )

    assert response.metadata.synthesized_context_present is True
    assert response.synthesized_security_context is not None
    assert response.final_task_queue[0].subtype == "auth_bootstrap"
    assert response.final_task_queue[0].context_hints["bootstrap_candidates"]["register"] == ["/identity/api/auth/signup"]


def test_auth_bootstrap_preferred_when_auth_endpoints_exist_and_roles_missing() -> None:
    synthesized = SynthesizedSecurityContext.model_validate(
        {
            "authorization": {
                "candidate_targets": ["/identity/api/auth/signup", "/identity/api/auth/login"],
                "likely_subtypes": ["auth_bootstrap"],
                "missing_prerequisites": ["has_auth_profiles"],
                "candidate_bootstrap_endpoints": {
                    "register": ["/identity/api/auth/signup"],
                    "login": ["/identity/api/auth/login"],
                    "profile": [],
                    "create_resource": [],
                },
                "preparation_suggestions": ["auto_provision"],
                "priority_hint": 1.0,
                "confidence": 0.95,
            }
        }
    )
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(path="/identity/api/auth/signup", method="POST"),
            NormalizedEndpoint(path="/identity/api/auth/login", method="POST"),
            NormalizedEndpoint(path="/workshop/api", method="GET", candidate_classes=["authorization"]),
        ]
    )

    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx([]),
            normalized_surface=surface,
            synthesized_security_context=synthesized,
            routing_mode="hybrid",
        )
    )

    top = response.final_task_queue[0]
    assert top.subtype == "auth_bootstrap"
    assert top.readiness == "needs_preparation"
    assert top.allowed_tools == ["auto_provision"]


def test_injection_candidate_targets_with_weak_shape_emit_input_shape_probe() -> None:
    synthesized = SynthesizedSecurityContext.model_validate(
        {
            "injection": {
                "candidate_targets": ["/search"],
                "likely_subtypes": ["reflection_probe"],
                "missing_prerequisites": ["has_input_shape"],
                "candidate_bootstrap_endpoints": {
                    "shape_probe": ["/search"],
                    "reflection_probe": ["/search"],
                    "path_probe": [],
                },
                "preparation_suggestions": ["input_shape_probe"],
                "priority_hint": 0.7,
                "confidence": 0.72,
            }
        }
    )
    surface = NormalizedApiSurface(endpoints=[NormalizedEndpoint(path="/search", method="GET")])

    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx([]),
            normalized_surface=surface,
            synthesized_security_context=synthesized,
            routing_mode="hybrid",
        )
    )

    task = response.final_task_queue[0]
    assert task.class_name == "injection"
    assert task.readiness == "needs_preparation"
    assert task.allowed_tools == ["input_shape_probe"]
    assert task.context_hints["preparation_suggestions"] == ["input_shape_probe"]


def test_business_logic_hints_with_weak_workflow_context_emit_workflow_probe() -> None:
    synthesized = SynthesizedSecurityContext.model_validate(
        {
            "business_logic": {
                "candidate_targets": ["/orders/approve"],
                "likely_subtypes": ["workflow_probe"],
                "missing_prerequisites": ["has_workflow_hints"],
                "candidate_bootstrap_endpoints": {
                    "workflow_roots": ["/orders"],
                    "create": ["/orders"],
                    "transition": ["/orders/approve"],
                },
                "preparation_suggestions": ["workflow_probe"],
                "priority_hint": 0.8,
                "confidence": 0.74,
            }
        }
    )
    surface = NormalizedApiSurface(endpoints=[NormalizedEndpoint(path="/orders/approve", method="POST")])

    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx([]),
            normalized_surface=surface,
            synthesized_security_context=synthesized,
            routing_mode="hybrid",
        )
    )

    task = response.final_task_queue[0]
    assert task.class_name == "business_logic"
    assert task.readiness == "needs_preparation"
    assert task.allowed_tools == ["workflow_probe"]


def test_weak_synthesized_context_does_not_invent_endpoints_or_credentials() -> None:
    synthesized = SynthesizedSecurityContext.model_validate(
        {
            "authorization": {
                "candidate_targets": [],
                "likely_subtypes": [],
                "missing_prerequisites": ["has_auth_profiles"],
                "candidate_bootstrap_endpoints": {"register": [], "login": [], "profile": [], "create_resource": []},
                "preparation_suggestions": [],
                "priority_hint": 0.05,
                "confidence": 0.03,
            },
            "global_notes": ["Weak evidence only."],
            "global_priority_order": [],
        }
    )
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/identity/api/v2/vehicle/{id}/location",
                method="GET",
                path_params=["id"],
                object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                candidate_scores=CandidateScores(authorization=0.9),
                candidate_classes=["authorization"],
            )
        ]
    )
    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx(
                [
                    {"name": "user_a", "token": "a"},
                    {"name": "user_b", "token": "b"},
                ]
            ),
            normalized_surface=surface,
            synthesized_security_context=synthesized,
            routing_mode="hybrid",
        )
    )

    task = response.final_task_queue[0]
    assert task.endpoint == "/identity/api/v2/vehicle/{id}/location"
    assert task.context_hints == {}
    assert task.allowed_tools == ["auth_test_access"]


def test_current_working_bola_path_still_works_unchanged_with_synthesizer_absent() -> None:
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/identity/api/v2/vehicle/{id}/location",
                method="GET",
                path_params=["id"],
                object_id_candidates=["4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"],
                resource_signals=ResourceSignals(has_object_id=True, has_sensitive_keywords=True),
                candidate_scores=CandidateScores(authorization=1.0),
                candidate_classes=["authorization"],
            )
        ]
    )

    response = TaskPlanner().plan(
        TaskPlanningRequest(
            execution_context=_ctx(
                [
                    {"name": "user_a", "token": "a"},
                    {"name": "user_b", "token": "b"},
                ]
            ),
            normalized_surface=surface,
            routing_mode="hybrid",
        )
    )

    task = response.final_task_queue[0]
    assert task.subtype == "bola"
    assert task.readiness == "ready_to_test"
    assert task.allowed_tools == ["auth_test_access"]
