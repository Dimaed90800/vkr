from backend.models.api_surface import (
    CandidateScores,
    NormalizedApiSurface,
    NormalizedEndpoint,
    ResourceSignals,
)
from backend.services.task_generator import TaskGenerator


def test_generator_builds_authorization_task_from_object_endpoint() -> None:
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/users/{id}",
                method="GET",
                operation_id="getUser",
                summary="Get user",
                path_params=["id"],
                query_params=[],
                body_fields=[],
                auth_required=True,
                security_schemes=["bearerAuth"],
                tags=["users"],
                resource_signals=ResourceSignals(
                    has_object_id=True,
                    has_role_fields=False,
                    has_sensitive_keywords=True,
                ),
                candidate_scores=CandidateScores(
                    authorization=0.91,
                    injection=0.22,
                    business_logic=0.30,
                ),
                candidate_classes=["authorization"],
            )
        ]
    )

    tasks = TaskGenerator().generate(
        surface,
        roles=[{"name": "user_a"}, {"name": "user_b"}],
    )

    assert len(tasks) == 1
    task = tasks[0]
    assert task["class"] == "authorization"
    assert task["subtype"] == "bola"
    assert task["endpoint"] == "/users/{id}"
    assert task["method"] == "GET"
    assert task["params"]["path_params"] == ["id"]
    assert task["auth_context"]["owner_role"] == "user_a"
    assert task["auth_context"]["other_role"] == "user_b"
    assert task["allowed_tools"] == ["auth_test_access"]
    assert task["priority"] == 91


def test_generator_builds_multiple_task_classes() -> None:
    surface = NormalizedApiSurface(
        endpoints=[
            NormalizedEndpoint(
                path="/payments/transfer",
                method="POST",
                operation_id="transferFunds",
                summary="Transfer balance",
                path_params=[],
                query_params=["query"],
                body_fields=["amount", "balance", "ownerId"],
                auth_required=True,
                security_schemes=["bearerAuth"],
                tags=["payments"],
                resource_signals=ResourceSignals(
                    has_object_id=False,
                    has_role_fields=True,
                    has_sensitive_keywords=True,
                ),
                candidate_scores=CandidateScores(
                    authorization=0.61,
                    injection=0.52,
                    business_logic=0.88,
                ),
                candidate_classes=["business_logic", "authorization", "injection"],
            )
        ]
    )

    tasks = TaskGenerator().generate(surface, roles=[])

    assert len(tasks) == 3
    classes = [task["class"] for task in tasks]
    assert "business_logic" in classes
    assert "authorization" in classes
    assert "injection" in classes
    assert tasks[0]["priority"] >= tasks[1]["priority"] >= tasks[2]["priority"]
