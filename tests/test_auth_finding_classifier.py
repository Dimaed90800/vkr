from backend.models.testing import TaskModel
from backend.services.auth_finding_classifier import (
    classify_auth_finding,
    finding_title_label,
    finding_type_label,
)


def _task(
    endpoint: str,
    *,
    path_params: list[str] | None = None,
    query_params: list[str] | None = None,
    subtype: str = "generic_access_control",
    owner_role: str = "user_a",
    other_role: str = "user_b",
) -> TaskModel:
    return TaskModel(
        id="task_auth_001",
        class_name="authorization",
        subtype=subtype,
        endpoint=endpoint,
        method="GET",
        params={
            "path_params": path_params or [],
            "query_params": query_params or [],
            "body_fields": [],
            "object_id_candidates": [],
            "selected_object_id": None,
            "requires_object_id_enrichment": False,
            "object_param_name": None,
        },
        auth_context={
            "owner_role": owner_role,
            "other_role": other_role,
            "token_strategy": "cross_role_replay",
        },
        hypothesis="authorization comparison",
        allowed_tools=["auth_test_access"],
    )


def _evidence(similarity: float = 0.95, owner_status: int = 200, other_status: int = 200) -> dict:
    return {
        "response_summary": {
            "owner": {"status_code": owner_status},
            "other": {"status_code": other_status},
            "similarity": similarity,
        }
    }


def test_users_id_classifies_as_bola() -> None:
    task = _task("/users/{id}", path_params=["id"], subtype="bola")

    classification = classify_auth_finding(task, _evidence())

    assert classification == "bola"
    assert finding_type_label(classification) == "BOLA"


def test_vehicle_collection_classifies_as_generic_access_control() -> None:
    task = _task("/vehicle/vehicles")

    classification = classify_auth_finding(task, _evidence())

    assert classification == "generic_access_control"
    assert finding_title_label(classification) == "Generic Access Control Weakness"


def test_dashboard_classifies_as_horizontal_privilege() -> None:
    task = _task("/dashboard")

    classification = classify_auth_finding(task, _evidence())

    assert classification == "horizontal_privilege"
    assert finding_type_label(classification) == "HORIZONTAL_PRIVILEGE_ESCALATION"


def test_admin_users_classifies_as_vertical_privilege() -> None:
    task = _task("/admin/users", owner_role="user_a", other_role="user_b")

    classification = classify_auth_finding(task, _evidence())

    assert classification == "vertical_privilege"
    assert finding_type_label(classification) == "VERTICAL_PRIVILEGE_ESCALATION"
