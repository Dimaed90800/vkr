from backend.models.testing import TaskModel
from backend.services.followup_task_generation_service import FollowupTaskGenerationService
from backend.services.task_generator import TaskGenerator


def test_preparation_tool_preference_uses_preparation_tool() -> None:
    generator = TaskGenerator()
    pref = generator._tool_preference("authorization", "object_authorization", "needs_preparation")
    assert pref["preferred_tool"] == "create_test_object"
    assert "auto_provision" in pref["fallback_tools"]


def test_followup_clone_detects_import_har_as_preparation() -> None:
    task = TaskModel.model_validate(
        {
            "id": "task_injection_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/search",
            "method": "POST",
            "hypothesis": "shape discovery needed",
            "allowed_tools": ["import_har_capture"],
            "readiness": "needs_preparation",
            "preferred_tool": "input_shape_probe",
            "fallback_tools": ["import_har_capture"],
            "worker_role": "Contract & Negative Testing Agent",
        }
    )
    cloned = FollowupTaskGenerationService()._clone_task(task, "baseline_refinement", allowed_tools=["import_har_capture"], priority_boost=2)
    assert cloned.readiness == "needs_preparation"
    assert cloned.recommended_next_step in {"input_shape_probe", "import_har_capture"}
