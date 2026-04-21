from pathlib import Path

from backend.models.testing import ExecutionContext, TaskModel
from backend.models.tool_wrappers import ToolBudget, ToolWrapperRequest
from backend.services.evidence_builder_service import EvidenceBuilderService
from backend.services.tool_wrappers.service import ToolWrapperService


def _task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_contract_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/api/items",
            "method": "GET",
            "hypothesis": "Malformed input may violate the API contract.",
            "allowed_tools": ["schemathesis_negative_test", "cats_fuzz_test"],
            "worker_role": "Contract & Negative Testing Agent",
            "preferred_tool": "schemathesis_negative_test",
            "fallback_tools": ["cats_fuzz_test"],
            "artifact_requirements": ["http_trace", "raw_report"],
        }
    )


def test_wrapper_stub_returns_normalized_judge_ready_evidence(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-test-wrapper",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        budgets=ToolBudget(max_requests=5, max_duration_sec=10, concurrency=1),
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Contract & Negative Testing Agent",
        tool_result=result,
    )

    assert result.tool_name == "cats_fuzz_test"
    assert result.schema_version == "tool-wrapper-result/v1"
    assert result.status == "partial"
    assert "wrapper_scaffold_ready" in result.signals
    assert Path(result.artifacts.replay_pack_path).exists()
    assert evidence.schema_version == "judge-ready-evidence/v1"
    assert evidence.source_task_id == "task_contract_001"
    assert evidence.tool_name == "cats_fuzz_test"
    assert evidence.worker_role == "Contract & Negative Testing Agent"
    assert evidence.reproduction["url"] == "http://127.0.0.1:8001/api/items"


def test_schemathesis_missing_openapi_returns_normalized_partial(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="schemathesis_negative_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-test-missing-openapi",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=3,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        budgets=ToolBudget(max_requests=3, max_duration_sec=10, concurrency=1),
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)

    assert result.status == "partial"
    assert result.schema_version == "tool-wrapper-result/v1"
    assert result.source_task_id == "task_contract_001"
    assert result.fallback_reason
    assert "openapi_missing" in result.signals
    assert result.termination_reason == "missing_openapi"
    assert Path(result.artifacts.replay_pack_path).exists()


def test_replay_pack_contains_reproduction_metadata(tmp_path: Path) -> None:
    task = _task()
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run/test wrapper",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=5,
            max_duration_sec=10,
        ),
        task=task,
        task_metadata={"worker_role": "Contract & Negative Testing Agent"},
        arguments={"headers": {"Authorization": "Bearer secret-token"}},
        output_dir=str(tmp_path),
    )

    result = ToolWrapperService().execute(request)
    replay_pack_path = Path(result.artifacts.replay_pack_path)
    replay_pack = replay_pack_path.read_text(encoding="utf-8")

    assert replay_pack_path == tmp_path / "run_test_wrapper" / "cats_fuzz_test" / "task_contract_001" / "replay_pack.json"
    assert '"schema_version": "replay-pack/v1"' in replay_pack
    assert '"source_task_id": "task_contract_001"' in replay_pack
    assert '"Authorization": "<redacted>"' in replay_pack
    assert '"strategy": "deterministic_tool_replay"' in replay_pack
