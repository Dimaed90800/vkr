from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from backend.models.testing import ExecutionContext, TaskModel
    from backend.models.tool_wrappers import ToolBudget, ToolWrapperRequest
    from backend.services.evidence_builder_service import EvidenceBuilderService
    from backend.services.tool_wrappers import ToolWrapperService
except ModuleNotFoundError:  # Docker toolbox image copies backend contents to /app
    from models.testing import ExecutionContext, TaskModel
    from models.tool_wrappers import ToolBudget, ToolWrapperRequest
    from services.evidence_builder_service import EvidenceBuilderService
    from services.tool_wrappers import ToolWrapperService


def main() -> int:
    output_dir = Path(tempfile.mkdtemp(prefix="restler-wrapper-smoke-"))
    task = TaskModel.model_validate(
        {
            "id": "task_restler_smoke_001",
            "class": "business_logic",
            "subtype": "stateful_sequence",
            "endpoint": "/orders",
            "method": "POST",
            "hypothesis": "Stateful REST API sequences should not bypass expected workflow steps.",
            "allowed_tools": ["restler_compile", "restler_fuzz", "restler_replay", "logic_test"],
            "worker_role": "Business Flow / Stateful Agent",
            "preferred_tool": "restler_fuzz",
        }
    )
    request = ToolWrapperRequest(
        tool_name="restler_fuzz",
        run_id="run-restler-smoke",
        target_url="http://127.0.0.1:8001",
        openapi_url="http://127.0.0.1:8001/openapi.json",
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-restler-smoke",
            openapi_url="http://127.0.0.1:8001/openapi.json",
            allowed_hosts=["127.0.0.1:8001"],
            max_requests=4,
            max_duration_sec=20,
        ),
        task=task,
        task_metadata={"worker_role": "Business Flow / Stateful Agent"},
        budgets=ToolBudget(max_requests=4, max_duration_sec=20, concurrency=1),
        output_dir=str(output_dir),
    )
    result = ToolWrapperService().execute(request)
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role="Business Flow / Stateful Agent",
        tool_result=result,
        run_id="run-restler-smoke",
        notes=["restler_smoke_contract"],
    )
    body = {
        "result": result.model_dump(mode="json"),
        "judge_ready_evidence": evidence.model_dump(mode="json"),
    }
    print(json.dumps(body, indent=2, ensure_ascii=False))
    signals = set(result.signals or [])
    if result.status != "partial":
        return 1
    if "wrapper_scaffold_ready" not in signals or "stateful_sequence_fuzzing_planned" not in signals:
        return 1
    if not Path(result.artifacts.replay_pack_path).exists():
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
