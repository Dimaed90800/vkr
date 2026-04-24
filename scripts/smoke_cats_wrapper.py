from __future__ import annotations

import json
from pathlib import Path

from backend.models.testing import ExecutionContext, TaskModel
from backend.models.tool_wrappers import ToolBudget, ToolWrapperRequest
from backend.services.tool_wrappers.service import ToolWrapperService


def main() -> int:
    spec_path = Path(__file__).resolve().parent / "runtime" / "_smoke_openapi.json"
    if not spec_path.exists():
        spec_path.write_text(json.dumps({
            "openapi": "3.0.0",
            "info": {"title": "Smoke API", "version": "1.0.0"},
            "paths": {"/signin": {"get": {"operationId": "signin"}}},
        }), encoding="utf-8")
    task = TaskModel.model_validate({
        "id": "task_cats_smoke_001",
        "class": "injection",
        "subtype": "input_injection",
        "endpoint": "/signin",
        "method": "GET",
        "hypothesis": "CATS smoke wrapper should produce normalized output.",
        "allowed_tools": ["cats_fuzz_test"],
        "preferred_tool": "cats_fuzz_test",
        "worker_role": "Contract & Negative Testing Agent",
    })
    request = ToolWrapperRequest(
        tool_name="cats_fuzz_test",
        run_id="run-cats-smoke",
        target_url="http://127.0.0.1:8001",
        openapi_spec_path=str(spec_path),
        execution_context=ExecutionContext(
            target_url="http://127.0.0.1:8001",
            run_id="run-cats-smoke",
            openapi_url=str(spec_path),
            allowed_hosts=["127.0.0.1:8001"],
        ),
        task=task,
        budgets=ToolBudget(max_requests=5, max_duration_sec=20),
    )
    result = ToolWrapperService().execute(request)
    print(json.dumps(result.model_dump(mode="json"), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
