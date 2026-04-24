from __future__ import annotations

import json
import os
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
except ModuleNotFoundError:
    from models.testing import ExecutionContext, TaskModel
    from models.tool_wrappers import ToolBudget, ToolWrapperRequest
    from services.evidence_builder_service import EvidenceBuilderService
    from services.tool_wrappers import ToolWrapperService


def _write_openapi(path: Path) -> Path:
    payload = {
        "openapi": "3.0.0",
        "info": {"title": "Akto Adapter Smoke", "version": "1.0.0"},
        "paths": {
            "/orders": {"get": {"operationId": "listOrders"}},
            "/orders/{id}": {"delete": {"operationId": "deleteOrder", "security": [{"bearerAuth": []}]}}
        },
    }
    path.write_text(json.dumps(payload), encoding='utf-8')
    return path


def main() -> int:
    output_dir = Path(tempfile.mkdtemp(prefix='akto-wrapper-smoke-'))
    spec_path = _write_openapi(output_dir / 'openapi.json')
    os.environ.setdefault(
        'AKTO_WRAPPER_COMMAND',
        'python /app/scripts/runtime/akto_runtime_adapter.py --request-json {request_json} --result-json {result_json} --output-dir {output_dir}',
    )
    task = TaskModel.model_validate(
        {
            'id': 'task_akto_smoke_001',
            'class': 'authorization',
            'subtype': 'function_level_authorization',
            'endpoint': '/orders/{id}',
            'method': 'DELETE',
            'hypothesis': 'A low-privileged user may be able to reach a privileged function.',
            'allowed_tools': ['akto_authz_scan'],
            'worker_role': 'Auth & Identity Agent',
            'preferred_tool': 'akto_authz_scan',
            'auth_context': {'owner_role': 'user_a', 'other_role': 'user_b', 'token_strategy': 'cross_role_replay'},
        }
    )
    request = ToolWrapperRequest(
        tool_name='akto_authz_scan',
        run_id='run-akto-smoke',
        target_url='http://127.0.0.1:8001',
        openapi_spec_path=str(spec_path),
        execution_context=ExecutionContext(
            target_url='http://127.0.0.1:8001',
            run_id='run-akto-smoke',
            openapi_url=str(spec_path),
            allowed_hosts=['127.0.0.1:8001'],
            max_requests=5,
            max_duration_sec=20,
        ),
        task=task,
        task_metadata={'worker_role': 'Auth & Identity Agent'},
        budgets=ToolBudget(max_requests=5, max_duration_sec=20, concurrency=1),
        output_dir=str(output_dir),
    )
    result = ToolWrapperService().execute(request)
    evidence = EvidenceBuilderService().from_wrapper_result(
        task=task,
        worker_role='Auth & Identity Agent',
        tool_result=result,
        run_id='run-akto-smoke',
        notes=['akto_smoke_contract'],
    )
    print(json.dumps({'result': result.model_dump(mode='json'), 'judge_ready_evidence': evidence.model_dump(mode='json')}, ensure_ascii=False, indent=2))
    return 0 if result.status in {'ok', 'partial'} and result.candidate_findings else 1


if __name__ == '__main__':
    raise SystemExit(main())
