from __future__ import annotations

import argparse
import json
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen


def _load_request(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _write_json(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def _load_openapi(ref: str) -> dict:
    if not ref:
        return {}
    if ref.startswith('http://') or ref.startswith('https://'):
        with urlopen(ref) as resp:  # nosec - constrained by backend scope
            return json.loads(resp.read().decode('utf-8'))
    return json.loads(Path(ref).read_text(encoding='utf-8'))


def _inventory_rows(openapi_doc: dict) -> list[dict]:
    rows = []
    for path, methods in (openapi_doc.get('paths') or {}).items():
        for method, info in (methods or {}).items():
            if method.lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                continue
            rows.append({
                'path': path,
                'method': method.upper(),
                'operation_id': (info or {}).get('operationId') or '',
                'security': list((info or {}).get('security') or []),
            })
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--request-json', required=True)
    parser.add_argument('--result-json', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    request = _load_request(args.request_json)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tool_name = str(request.get('tool_name') or 'akto_inventory_discovery')
    openapi_ref = str(request.get('openapi_ref') or '')
    target_url = str(request.get('target_url') or '')
    target_host = urlparse(target_url).netloc

    try:
        openapi_doc = _load_openapi(openapi_ref)
    except Exception as exc:
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'partial',
            'summary': f'Akto adapter could not load OpenAPI: {exc}',
            'signals': ['akto_runtime_adapter', 'openapi_missing'],
            'raw_report_paths': [],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'missing_openapi',
            'fallback_reason': f'Akto adapter requires OpenAPI to build runtime inventory/authz plan: {exc}',
            'error': 'openapi_missing',
        }
        _write_json(args.result_json, payload)
        return 0

    inventory = _inventory_rows(openapi_doc)
    report_path = out_dir / 'akto_runtime_inventory.json'
    report_path.write_text(json.dumps({'inventory': inventory[:100], 'target_host': target_host}, ensure_ascii=False, indent=2), encoding='utf-8')

    if tool_name == 'akto_inventory_discovery':
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'ok' if inventory else 'partial',
            'summary': f'Akto adapter built runtime inventory with {len(inventory)} operations.',
            'signals': ['akto_runtime_adapter', 'runtime_inventory_built'] + (['api_inventory_enriched'] if inventory else []),
            'raw_report_paths': [str(report_path)],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'completed' if inventory else 'scaffold_only',
            'fallback_reason': None if inventory else 'No inventory rows could be synthesized from OpenAPI.',
            'error': None,
        }
        _write_json(args.result_json, payload)
        return 0

    task = request.get('task') or {}
    endpoint = str(task.get('endpoint') or '')
    method = str(task.get('method') or 'GET').upper()
    auth_context = (task.get('auth_context') or {}) if isinstance(task, dict) else {}
    candidate = {
        'task_id': request.get('task_id') or task.get('id') or '',
        'vuln_type': task.get('subtype') or 'generic_access_control',
        'endpoint': endpoint,
        'method': method,
        'signals': ['authz_runtime_plan_ready'],
        'confidence': 0.25,
        'source_tool': tool_name,
        'details': {
            'owner_role': auth_context.get('owner_role'),
            'other_role': auth_context.get('other_role'),
            'token_strategy': auth_context.get('token_strategy'),
            'runtime_inventory_size': len(inventory),
        },
    }
    payload = {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': tool_name,
        'status': 'partial',
        'summary': f'Akto authz adapter prepared runtime-backed authorization plan for {method} {endpoint}.',
        'signals': ['akto_runtime_adapter', 'authz_runtime_plan_ready', 'runtime_inventory_built'],
        'raw_report_paths': [str(report_path)],
        'candidate_findings': [candidate],
        'used_requests': 0,
        'termination_reason': 'tool_reported_findings',
        'fallback_reason': 'Akto upstream runtime is not installed; adapter produced runtime-backed authz plan only.',
        'error': None,
    }
    _write_json(args.result_json, payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
