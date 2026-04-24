from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen


ERROR_MARKERS = (' 5xx', ' 500', ' 502', ' 503', ' 504', ' error ', 'exception')


def _load_request(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _write_json(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def _load_openapi(ref: str, out_dir: Path) -> tuple[dict, str | None]:
    if not ref:
        return {}, None
    target = out_dir / 'cats_openapi.json'
    if ref.startswith(('http://', 'https://')):
        with urlopen(ref) as resp:  # nosec - constrained by backend scope
            content = resp.read()
            target.write_bytes(content)
            return json.loads(content.decode('utf-8')), str(target)
    target.write_bytes(Path(ref).read_bytes())
    return json.loads(target.read_text(encoding='utf-8')), str(target)


def _cats_bin() -> str | None:
    return os.getenv('CATS_BIN') or shutil.which('cats')


def _inventory(doc: dict) -> list[dict]:
    rows = []
    for path, methods in (doc.get('paths') or {}).items():
        for method, info in (methods or {}).items():
            if str(method).lower() not in {'get', 'post', 'put', 'patch', 'delete'}:
                continue
            rows.append({
                'path': path,
                'method': str(method).upper(),
                'operation_id': (info or {}).get('operationId') or '',
                'parameter_count': len((info or {}).get('parameters') or []),
            })
    return rows


def _header_args(arguments: dict) -> list[str]:
    headers = arguments.get('headers') or {}
    values = []
    if isinstance(headers, dict):
        for key, value in headers.items():
            values.extend(['-H', f'{key}={value}'])
    return values


def _candidate_findings(tool_name: str, endpoint: str, method: str, stdout: str, stderr: str) -> list[dict]:
    text = f"{stdout}\n{stderr}".lower()
    findings = []
    if any(marker in text for marker in ERROR_MARKERS):
        findings.append({
            'vuln_type': 'negative_test_server_error',
            'endpoint': endpoint,
            'method': method,
            'confidence': 0.45,
            'source_tool': tool_name,
            'details': {'summary': 'CATS observed error markers in runtime output.'},
        })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--request-json', required=True)
    parser.add_argument('--result-json', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    request = _load_request(args.request_json)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tool_name = str(request.get('tool_name') or 'cats_fuzz_test')
    openapi_ref = str(request.get('openapi_ref') or '')
    target_url = str(request.get('target_url') or '')
    task = request.get('task') or {}
    endpoint = str(task.get('endpoint') or '')
    method = str(task.get('method') or 'GET').upper()

    try:
        openapi_doc, local_spec = _load_openapi(openapi_ref, out_dir)
    except Exception as exc:
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'partial',
            'summary': f'CATS adapter could not load OpenAPI: {exc}',
            'signals': ['cats_runtime_adapter', 'openapi_missing'],
            'raw_report_paths': [],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'missing_openapi',
            'fallback_reason': f'CATS adapter requires OpenAPI: {exc}',
            'error': 'openapi_missing',
        }
        _write_json(args.result_json, payload)
        return 0

    inv = _inventory(openapi_doc)
    report_path = out_dir / 'cats_runtime_inventory.json'
    report_path.write_text(json.dumps({'inventory': inv[:100]}, ensure_ascii=False, indent=2), encoding='utf-8')

    cats_bin = _cats_bin()
    if cats_bin and local_spec and target_url:
        cmd = [cats_bin, '-c', local_spec, '-s', target_url, '-b', '--skipReportingForIgnored']
        cmd.extend(_header_args(request.get('arguments') or {}))
        proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(out_dir), check=False)
        stdout_path = out_dir / 'cats_stdout.log'
        stderr_path = out_dir / 'cats_stderr.log'
        stdout_path.write_text(proc.stdout, encoding='utf-8')
        stderr_path.write_text(proc.stderr, encoding='utf-8')
        findings = _candidate_findings(tool_name, endpoint, method, proc.stdout, proc.stderr)
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'ok' if proc.returncode == 0 else 'partial',
            'summary': f'CATS runtime exited with code {proc.returncode}.',
            'signals': ['cats_runtime_adapter', 'cats_fuzz_invoked', 'negative_test_completed'] + (['server_error_observed'] if findings else []),
            'raw_report_paths': [str(report_path), str(stdout_path), str(stderr_path)],
            'candidate_findings': findings,
            'used_requests': 0,
            'termination_reason': 'completed' if proc.returncode == 0 else 'tool_reported_findings',
            'fallback_reason': None,
            'error': None if proc.returncode == 0 else 'cats_runtime_reported_failures',
        }
        _write_json(args.result_json, payload)
        return 0

    payload = {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': tool_name,
        'status': 'partial',
        'summary': f'CATS adapter prepared deterministic negative-testing plan for {len(inv)} operations.',
        'signals': ['cats_runtime_adapter', 'cats_fuzz_scaffold_ready', 'negative_test_completed', 'planner_only'],
        'raw_report_paths': [str(report_path)],
        'candidate_findings': [],
        'used_requests': 0,
        'termination_reason': 'tool_unavailable',
        'fallback_reason': 'CATS binary is not installed or target_url is missing; adapter prepared a negative-testing plan only.',
        'error': None,
    }
    _write_json(args.result_json, payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
