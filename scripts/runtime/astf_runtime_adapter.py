from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path


VULN_KEYWORDS = (
    'vulnerability', 'critical', 'high', 'medium', 'low', 'exposed', 'misconfiguration', 'broken', 'unauthorized'
)


def _load_request(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _write_json(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def _astf_bin() -> str | None:
    return os.getenv('ASTF_BIN') or shutil.which('astf')


def _auth_header_value(request: dict) -> str | None:
    arguments = request.get('arguments') or {}
    headers = arguments.get('headers') or {}
    if isinstance(headers, dict):
        value = headers.get('Authorization') or headers.get('authorization')
        if value:
            return f'Authorization: {value}'
    return None


def _candidate_findings_from_output(tool_name: str, endpoint: str, method: str, stdout: str, stderr: str) -> list[dict]:
    text = f"{stdout}\n{stderr}".lower()
    findings = []
    for keyword in VULN_KEYWORDS:
        if keyword in text:
            findings.append({
                'vuln_type': 'astf_signal',
                'endpoint': endpoint,
                'method': method,
                'confidence': 0.35,
                'source_tool': tool_name,
                'details': {'keyword': keyword},
            })
    return findings[:10]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--request-json', required=True)
    parser.add_argument('--result-json', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    request = _load_request(args.request_json)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tool_name = str(request.get('tool_name') or 'astf_top10_suite')
    target_url = str(request.get('target_url') or '')
    task = request.get('task') or {}
    endpoint = str(task.get('endpoint') or '')
    method = str(task.get('method') or 'GET').upper()

    astf_bin = _astf_bin()
    if not astf_bin:
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'partial',
            'summary': 'ASTF runtime is not installed.',
            'signals': ['astf_runtime_adapter', 'tool_unavailable'],
            'raw_report_paths': [],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'tool_unavailable',
            'fallback_reason': 'ASTF binary is not installed.',
            'error': 'astf_runtime_missing',
        }
        _write_json(args.result_json, payload)
        return 0

    cmd = [astf_bin, 'scan', '--target', target_url]
    auth_header = _auth_header_value(request)
    if auth_header:
        cmd.extend(['--auth-header', auth_header])

    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(out_dir), check=False)
    stdout_path = out_dir / 'astf_stdout.log'
    stderr_path = out_dir / 'astf_stderr.log'
    stdout_path.write_text(proc.stdout, encoding='utf-8')
    stderr_path.write_text(proc.stderr, encoding='utf-8')

    findings = _candidate_findings_from_output(tool_name, endpoint, method, proc.stdout, proc.stderr)
    payload = {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': tool_name,
        'status': 'ok' if proc.returncode == 0 else 'partial',
        'summary': f'ASTF runtime exited with code {proc.returncode}.',
        'signals': ['astf_runtime_adapter', 'astf_scan_invoked'] + (['astf_reported_signals'] if findings else []),
        'raw_report_paths': [str(stdout_path), str(stderr_path)],
        'candidate_findings': findings,
        'used_requests': 0,
        'termination_reason': 'completed' if proc.returncode == 0 else 'tool_reported_findings',
        'fallback_reason': None,
        'error': None if proc.returncode == 0 else 'astf_runtime_reported_failures',
    }
    _write_json(args.result_json, payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
