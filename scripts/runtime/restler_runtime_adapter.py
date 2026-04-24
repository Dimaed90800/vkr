from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen


def _load_request(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding='utf-8'))


def _write_json(path: str, payload: dict) -> None:
    Path(path).write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding='utf-8')


def _fetch_openapi(ref: str, out_dir: Path) -> str | None:
    if not ref:
        return None
    target = out_dir / 'openapi.json'
    if ref.startswith('http://') or ref.startswith('https://'):
        with urlopen(ref) as resp:  # nosec - controlled by user target scope in backend
            target.write_bytes(resp.read())
    else:
        target.write_bytes(Path(ref).read_bytes())
    return str(target)


def _restler_bin() -> str | None:
    return os.getenv('RESTLER_BIN') or shutil.which('restler') or '/RESTler/restler/Restler'


def _run(cmd: list[str], cwd: Path) -> tuple[int, str, str]:
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(cwd), check=False)
    return proc.returncode, proc.stdout, proc.stderr


def _write_logs(out_dir: Path, prefix: str, stdout: str, stderr: str) -> list[str]:
    stdout_path = out_dir / f'{prefix}_stdout.log'
    stderr_path = out_dir / f'{prefix}_stderr.log'
    stdout_path.write_text(stdout, encoding='utf-8')
    stderr_path.write_text(stderr, encoding='utf-8')
    return [str(stdout_path), str(stderr_path)]


def _settings_file(out_dir: Path, target_url: str) -> str:
    settings = {
        'host': target_url,
        'use_ssl': target_url.startswith('https://'),
        'include_user_agent': True,
        'no_tokens_in_logs': True,
    }
    path = out_dir / 'restler_settings.json'
    path.write_text(json.dumps(settings, ensure_ascii=False, indent=2), encoding='utf-8')
    return str(path)


def _find_compile_artifacts(out_dir: Path) -> tuple[str | None, str | None]:
    grammar = None
    dictionary = None
    for candidate in [out_dir / 'Compile' / 'grammar.py', out_dir / 'grammar.py']:
        if candidate.exists():
            grammar = str(candidate)
            break
    for candidate in [out_dir / 'Compile' / 'dict.json', out_dir / 'dict.json']:
        if candidate.exists():
            dictionary = str(candidate)
            break
    return grammar, dictionary


def _candidate_findings(tool_name: str, endpoint: str, method: str, out_dir: Path) -> list[dict]:
    findings = []
    for bug_file in out_dir.rglob('bug_buckets.txt'):
        text = bug_file.read_text(encoding='utf-8', errors='ignore')
        if text.strip():
            findings.append({
                'vuln_type': 'stateful_runtime_bug_bucket',
                'endpoint': endpoint,
                'method': method,
                'confidence': 0.6,
                'source_tool': tool_name,
                'details': {'bug_buckets_path': str(bug_file)},
            })
    return findings[:20]


def _fallback_payload(request: dict, summary: str, out_dir: Path, extra_signals: list[str] | None = None, termination_reason: str = 'tool_unavailable') -> dict:
    reports = []
    config_path = out_dir / 'restler_runtime_adapter.json'
    config_path.write_text(json.dumps({'request': request, 'notes': summary}, ensure_ascii=False, indent=2), encoding='utf-8')
    reports.append(str(config_path))
    return {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': request.get('tool_name', 'restler_fuzz'),
        'status': 'partial',
        'summary': summary,
        'signals': ['restler_runtime_adapter', *(extra_signals or [])],
        'raw_report_paths': reports,
        'candidate_findings': [],
        'used_requests': 0,
        'termination_reason': termination_reason,
        'fallback_reason': summary,
        'error': summary,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument('--request-json', required=True)
    parser.add_argument('--result-json', required=True)
    parser.add_argument('--output-dir', required=True)
    args = parser.parse_args()

    request = _load_request(args.request_json)
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    tool_name = str(request.get('tool_name') or 'restler_fuzz')
    openapi_ref = str(request.get('openapi_ref') or '')
    target_url = str(request.get('target_url') or '')
    task = request.get('task') or {}
    endpoint = str(task.get('endpoint') or '')
    method = str(task.get('method') or 'GET').upper()

    if tool_name == 'restler_replay':
        replay_path = out_dir / 'restler_replay_sequence.json'
        replay_path.write_text(json.dumps({'sequence': [task]}, ensure_ascii=False, indent=2), encoding='utf-8')
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'partial',
            'summary': 'RESTler replay adapter prepared deterministic replay artifacts.',
            'signals': ['restler_runtime_adapter', 'restler_replay_scaffold_ready', 'sequence_replay_planned'],
            'raw_report_paths': [str(replay_path)],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'planner_only',
            'fallback_reason': 'Sequence replay remains adapter-only in this project; use replay_http_sequence for concrete replay.',
            'error': None,
        }
        _write_json(args.result_json, payload)
        return 0

    if not openapi_ref:
        payload = _fallback_payload(request, 'RESTler adapter requires openapi_ref for compile/fuzz.', out_dir, ['openapi_missing'], 'missing_openapi')
        _write_json(args.result_json, payload)
        return 0

    try:
        local_spec = _fetch_openapi(openapi_ref, out_dir)
    except Exception as exc:
        payload = _fallback_payload(request, f'Failed to fetch OpenAPI for RESTler: {exc}', out_dir, ['openapi_fetch_failed'], 'missing_openapi')
        _write_json(args.result_json, payload)
        return 0

    restler_bin = _restler_bin()
    if not restler_bin or (not Path(restler_bin).exists() and shutil.which(restler_bin) is None):
        payload = _fallback_payload(request, 'RESTler binary is not installed.', out_dir, ['tool_unavailable'], 'tool_unavailable')
        _write_json(args.result_json, payload)
        return 0

    compile_cmd = [restler_bin, 'compile', '--api_spec', local_spec]
    code, stdout, stderr = _run(compile_cmd, out_dir)
    reports = _write_logs(out_dir, 'restler_compile', stdout, stderr)
    grammar_file, dict_file = _find_compile_artifacts(out_dir)
    if grammar_file:
        reports.append(grammar_file)
    if dict_file:
        reports.append(dict_file)

    if tool_name == 'restler_compile':
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'ok' if code == 0 else 'partial',
            'summary': f'RESTler compile exited with code {code}.',
            'signals': ['restler_runtime_adapter', 'restler_compile_invoked', 'sequence_grammar_planned'],
            'raw_report_paths': reports,
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'completed' if code == 0 else 'tool_reported_findings',
            'fallback_reason': None,
            'error': None if code == 0 else 'restler_compile_failed',
        }
        _write_json(args.result_json, payload)
        return 0

    if code != 0 or not grammar_file or not dict_file:
        payload = _fallback_payload(
            request,
            'RESTler compile did not produce grammar.py and dict.json required for fuzzing.',
            out_dir,
            ['compile_failed'],
            'tool_reported_findings',
        )
        _write_json(args.result_json, payload)
        return 0

    settings_file = _settings_file(out_dir, target_url)
    fuzz_cmd = [restler_bin, 'fuzz-lean', '--grammar_file', grammar_file, '--dictionary_file', dict_file, '--settings', settings_file]
    fuzz_code, fuzz_stdout, fuzz_stderr = _run(fuzz_cmd, out_dir)
    reports.extend(_write_logs(out_dir, 'restler_fuzz_lean', fuzz_stdout, fuzz_stderr))
    findings = _candidate_findings(tool_name, endpoint, method, out_dir)
    payload = {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': tool_name,
        'status': 'ok' if fuzz_code == 0 else 'partial',
        'summary': f'RESTler fuzz-lean exited with code {fuzz_code}.',
        'signals': ['restler_runtime_adapter', 'restler_fuzz_invoked', 'stateful_sequence_fuzzing_planned'] + (['bug_buckets_found'] if findings else []),
        'raw_report_paths': reports,
        'candidate_findings': findings,
        'used_requests': 0,
        'termination_reason': 'completed' if fuzz_code == 0 else 'tool_reported_findings',
        'fallback_reason': None,
        'error': None if fuzz_code == 0 else 'restler_fuzz_failed',
    }
    _write_json(args.result_json, payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
