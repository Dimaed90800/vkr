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
    return os.getenv('RESTLER_BIN') or shutil.which('restler')


def _run_compile(restler_bin: str, openapi_path: str, out_dir: Path) -> tuple[int, str, str, list[str]]:
    cmd = [restler_bin, 'compile', '--api_spec', openapi_path]
    proc = subprocess.run(cmd, text=True, capture_output=True, cwd=str(out_dir), check=False)
    reports = []
    for candidate in ['Compile/grammar.py', 'Compile/dict.json']:
        path = out_dir / candidate
        if path.exists():
            reports.append(str(path))
    return proc.returncode, proc.stdout, proc.stderr, reports


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

    if tool_name == 'restler_replay':
        replay_path = out_dir / 'restler_replay_sequence.json'
        replay_path.write_text(json.dumps({'sequence': [request.get('task') or {}]}, ensure_ascii=False, indent=2), encoding='utf-8')
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'partial',
            'summary': 'RESTler replay adapter prepared deterministic replay artifacts.',
            'signals': ['restler_runtime_adapter', 'restler_replay_scaffold_ready', 'sequence_replay_planned'],
            'raw_report_paths': [str(replay_path)],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'scaffold_only',
            'fallback_reason': 'RESTler replay runtime is adapter-backed in this environment.',
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
    if tool_name == 'restler_compile' and restler_bin:
        code, stdout, stderr, reports = _run_compile(restler_bin, local_spec, out_dir)
        (out_dir / 'restler_stdout.log').write_text(stdout, encoding='utf-8')
        (out_dir / 'restler_stderr.log').write_text(stderr, encoding='utf-8')
        payload = {
            'schema_version': 'external-runtime-result/v1',
            'tool_name': tool_name,
            'status': 'ok' if code == 0 else 'partial',
            'summary': f'RESTler compile exited with code {code}.',
            'signals': ['restler_runtime_adapter', 'restler_compile_invoked', 'sequence_grammar_planned'],
            'raw_report_paths': reports + [str(out_dir / 'restler_stdout.log'), str(out_dir / 'restler_stderr.log')],
            'candidate_findings': [],
            'used_requests': 0,
            'termination_reason': 'completed' if code == 0 else 'tool_reported_findings',
            'fallback_reason': None,
            'error': None if code == 0 else 'restler_compile_failed',
        }
        _write_json(args.result_json, payload)
        return 0

    grammar_path = out_dir / 'Compile' / 'grammar.py'
    grammar_path.parent.mkdir(parents=True, exist_ok=True)
    grammar_path.write_text('# RESTler grammar placeholder generated by runtime adapter\n', encoding='utf-8')
    dict_path = out_dir / 'Compile' / 'dict.json'
    dict_path.write_text('{}\n', encoding='utf-8')
    signals = ['restler_runtime_adapter']
    if tool_name == 'restler_compile':
        signals.extend(['restler_compile_scaffold_ready', 'sequence_grammar_planned'])
        summary = 'RESTler compile adapter prepared grammar placeholders.'
    else:
        signals.extend(['restler_fuzz_scaffold_ready', 'stateful_sequence_fuzzing_planned'])
        summary = 'RESTler fuzz adapter prepared deterministic stateful fuzz inputs.'
    payload = {
        'schema_version': 'external-runtime-result/v1',
        'tool_name': tool_name,
        'status': 'partial',
        'summary': summary,
        'signals': signals,
        'raw_report_paths': [str(grammar_path), str(dict_path)],
        'candidate_findings': [],
        'used_requests': 0,
        'termination_reason': 'scaffold_only',
        'fallback_reason': 'RESTler binary is not installed; adapter generated compile/fuzz artifacts only.',
        'error': None,
    }
    _write_json(args.result_json, payload)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
