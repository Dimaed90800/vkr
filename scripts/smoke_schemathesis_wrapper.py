from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from fastapi.testclient import TestClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

try:
    from backend.main import app
except ModuleNotFoundError:  # Docker toolbox image copies backend contents to /app
    from main import app


class _SmokeTarget(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/openapi.json":
            self._json(200, self._openapi())
            return
        self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/items":
            self._json(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(raw or "{}")
        except Exception:
            payload = {}
        name = payload.get("name")
        if not isinstance(name, str) or len(name) < 3:
            self._json(500, {"error": "name validator crashed"})
            return
        self._json(201, {"id": "item-1", "name": name})

    def _openapi(self) -> dict:
        return {
            "openapi": "3.0.3",
            "info": {"title": "Schemathesis Wrapper Smoke", "version": "1.0.0"},
            "paths": {
                "/items": {
                    "post": {
                        "requestBody": {
                            "required": True,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["name"],
                                        "properties": {"name": {"type": "string", "minLength": 3}},
                                    }
                                }
                            },
                        },
                        "responses": {
                            "201": {
                                "description": "created",
                                "content": {"application/json": {"schema": {"type": "object"}}},
                            },
                            "400": {"description": "invalid input"},
                        },
                    }
                }
            },
        }

    def _json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _start_target() -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SmokeTarget)
    port = int(server.server_address[1])
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def _payload(port: int, output_dir: Path, *, include_openapi: bool = True) -> dict:
    payload = {
        "tool_name": "schemathesis_negative_test",
        "run_id": "run-schemathesis-smoke",
        "target_url": f"http://127.0.0.1:{port}",
        "execution_context": {
            "target_url": f"http://127.0.0.1:{port}",
            "allowed_hosts": [f"127.0.0.1:{port}"],
            "max_requests": 3,
            "max_duration_sec": 30,
        },
        "task": {
            "id": "task_schemathesis_smoke_001",
            "class": "injection",
            "subtype": "schema_negative_test",
            "endpoint": "/items",
            "method": "POST",
            "hypothesis": "Invalid request bodies should not trigger 5xx responses.",
            "allowed_tools": ["schemathesis_negative_test", "injection_test"],
            "worker_role": "Contract & Negative Testing Agent",
            "preferred_tool": "schemathesis_negative_test",
        },
        "task_metadata": {"worker_role": "Contract & Negative Testing Agent"},
        "budgets": {"max_requests": 3, "max_duration_sec": 30, "concurrency": 1},
        "arguments": {"max_examples": 3},
        "output_dir": str(output_dir),
    }
    if include_openapi:
        payload["openapi_url"] = f"http://127.0.0.1:{port}/openapi.json"
        payload["execution_context"]["openapi_url"] = f"http://127.0.0.1:{port}/openapi.json"
    return payload


def _print_response(response) -> dict:
    body = response.json()
    print(json.dumps(body, indent=2, ensure_ascii=False))
    return body


def _run_success(client: TestClient, port: int, output_dir: Path) -> int:
    response = client.post("/v1/tools/wrappers/execute", json=_payload(port, output_dir, include_openapi=True))
    body = _print_response(response)
    if response.status_code != 200:
        return 1
    evidence = body.get("judge_ready_evidence") or {}
    signals = set(evidence.get("signals") or [])
    return 0 if {"5xx", "schema_violation", "negative_test_completed"}.intersection(signals) else 1


def _run_missing_openapi(client: TestClient, port: int, output_dir: Path) -> int:
    response = client.post("/v1/tools/wrappers/execute", json=_payload(port, output_dir, include_openapi=False))
    body = _print_response(response)
    result = body.get("result") or {}
    signals = set(result.get("signals") or [])
    return 0 if (
        response.status_code == 200
        and result.get("status") == "partial"
        and result.get("termination_reason") == "missing_openapi"
        and "openapi_missing" in signals
        and result.get("fallback_reason")
    ) else 1


def _run_missing_cli(client: TestClient, port: int, output_dir: Path) -> int:
    original_path = os.environ.get("PATH", "")
    os.environ["PATH"] = ""
    try:
        response = client.post("/v1/tools/wrappers/execute", json=_payload(port, output_dir, include_openapi=True))
    finally:
        os.environ["PATH"] = original_path
    body = _print_response(response)
    result = body.get("result") or {}
    signals = set(result.get("signals") or [])
    return 0 if (
        response.status_code == 200
        and result.get("status") == "partial"
        and result.get("termination_reason") == "tool_unavailable"
        and "tool_unavailable" in signals
        and result.get("fallback_reason")
    ) else 1


def main() -> int:
    scenario = sys.argv[1] if len(sys.argv) > 1 else "success"
    if scenario == "success" and not (shutil.which("st") or shutil.which("schemathesis")):
        print("Schemathesis CLI not found. Build the toolbox image or install backend requirements first.", file=sys.stderr)
        return 2

    server, port, thread = _start_target()
    output_dir = Path(tempfile.mkdtemp(prefix="schemathesis-wrapper-smoke-"))
    client = TestClient(app)
    try:
        if scenario == "success":
            return _run_success(client, port, output_dir)
        if scenario == "missing-openapi":
            return _run_missing_openapi(client, port, output_dir)
        if scenario == "missing-cli":
            return _run_missing_cli(client, port, output_dir)
        print("Usage: python scripts/smoke_schemathesis_wrapper.py [success|missing-openapi|missing-cli]", file=sys.stderr)
        return 2
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)


if __name__ == "__main__":
    raise SystemExit(main())
