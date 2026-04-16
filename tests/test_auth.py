import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi.testclient import TestClient

from backend.main import app


class _RoleAwareHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        role = self.headers.get("X-Debug-Role", "unknown")
        payload = {
            "resource_id": "veh-123",
            "role_echo": role,
            "shared_value": "same-object",
        }
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _build_payload(port: int, endpoint: str | None = None) -> dict:
    resolved_endpoint = endpoint or f"http://127.0.0.1:{port}/identity/api/v2/vehicle/veh-123/location"
    return {
        "execution_context": {
            "target_url": f"http://127.0.0.1:{port}",
            "allowed_hosts": [f"127.0.0.1:{port}"],
            "roles": [
                {"name": "user_a", "auth_headers": {"Authorization": "Bearer token-a"}},
                {"name": "user_b", "auth_headers": {"Authorization": "Bearer token-b"}},
            ],
            "max_requests": 100,
            "max_duration_sec": 900,
            "max_retries_per_task": 1,
        },
        "task": {
            "id": "task_authz_bola_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": resolved_endpoint,
            "method": "GET",
            "params": {
                "path_params": ["id"],
                "query_params": [],
                "body_fields": [],
                "object_id_candidates": ["veh-123"],
            },
            "auth_context": {
                "owner_role": "user_a",
                "other_role": "user_b",
                "token_strategy": "cross_role_replay",
            },
            "hypothesis": "Cross-role access to the same object may be possible.",
            "priority": 90,
            "retry_count": 0,
            "rework_hint": None,
            "status": "pending",
            "allowed_tools": ["auth_test_access"],
        },
        "tool_name": "auth_test_access",
        "arguments": {
            "endpoint": resolved_endpoint,
            "method": "GET",
            "owner_role": "user_a",
            "other_role": "user_b",
            "object_id": "veh-123",
        },
    }


def test_successful_authorization_comparison() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _RoleAwareHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    client = TestClient(app)
    try:
        response = client.post("/v1/auth/test-access", json=_build_payload(port))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["request_summary"]["tested_roles"] == ["user_a", "user_b"]
    assert body["response_summary"]["owner"]["status_code"] == 200
    assert body["response_summary"]["other"]["status_code"] == 200
    assert body["response_summary"]["similarity"] >= 0.85
    assert body["raw_status"] == "success"
    assert "same_status_code" in body["indicators"]
    assert "similar_response" in body["indicators"]
    assert "potential_bola" in body["indicators"]


def test_request_error_returns_error_status() -> None:
    client = TestClient(app)
    payload = _build_payload(6553, "http://127.0.0.1:6553/unreachable")

    response = client.post("/v1/auth/test-access", json=payload)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_status"] == "error"
    assert body["response_summary"]["owner"]["status_code"] is None
    assert body["response_summary"]["other"]["status_code"] is None
    assert "access_test_completed" in body["indicators"]


def test_blocked_host_is_rejected() -> None:
    client = TestClient(app)
    payload = _build_payload(80, "http://example.com/protected")
    payload["execution_context"]["allowed_hosts"] = ["127.0.0.1:80"]
    payload["execution_context"]["target_url"] = "http://example.com"

    response = client.post("/v1/auth/test-access", json=payload)

    assert response.status_code == 400, response.text
    detail = response.json()["detail"]
    assert detail["error"] == "invalid_authorization_test"
