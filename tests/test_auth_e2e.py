import socket
import threading
import time

import pytest
import uvicorn
from fastapi.testclient import TestClient

from backend.main import app as toolbox_app
from demo_target.main import create_app


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _run_demo_server(mode: str, port: int):
    app = create_app(mode=mode)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    deadline = time.time() + 5
    while not server.started and time.time() < deadline:
        time.sleep(0.05)

    if not server.started:
        raise RuntimeError("Demo target did not start in time")

    return server, thread


def _request_payload(mode: str, port: int) -> dict:
    return {
        "execution_context": {
            "target_url": f"http://127.0.0.1:{port}",
            "allowed_hosts": [f"127.0.0.1:{port}"],
            "roles": [
                {"name": "user_a", "auth_headers": {"Authorization": "Bearer token-a"}},
                {"name": "user_b", "auth_headers": {"Authorization": "Bearer token-b"}},
            ],
            "max_requests": 20,
            "max_duration_sec": 300,
            "max_retries_per_task": 1,
        },
        "task": {
            "id": "task_authz_bola_vehicle_location_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/vehicle/veh-123/location",
            "method": "GET",
            "params": {
                "path_params": ["vehicle_id"],
                "query_params": ["mode"],
                "body_fields": [],
                "object_id_candidates": ["veh-123"],
            },
            "auth_context": {
                "owner_role": "user_a",
                "other_role": "user_b",
                "token_strategy": "cross_role_replay",
            },
            "hypothesis": "Different roles may access the same vehicle location object.",
            "priority": 90,
            "retry_count": 0,
            "rework_hint": None,
            "status": "pending",
            "allowed_tools": ["auth_test_access"],
        },
        "tool_name": "auth_test_access",
        "arguments": {
            "endpoint": "/identity/api/v2/vehicle/veh-123/location",
            "method": "GET",
            "owner_role": "user_a",
            "other_role": "user_b",
            "query_params": {
                "mode": mode,
            },
        },
    }


@pytest.mark.parametrize(
    ("mode", "expect_bola"),
    [
        ("vulnerable", True),
        ("secure", False),
    ],
)
def test_auth_e2e_demo_target(mode: str, expect_bola: bool) -> None:
    port = _free_port()
    server, thread = _run_demo_server(mode, port)
    client = TestClient(toolbox_app)

    try:
        response = client.post("/v1/auth/test-access", json=_request_payload(mode, port))
    finally:
        server.should_exit = True
        thread.join(timeout=5)

    assert response.status_code == 200, response.text
    body = response.json()
    indicators = body["indicators"]

    assert body["request_summary"]["tested_roles"] == ["user_a", "user_b"]
    assert body["response_summary"]["owner"]["status_code"] == 200

    if expect_bola:
        assert body["response_summary"]["other"]["status_code"] == 200
        assert "potential_bola" in indicators
    else:
        assert body["response_summary"]["other"]["status_code"] == 403
        assert "potential_bola" not in indicators
