import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from fastapi.testclient import TestClient

from backend.main import app


class _ExtendedToolHandler(BaseHTTPRequestHandler):
    mutable_state = {"role": "ROLE_USER", "status": "pending"}
    order_counter = 0

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        if path == "/search":
            if "codex_probe" in query:
                self._send_json(500, {"error": "SQL syntax error near codex_probe_1337"})
                return
            self._send_json(200, {"result": "ok"})
            return
        if path == "/stable-search":
            self._send_json(200, {"result": "stable"})
            return
        if path == "/reflect-search":
            marker = query.split("=", 1)[1] if "=" in query else ""
            self._send_json(200, {"result": marker})
            return
        if path == "/slow-search":
            if "1%27%20OR%20%271%27%3D%271" in query or "1' OR '1'='1" in query:
                time.sleep(0.9)
            self._send_json(200, {"result": "ok"})
            return
        if path == "/identity/api/v2/user/dashboard":
            self._send_json(200, {"id": 1, "email": "victim@example.com", "credit": 100, "role": "ROLE_USER"})
            return
        if path == "/nested-exposure":
            self._send_json(200, {"owner": {"email": "owner@example.com", "balance": 77}, "vehicle": {"vin": "VIN-123"}})
            return
        if path == "/validation-leak":
            self._send_json(422, {"message": "validation error", "token": "field required", "email": "field required"})
            return
        if path == "/harmless":
            self._send_json(200, {"status": "ok", "items": [1, 2, 3]})
            return
        if path == "/ignored-mutation":
            self._send_json(200, {"status": "ok"})
            return
        if path == "/accounts/settings":
            self._send_json(200, dict(self.mutable_state))
            return
        if path == "/workshop/api/shop/orders/all":
            if "authorization" not in {k.lower() for k in self.headers}:
                self._send_json(401, {"error": "missing auth"})
                return
            self._send_json(200, {"orders": [{"order_id": "ord-001", "status": "created"}]})
            return
        if path in {"/v1/orders", "/v2/orders"}:
            self._send_json(200, {"version": path.split("/")[1], "orders": []})
            return
        if path == "/config":
            body = {"debug": True, "internal_url": "http://localhost:9000/admin"}
            self._send_json(200, body, extra_headers={"X-Debug": "enabled", "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(raw or "{}")
        except Exception:
            payload = {}

        if self.path == "/identity/api/v2/user/change-email":
            self._send_json(200, payload)
            return
        if self.path == "/checkout":
            self._send_json(200, {"status": payload.get("status", "approved"), "accepted": True})
            return
        if self.path == "/apply_coupon":
            self._send_json(200, {"coupon": payload.get("coupon_code", "X"), "accepted": True})
            return
        if self.path == "/accounts/settings":
            self.mutable_state.update({k: v for k, v in payload.items() if k in {"role", "status"}})
            self._send_json(200, payload)
            return
        if self.path == "/workshop/api/shop/orders":
            if "authorization" not in {k.lower() for k in self.headers}:
                self._send_json(401, {"error": "missing auth"})
                return
            type(self).order_counter += 1
            self._send_json(201, {"status": "created", "order_id": f"ord-{type(self).order_counter:03d}"})
            return
        if self.path == "/workshop/api/shop/orders/return_order":
            if "authorization" not in {k.lower() for k in self.headers}:
                self._send_json(401, {"error": "missing auth"})
                return
            self._send_json(200, {"status": "returned", "accepted": True})
            return
        if self.path == "/ignored-mutation":
            self._send_json(200, {"status": "ok"})
            return
        if self.path == "/identity/api/auth/login":
            self._send_json(200, {"message": "ok"})
            return

        self._send_json(404, {"error": "not found"})

    def do_OPTIONS(self) -> None:  # noqa: N802
        if self.path == "/config":
            self._send_json(200, {"allow": "GET,OPTIONS,TRACE"}, extra_headers={"Allow": "GET,OPTIONS,TRACE"})
            return
        self._send_json(405, {"error": "not allowed"})

    def do_TRACE(self) -> None:  # noqa: N802
        if self.path == "/config":
            self._send_json(200, {"trace": True})
            return
        self._send_json(405, {"error": "not allowed"})

    def _send_json(self, status: int, payload: dict, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def _server() -> tuple[ThreadingHTTPServer, int, threading.Thread]:
    _ExtendedToolHandler.mutable_state = {"role": "ROLE_USER", "status": "pending"}
    _ExtendedToolHandler.order_counter = 0
    server = ThreadingHTTPServer(("127.0.0.1", 0), _ExtendedToolHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def _context(port: int) -> dict:
    return {
        "target_url": f"http://127.0.0.1:{port}",
        "allowed_hosts": [f"127.0.0.1:{port}"],
        "roles": [
            {"name": "user_a", "auth_headers": {"Authorization": "Bearer token-a"}},
            {"name": "user_b", "auth_headers": {"Authorization": "Bearer token-b"}},
        ],
        "max_requests": 10,
        "max_duration_sec": 30,
        "max_retries_per_task": 1,
        "capabilities": {"has_auth_profiles": True},
    }


def test_property_mutation_tool_returns_structured_evidence() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_auth_property_001",
            "class": "authorization",
            "subtype": "property_level_authorization",
            "endpoint": "/identity/api/v2/user/change-email",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["email", "role"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Sensitive fields may be writable.",
            "allowed_tools": ["property_mutation_test"],
        },
        "tool_name": "property_mutation_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/auth/property-mutation-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert "sensitive_field_accepted" in body["indicators"]
    assert body["response_summary"]["finding_type_hint"] == "property_level_authorization"
    assert "role" in body["response_summary"]["mutated_fields"]


def test_injection_tool_detects_error_and_behavior_change() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_injection_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/search",
            "method": "GET",
            "params": {"path_params": [], "query_params": ["q"], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Search may be injectable.",
            "allowed_tools": ["injection_test"],
        },
        "tool_name": "injection_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/injection/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert "sql_error_signal" in body["indicators"]
    assert "significant_behavior_change" in body["indicators"]
    assert body["response_summary"]["finding_type_hint"] == "injection"
    assert body["response_summary"]["evidence_strength"] == "strong"


def test_injection_similar_baseline_attack_without_signal_stays_weak() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_injection_weak_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/stable-search",
            "method": "GET",
            "params": {"path_params": [], "query_params": ["q"], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Stable search should not over-confirm injection.",
            "allowed_tools": ["injection_test"],
        },
        "tool_name": "injection_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/injection/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["evidence_strength"] == "weak"
    assert "sql_error_signal" not in body["indicators"]
    assert "unescaped_reflection" not in body["indicators"]


def test_injection_reflection_and_time_anomaly_are_captured() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    reflection_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_injection_reflect_001",
            "class": "injection",
            "subtype": "reflection_probe",
            "endpoint": "/reflect-search",
            "method": "GET",
            "params": {"path_params": [], "query_params": ["q"], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Reflection should be visible.",
            "allowed_tools": ["injection_test"],
        },
        "tool_name": "injection_test",
        "arguments": {},
    }
    slow_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_injection_slow_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/slow-search",
            "method": "GET",
            "params": {"path_params": [], "query_params": ["q"], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Slow response should be recorded.",
            "allowed_tools": ["injection_test"],
        },
        "tool_name": "injection_test",
        "arguments": {},
    }
    try:
        reflection_response = client.post("/v1/injection/test", json=reflection_payload)
        slow_response = client.post("/v1/injection/test", json=slow_payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    reflection_body = reflection_response.json()
    slow_body = slow_response.json()
    assert reflection_response.status_code == 200, reflection_response.text
    assert "reflection_detected" in reflection_body["indicators"]
    assert reflection_body["response_summary"]["reflection"]["context_summary"] in {"raw", "escaped"}
    assert slow_response.status_code == 200, slow_response.text
    assert slow_body["response_summary"]["time_signal"]["significant_time_anomaly"] is True
    assert "significant_time_anomaly" in slow_body["indicators"]


def test_logic_tool_reports_invariant_violation() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_logic_001",
            "class": "business_logic",
            "subtype": "workflow_bypass",
            "endpoint": "/checkout",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["status", "amount"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Workflow may accept invalid transitions.",
            "allowed_tools": ["logic_test"],
            "capability_state": {"has_workflow_hints": True},
        },
        "tool_name": "logic_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/logic/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert "invariant_violation" in body["indicators"]
    assert body["response_summary"]["finding_type_hint"] == "workflow_abuse"
    assert body["response_summary"]["evidence_strength"] == "strong"
    assert "baseline_state" in body["response_summary"]["state_delta_summary"]
    assert "invalid_transition_accepted" in body["response_summary"]["violated_invariant_summary"]


def test_logic_tool_reports_repeated_and_cross_role_workflow_evidence() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_logic_repeat_001",
            "class": "business_logic",
            "subtype": "repeated_sensitive_action",
            "endpoint": "/apply_coupon",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["coupon_code"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Coupon action may be repeatable and cross-role accessible.",
            "allowed_tools": ["logic_test"],
            "capability_state": {"has_workflow_hints": True},
        },
        "tool_name": "logic_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/logic/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    violated = body["response_summary"]["violated_invariant_summary"]
    assert violated["repeated_sensitive_action_allowed"] is True
    assert violated["cross_role_workflow_access"] is True
    assert body["response_summary"]["evidence_strength"] in {"medium", "strong"}


def test_logic_tool_on_auth_required_endpoint_uses_authenticated_context() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_logic_auth_required_001",
            "class": "business_logic",
            "subtype": "invalid_transition",
            "endpoint": "/workshop/api/shop/orders",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["product_id", "quantity"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Order workflow should use authenticated context.",
            "allowed_tools": ["logic_test"],
            "capability_state": {"has_workflow_hints": True},
            "context_hints": {"auth_required": True, "resource_family": "order"},
        },
        "tool_name": "logic_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/logic/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["baseline"]["status_code"] != 401
    assert "missing_auth_context" not in body["indicators"]


def test_logic_tool_401_only_probe_becomes_preparation_signal() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": {**_context(port), "roles": []},
        "task": {
            "id": "task_logic_401_001",
            "class": "business_logic",
            "subtype": "invalid_transition",
            "endpoint": "/workshop/api/shop/orders/return_order",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["order_id"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Unauthenticated workflow probes should not count as real logic tests.",
            "allowed_tools": ["logic_test"],
            "capability_state": {"has_workflow_hints": True},
            "context_hints": {"auth_required": True, "resource_family": "order"},
        },
        "tool_name": "logic_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/logic/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_status"] == "blocked"
    assert "missing_auth_context" in body["indicators"]
    assert "unauthenticated_request_to_auth_required_endpoint" in body["indicators"]


def test_logic_test_delegates_preparation_task_to_workflow_probe() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_logic_prepare_001",
            "class": "business_logic",
            "subtype": "invalid_transition",
            "endpoint": "/workshop/api/shop/orders/return_order",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["order_id"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Prepare workflow state before retrying return flow.",
            "allowed_tools": ["workflow_probe"],
            "readiness": "needs_preparation",
            "test_strategy": "prepare_workflow_state_then_retry",
            "context_hints": {"resource_family": "order", "auth_required": True},
        },
        "tool_name": "logic_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/logic/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["request_summary"]["action"] == "workflow_probe"
    assert body["response_summary"]["status"] == "stubbed_preparation"
    assert "preparation_possible" in body["indicators"]


def test_injection_test_delegates_preparation_task_to_input_shape_probe() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_injection_prepare_001",
            "class": "injection",
            "subtype": "input_injection",
            "endpoint": "/search",
            "method": "GET",
            "params": {"path_params": [], "query_params": ["q"], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Infer input shape before a direct injection attempt.",
            "allowed_tools": ["input_shape_probe"],
            "readiness": "needs_preparation",
            "test_strategy": "baseline_refinement",
        },
        "tool_name": "injection_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/injection/test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["request_summary"]["action"] == "input_shape_probe"
    assert "input_shape_inferred" in body["indicators"]


def test_authorization_placeholder_object_id_prevents_execution() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_authorization_placeholder_001",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/admin/videos/{video_id}",
            "method": "GET",
            "params": {
                "path_params": ["video_id"],
                "query_params": [],
                "body_fields": [],
                "object_id_candidates": [],
                "selected_object_id": "video_id",
                "requires_object_id_enrichment": True,
                "object_param_name": "video_id",
            },
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Placeholder object ids should be blocked before auth replay.",
            "allowed_tools": ["auth_test_access"],
            "context_hints": {"auth_required": True, "resource_family": "video"},
        },
        "tool_name": "auth_test_access",
        "arguments": {},
    }
    try:
        response = client.post("/v1/auth/test-access", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_status"] == "blocked"
    assert "placeholder_object_id" in body["indicators"]


def test_auth_test_access_never_materializes_literal_placeholder_without_real_id() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_authorization_placeholder_002",
            "class": "authorization",
            "subtype": "bola",
            "endpoint": "/identity/api/v2/admin/videos/{video_id}",
            "method": "GET",
            "params": {
                "path_params": ["video_id"],
                "query_params": [],
                "body_fields": [],
                "object_id_candidates": [],
                "selected_object_id": None,
                "requires_object_id_enrichment": True,
                "object_param_name": "video_id",
            },
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "No placeholder literal path materialization should occur.",
            "allowed_tools": ["auth_test_access"],
            "context_hints": {"auth_required": True, "resource_family": "video"},
        },
        "tool_name": "auth_test_access",
        "arguments": {},
    }
    try:
        response = client.post("/v1/auth/test-access", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["raw_status"] == "blocked"
    assert "/videos/video_id" not in body["request_summary"]["endpoint"]


def test_rate_abuse_tool_extracts_no_rate_limit_signal() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_rate_001",
            "class": "business_logic",
            "subtype": "rate_abuse",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["email", "password"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Login may lack throttling.",
            "allowed_tools": ["resource_abuse_test"],
        },
        "tool_name": "resource_abuse_test",
        "arguments": {"attempt_count": 3},
    }
    try:
        response = client.post("/v1/resource/abuse-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["attempt_count"] == 3
    assert body["response_summary"]["no_rate_limit_detected"] is True
    assert "no_rate_limit_detected" in body["indicators"]


def test_data_exposure_detects_sensitive_keys_and_harmless_json_stays_weak() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    sensitive_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_exposure_sensitive_001",
            "class": "business_logic",
            "subtype": "excessive_data_exposure",
            "endpoint": "/identity/api/v2/user/dashboard",
            "method": "GET",
            "params": {"path_params": [], "query_params": [], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Dashboard may expose sensitive fields.",
            "allowed_tools": ["data_exposure_test"],
        },
        "tool_name": "data_exposure_test",
        "arguments": {},
    }
    harmless_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_exposure_harmless_001",
            "class": "business_logic",
            "subtype": "excessive_data_exposure",
            "endpoint": "/harmless",
            "method": "GET",
            "params": {"path_params": [], "query_params": [], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Harmless endpoint should stay weak.",
            "allowed_tools": ["data_exposure_test"],
        },
        "tool_name": "data_exposure_test",
        "arguments": {},
    }
    try:
        sensitive_response = client.post("/v1/data/exposure-test", json=sensitive_payload)
        harmless_response = client.post("/v1/data/exposure-test", json=harmless_payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    sensitive_body = sensitive_response.json()
    harmless_body = harmless_response.json()
    assert sensitive_response.status_code == 200, sensitive_response.text
    assert "email" in {item.split(".")[-1] for item in sensitive_body["response_summary"]["sensitive_keys_found"]}
    assert sensitive_body["response_summary"]["evidence_strength"] == "strong"
    assert harmless_response.status_code == 200, harmless_response.text
    assert harmless_body["response_summary"]["sensitive_keys_found"] == []
    assert harmless_body["response_summary"]["evidence_strength"] == "weak"


def test_data_exposure_validation_schema_leak_stays_weak() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_exposure_validation_001",
            "class": "business_logic",
            "subtype": "excessive_data_exposure",
            "endpoint": "/validation-leak",
            "method": "GET",
            "params": {"path_params": [], "query_params": [], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Validation error should remain a weak hint.",
            "allowed_tools": ["data_exposure_test"],
        },
        "tool_name": "data_exposure_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/data/exposure-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["weak_signal_class"] == "schema_disclosure"
    assert body["response_summary"]["evidence_strength"] == "weak"
    assert "schema_disclosure" in body["indicators"]


def test_data_exposure_nested_sensitive_keys_are_recognized() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_exposure_nested_001",
            "class": "business_logic",
            "subtype": "excessive_data_exposure",
            "endpoint": "/nested-exposure",
            "method": "GET",
            "params": {"path_params": [], "query_params": [], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Nested sensitive keys should be recognized.",
            "allowed_tools": ["data_exposure_test"],
        },
        "tool_name": "data_exposure_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/data/exposure-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["nested_sensitive_keys_found"] != []
    assert body["response_summary"]["sample_exposed_fields"] != {}
    assert body["response_summary"]["evidence_strength"] == "strong"


def test_property_mutation_persistence_is_stronger_than_reflection_only() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    reflection_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_property_reflect_001",
            "class": "authorization",
            "subtype": "property_level_authorization",
            "endpoint": "/identity/api/v2/user/change-email",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["email", "role"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Reflected-only mutation should be weaker.",
            "allowed_tools": ["property_mutation_test"],
        },
        "tool_name": "property_mutation_test",
        "arguments": {},
    }
    persisted_payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_property_persist_001",
            "class": "authorization",
            "subtype": "property_level_authorization",
            "endpoint": "/accounts/settings",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["role", "status"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Persisted mutation should be stronger.",
            "allowed_tools": ["property_mutation_test"],
        },
        "tool_name": "property_mutation_test",
        "arguments": {},
    }
    try:
        reflection_response = client.post("/v1/auth/property-mutation-test", json=reflection_payload)
        persisted_response = client.post("/v1/auth/property-mutation-test", json=persisted_payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    reflection_body = reflection_response.json()
    persisted_body = persisted_response.json()
    assert reflection_response.status_code == 200, reflection_response.text
    assert persisted_response.status_code == 200, persisted_response.text
    assert reflection_body["response_summary"]["evidence_strength"] == "medium"
    assert persisted_body["response_summary"]["evidence_strength"] == "strong"
    assert persisted_body["response_summary"]["persisted_fields"] != []


def test_property_mutation_2xx_without_effect_stays_weak() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_property_ignored_001",
            "class": "authorization",
            "subtype": "property_level_authorization",
            "endpoint": "/ignored-mutation",
            "method": "POST",
            "params": {"path_params": [], "query_params": [], "body_fields": ["role", "status"]},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "2xx alone should not count as a strong mutation effect.",
            "allowed_tools": ["property_mutation_test"],
        },
        "tool_name": "property_mutation_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/auth/property-mutation-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["response_summary"]["accepted_fields"] == []
    assert body["response_summary"]["persisted_fields"] == []
    assert body["response_summary"]["evidence_strength"] == "weak"


def test_version_diff_tool_detects_deprecated_path() -> None:
    server, port, thread = _server()
    client = TestClient(app)
    payload = {
        "execution_context": _context(port),
        "task": {
            "id": "task_assets_001",
            "class": "business_logic",
            "subtype": "improper_assets_management",
            "endpoint": "/v2/orders",
            "method": "GET",
            "params": {"path_params": [], "query_params": [], "body_fields": []},
            "auth_context": {"owner_role": "user_a", "other_role": "user_b", "token_strategy": "cross_role_replay"},
            "hypothesis": "Older API versions may still be exposed.",
            "allowed_tools": ["version_diff_test"],
        },
        "tool_name": "version_diff_test",
        "arguments": {},
    }
    try:
        response = client.post("/v1/assets/version-diff-test", json=payload)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)

    assert response.status_code == 200, response.text
    body = response.json()
    assert "deprecated_exposed_path_detected" in body["indicators"]
    assert body["response_summary"]["finding_type_hint"] == "improper_assets_management"
