import json
from pathlib import Path

import pytest

from backend.models.testing import ExecutionContext, TaskModel, ToolTestRequest
from backend.services.auth_preparation_service import AuthPreparationService
from backend.services.http_client import HttpExecutionResult


OPENAPI_AUTH_SPEC = json.dumps(
    {
        "openapi": "3.0.0",
        "paths": {
            "/identity/api/auth/signup": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "password", "firstName", "lastName"],
                                    "properties": {
                                        "email": {"type": "string", "format": "email"},
                                        "password": {"type": "string"},
                                        "firstName": {"type": "string"},
                                        "lastName": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
            "/identity/api/auth/login": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "required": ["email", "password"],
                                    "properties": {
                                        "email": {"type": "string", "format": "email"},
                                        "password": {"type": "string"},
                                    },
                                }
                            }
                        }
                    }
                }
            },
        },
    }
)


class _AuthBootstrapHttpClient:
    def __init__(self, *, login_mode: str = "body", fail: bool = False) -> None:
        self.login_mode = login_mode
        self.fail = fail
        self.requests: list[dict] = []

    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        self.requests.append({"method": method, "url": url, "headers": headers or {}, "json_body": json_body or {}})
        if url.endswith("/identity/api/auth/signup"):
            if self.fail or set((json_body or {}).keys()) != {"email", "password", "firstName", "lastName"}:
                return HttpExecutionResult(method=method, url=url, status_code=422, headers={}, body_text="{}", elapsed_ms=1.0)
            return HttpExecutionResult(method=method, url=url, status_code=201, headers={}, body_text=json.dumps({"ok": True}), elapsed_ms=1.0)
        if url.endswith("/identity/api/auth/login"):
            if self.fail or set((json_body or {}).keys()) != {"email", "password"}:
                return HttpExecutionResult(method=method, url=url, status_code=401, headers={}, body_text="{}", elapsed_ms=1.0)
            if self.login_mode == "body":
                return HttpExecutionResult(method=method, url=url, status_code=200, headers={}, body_text=json.dumps({"result": {"authToken": "body-token"}}), elapsed_ms=1.0)
            if self.login_mode == "header":
                return HttpExecutionResult(method=method, url=url, status_code=200, headers={"x-auth-token": "header-token"}, body_text="{}", elapsed_ms=1.0)
            if self.login_mode == "cookie":
                return HttpExecutionResult(method=method, url=url, status_code=200, headers={"set-cookie": "sessionid=cookie-token; Path=/"}, body_text="{}", elapsed_ms=1.0)
            return HttpExecutionResult(method=method, url=url, status_code=200, headers={}, body_text="{}", elapsed_ms=1.0)
        return HttpExecutionResult(method=method, url=url, status_code=404, headers={}, body_text="{}", elapsed_ms=1.0)


class _FailingAuthHttpClient:
    def __init__(self, *, register_status: int = 400, login_status: int = 401) -> None:
        self.register_status = register_status
        self.login_status = login_status

    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        if url.endswith("/identity/api/auth/signup"):
            return HttpExecutionResult(method=method, url=url, status_code=self.register_status, headers={}, body_text='{"error":"bad"}', elapsed_ms=1.0)
        if url.endswith("/identity/api/auth/login"):
            return HttpExecutionResult(method=method, url=url, status_code=self.login_status, headers={}, body_text='{"error":"unauthorized"}', elapsed_ms=1.0)
        return HttpExecutionResult(method=method, url=url, status_code=404, headers={}, body_text="{}", elapsed_ms=1.0)


class _PreviewAuthHttpClient:
    async def execute(self, *, method, url, headers=None, query_params=None, json_body=None):
        if url.endswith("/identity/api/auth/signup"):
            body = '{"error":"duplicate","access_token":"signup-secret-token","password":"plain-secret"}'
            return HttpExecutionResult(method=method, url=url, status_code=500, headers={}, body_text=body, elapsed_ms=1.0)
        if url.endswith("/identity/api/auth/login"):
            body = '{"message":"unauthorized","token":"login-secret-token","authorization":"Bearer abc.def.ghi"}'
            return HttpExecutionResult(method=method, url=url, status_code=401, headers={"set-cookie": "sessionid=secret-cookie; Path=/"}, body_text=body, elapsed_ms=1.0)
        return HttpExecutionResult(method=method, url=url, status_code=404, headers={}, body_text="{}", elapsed_ms=1.0)


class _ParsingFailureAuthService(AuthPreparationService):
    def _authenticated_identity_from_result(self, identity, result, *, fallback_cookies):
        raise ValueError("parse failed")


class _ExtractionFailureAuthService(AuthPreparationService):
    def _extract_token_with_source(self, result):
        raise RuntimeError("token extraction failed")


def _task() -> TaskModel:
    return TaskModel.model_validate(
        {
            "id": "task_auth_bootstrap_openapi",
            "class": "authorization",
            "subtype": "auth_bootstrap",
            "endpoint": "/identity/api/auth/login",
            "method": "POST",
            "auth_context": {"owner_role": "user_a", "other_role": "user_b"},
            "hypothesis": "Bootstrap auth from OpenAPI operations.",
            "allowed_tools": ["auto_provision"],
            "readiness": "needs_preparation",
        }
    )


def _request(identity_count: int = 1) -> ToolTestRequest:
    return ToolTestRequest(
        execution_context=ExecutionContext(
            target_url="http://api.test",
            run_id="run-auth-openapi",
            allowed_hosts=["api.test"],
            openapi_spec_text=OPENAPI_AUTH_SPEC,
        ),
        task=_task(),
        tool_name="auto_provision",
        arguments={"identity_count": identity_count},
    )


def _request_with_spec(spec_text: str, identity_count: int = 1) -> ToolTestRequest:
    request = _request(identity_count=identity_count)
    request.execution_context.openapi_spec_text = spec_text
    return request


def test_openapi_register_login_operations_are_schema_grounded() -> None:
    service = AuthPreparationService(http_client=_AuthBootstrapHttpClient())
    request = _request()

    register_ops = service._best_auth_operations(request=request, endpoint_type="register")
    login_ops = service._best_auth_operations(request=request, endpoint_type="login")

    assert register_ops[0]["source"] == "openapi"
    assert register_ops[0]["method"] == "POST"
    assert register_ops[0]["content_type"] == "application/json"
    assert register_ops[0]["required_body_keys"] == ["email", "password", "firstName", "lastName"]
    assert login_ops[0]["required_body_keys"] == ["email", "password"]


def test_openapi_operation_selection_filters_token_login_and_non_generic_register() -> None:
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "paths": {
                "/identity/api/auth/signup": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "password", "name", "number"],
                                        "properties": {
                                            "email": {"type": "string"},
                                            "password": {"type": "string"},
                                            "name": {"type": "string"},
                                            "number": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "/workshop/api/mechanic/signup": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "password", "name", "number", "mechanic_code"],
                                        "properties": {
                                            "email": {"type": "string"},
                                            "password": {"type": "string"},
                                            "name": {"type": "string"},
                                            "number": {"type": "string"},
                                            "mechanic_code": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "/identity/api/auth/login": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "password"],
                                        "properties": {
                                            "email": {"type": "string"},
                                            "password": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
                "/identity/api/auth/v4.0/user/login-with-token": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "token"],
                                        "properties": {
                                            "email": {"type": "string"},
                                            "token": {"type": "string"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                },
            },
        }
    )
    service = AuthPreparationService(http_client=_AuthBootstrapHttpClient())
    request = _request_with_spec(spec)

    register_ops = service._best_auth_operations(request=request, endpoint_type="register")
    login_ops = service._best_auth_operations(request=request, endpoint_type="login")

    assert [item["path"] for item in register_ops] == ["/identity/api/auth/signup"]
    assert [item["path"] for item in login_ops] == ["/identity/api/auth/login"]


def test_auth_payload_variants_include_openapi_example_candidate() -> None:
    spec = json.dumps(
        {
            "openapi": "3.0.0",
            "paths": {
                "/identity/api/auth/login": {
                    "post": {
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "required": ["email", "password"],
                                        "properties": {
                                            "email": {"type": "string", "example": "seeded-user@example.com"},
                                            "password": {"type": "string", "example": "SeededPass!123"},
                                        },
                                    }
                                }
                            }
                        }
                    }
                }
            },
        }
    )
    service = AuthPreparationService(http_client=_AuthBootstrapHttpClient())
    request = _request_with_spec(spec)
    operation = service._best_auth_operations(request=request, endpoint_type="login")[0]
    identity = service._build_identity_seed(request, 0)

    payload_variants = service._auth_payload_variants(
        request=request,
        identity=identity,
        operation=operation,
        endpoint_type="login",
    )

    assert any(item.get("email") == "seeded-user@example.com" for item in payload_variants)
    assert any("password" in item for item in payload_variants)


def test_identity_seed_uses_numeric_phone_number() -> None:
    service = AuthPreparationService(http_client=_AuthBootstrapHttpClient())
    identity = service._build_identity_seed(_request(), 0)

    assert identity["number"].isdigit()
    assert identity["number"].startswith("555")


def test_identity_seed_is_unique_per_run() -> None:
    service = AuthPreparationService(http_client=_AuthBootstrapHttpClient())
    first = service._build_identity_seed(_request(), 0)
    second_request = _request()
    second_request.execution_context.run_id = "run-auth-openapi-next"
    second = service._build_identity_seed(second_request, 0)

    assert first["email"] != second["email"]
    assert first["number"] != second["number"]


@pytest.mark.asyncio
async def test_auto_provision_extracts_nested_body_token_and_persists_identity(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    http_client = _AuthBootstrapHttpClient(login_mode="body")

    response = await AuthPreparationService(http_client=http_client).auto_provision(_request())

    assert response.raw_status == "success"
    assert response.response_summary["usable_identity_total"] == 1
    assert response.identities[0]["token"] == "body-token"
    assert response.identities[0]["auth_headers"]["Authorization"] == "Bearer body-token"
    artifact_types = {artifact.type for artifact in response.artifacts}
    assert {"provisioned_identities", "auth_profiles"}.issubset(artifact_types)
    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_register_attempt" in events
    assert "auth_provision_login_result" in events
    assert "auth_provision_token_extracted" in events
    assert "AutoPass!" not in events


@pytest.mark.asyncio
async def test_auto_provision_extracts_header_token() -> None:
    response = await AuthPreparationService(http_client=_AuthBootstrapHttpClient(login_mode="header")).auto_provision(_request())

    assert response.response_summary["usable_identity_total"] == 1
    assert response.identities[0]["token"] == "header-token"
    assert response.identities[0]["auth_headers"]["X-Auth-Token"] == "header-token"


@pytest.mark.asyncio
async def test_auto_provision_extracts_cookie_session() -> None:
    response = await AuthPreparationService(http_client=_AuthBootstrapHttpClient(login_mode="cookie")).auto_provision(_request())

    assert response.response_summary["usable_identity_total"] == 1
    assert response.identities[0]["cookies"]["sessionid"] == "cookie-token"


@pytest.mark.asyncio
async def test_auto_provision_fails_without_success_or_auth_artifact() -> None:
    failed = await AuthPreparationService(http_client=_AuthBootstrapHttpClient(fail=True)).auto_provision(_request())
    missing_token = await AuthPreparationService(http_client=_AuthBootstrapHttpClient(login_mode="none")).auto_provision(_request())

    assert failed.response_summary["usable_identity_total"] == 0
    assert "registration_failed" in failed.response_summary["failure_reasons"]
    assert "login_failed" in failed.response_summary["failure_reasons"]
    assert missing_token.response_summary["usable_identity_total"] == 0
    assert "token_missing" in missing_token.response_summary["failure_reasons"]


@pytest.mark.asyncio
async def test_register_400_still_emits_attempt_and_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))

    await AuthPreparationService(http_client=_FailingAuthHttpClient(register_status=400)).auto_provision(_request())

    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_register_attempt" in events
    assert "auth_provision_register_result" in events
    assert '"status_code": 400' in events
    assert "AutoPass!" not in events
    assert "body-token" not in events


@pytest.mark.asyncio
async def test_login_401_still_emits_attempt_and_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))

    await AuthPreparationService(http_client=_FailingAuthHttpClient(register_status=201, login_status=401)).auto_provision(_request())

    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_login_attempt" in events
    assert "auth_provision_login_result" in events
    assert '"status_code": 401' in events
    assert "unexpected_status_code" in events


@pytest.mark.asyncio
async def test_response_parsing_failure_is_logged_as_login_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))

    await _ParsingFailureAuthService(http_client=_AuthBootstrapHttpClient(login_mode="body")).auto_provision(_request())

    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_login_attempt" in events
    assert "auth_provision_login_result" in events
    assert "token_extraction_failed" in events
    assert "ValueError" in events


@pytest.mark.asyncio
async def test_token_extraction_failure_is_logged_as_login_result(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))

    await _ExtractionFailureAuthService(http_client=_AuthBootstrapHttpClient(login_mode="body")).auto_provision(_request())

    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_login_attempt" in events
    assert "auth_provision_login_result" in events
    assert "token_extraction_failed" in events
    assert "RuntimeError" in events


@pytest.mark.asyncio
async def test_openapi_url_context_is_used_and_canonical_ops_reduce_fallback_attempts(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    spec_path = tmp_path / "openapi.json"
    spec_path.write_text(OPENAPI_AUTH_SPEC, encoding="utf-8")
    request = _request()
    request.execution_context.openapi_spec_text = ""
    request.execution_context.openapi_url = str(spec_path)
    http_client = _AuthBootstrapHttpClient(login_mode="body")

    response = await AuthPreparationService(http_client=http_client).auto_provision(request)

    assert response.raw_status == "success"
    assert response.response_summary["usable_identity_total"] == 1
    urls = [entry["url"] for entry in http_client.requests]
    assert urls.count("http://api.test/identity/api/auth/signup") == 1
    assert urls.count("http://api.test/identity/api/auth/login") == 1
    assert all(not url.endswith(path) for path in ("/api/register", "/register", "/signup", "/api/login", "/login", "/signin") for url in urls)
    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_openapi_context_received" in events
    assert "auth_operation_selected" in events
    assert '"source": "openapi"' in events


@pytest.mark.asyncio
async def test_non_success_auth_events_include_safe_response_preview(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("DAST_DIAGNOSTIC_LOG_DIR", str(tmp_path / "logs"))
    request = _request()

    await AuthPreparationService(http_client=_PreviewAuthHttpClient()).auto_provision(request)

    events = (tmp_path / "logs" / "run-auth-openapi" / "events.jsonl").read_text(encoding="utf-8")
    assert "auth_provision_register_result" in events
    assert "auth_provision_login_result" in events
    assert '"response_body_preview":' in events
    assert "***REDACTED***" in events
    assert "plain-secret" not in events
    assert "login-secret-token" not in events
    assert "secret-cookie" not in events
