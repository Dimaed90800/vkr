# Minimal Toolbox API Contract

This document defines the MVP backend/toolbox contract for the Dify multi-agent DAST workflow.

## Common rules

- All requests and responses are JSON.
- Every execution request must stay inside `allowed_hosts`.
- The backend is responsible for request-budget accounting, scope checks, header redaction, and audit logging.
- Secrets and raw bearer tokens must not be echoed back in responses.
- Artifact references may be returned instead of full raw payloads for large responses.

---

## POST /v1/recon/openapi

Purpose:
- Parse OpenAPI input and extract normalized API surface for the Router.

Request JSON:

```json
{
  "target_url": "http://host.docker.internal:8888",
  "openapi_url": "http://host.docker.internal:8888/openapi.json",
  "openapi_spec_text": null
}
```

Response JSON:

```json
{
  "target_url": "http://host.docker.internal:8888",
  "surface_summary": "OpenAPI parsed successfully.",
  "endpoints": [
    {
      "path": "/identity/api/v2/vehicle/{id}/location",
      "methods": ["GET"],
      "auth_required": true,
      "path_params": ["id"],
      "query_params": [],
      "body_fields": []
    }
  ],
  "auth_schemes": ["bearerAuth"],
  "schemas": ["VehicleLocation"]
}
```

Logic:
- Accept either `openapi_url` or `openapi_spec_text`.
- Resolve and parse OpenAPI.
- Normalize endpoints, methods, auth hints, and parameter inventory.

Safety restrictions:
- Reject non-HTTP/HTTPS URLs.
- Reject hosts outside the allowed toolbox configuration.
- Apply size limits to `openapi_spec_text`.
- Do not fetch arbitrary URLs outside target scope.

---

## POST /v1/http/execute

Purpose:
- Execute one safe HTTP request with scope validation and role-aware auth context.

Request JSON:

```json
{
  "execution_context": {
    "session_id": 189,
    "target_url": "http://host.docker.internal:8888",
    "allowed_hosts": ["host.docker.internal:8888"],
    "request_budget_remaining": 240
  },
  "request": {
    "method": "GET",
    "url": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
    "headers": {
      "Accept": "application/json"
    },
    "query": {},
    "json_body": null
  },
  "auth_context": {
    "role_name": "user_a",
    "token_ref": "role:user_a"
  }
}
```

Response JSON:

```json
{
  "request_summary": {
    "method": "GET",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
    "headers_redacted": {
      "Accept": "application/json",
      "Authorization": "Bearer <redacted>"
    }
  },
  "response_summary": {
    "status_code": 200,
    "headers": {
      "content-type": "application/json"
    },
    "body_preview": "{\"carId\":\"123\"}",
    "elapsed_ms": 148
  },
  "raw_status": "success",
  "artifacts": [
    {
      "type": "http_exchange_ref",
      "value": "artifact:http_exchange:abc123"
    }
  ]
}
```

Logic:
- Validate method, URL, and host.
- Resolve token from `token_ref`.
- Execute request with timeout and logging.
- Return redacted request summary and bounded response preview.

Safety restrictions:
- Reject requests outside `allowed_hosts`.
- Reject unsupported methods if disabled by policy.
- Enforce timeout and response-size caps.
- Redact auth headers and secrets from logs and output.

---

## POST /v1/auth/test-access

Purpose:
- Specialized authorization helper for cross-role and token-swap access checks.

Request JSON:

```json
{
  "execution_context": {
    "session_id": 189,
    "target_url": "http://host.docker.internal:8888",
    "allowed_hosts": ["host.docker.internal:8888"]
  },
  "task": {
    "id": "task_authz_bola_001",
    "class": "authorization",
    "subtype": "bola",
    "endpoint": "/identity/api/v2/vehicle/{id}/location",
    "method": "GET"
  },
  "tool_name": "auth_test_access",
  "arguments": {
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
    "method": "GET",
    "owner_role": "user_a",
    "other_role": "user_b",
    "object_id": "123"
  }
}
```

Response JSON:

```json
{
  "request_summary": {
    "method": "GET",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location"
  },
  "response_summary": {
    "status_codes": [200, 200],
    "body_similarity": "high",
    "owner_response_preview": "{\"carId\":\"123\"}",
    "other_response_preview": "{\"carId\":\"123\"}"
  },
  "raw_status": "success",
  "indicators": [
    "cross_role_access",
    "same_object",
    "same_json_response"
  ],
  "artifacts": [
    {
      "type": "cross_role_check_ref",
      "value": "artifact:auth_check:def456"
    }
  ]
}
```

Logic:
- Execute the same request under two auth contexts.
- Compare status codes and bounded response bodies.
- Return normalized access indicators for the worker and Judge.

Safety restrictions:
- Only use roles/tokens already provisioned in the session.
- Stay inside target scope.
- Do not attempt destructive state changes unless explicitly allowed by policy.

---

## POST /v1/evidence/store

Purpose:
- Persist one evidence record produced during the workflow.

Request JSON:

```json
{
  "session_id": 189,
  "evidence": {
    "task_id": "task_authz_bola_001",
    "worker_type": "authorization",
    "request_summary": {
      "method": "GET",
      "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location"
    },
    "response_summary": {
      "status_codes": [200, 200]
    },
    "raw_status": "success",
    "indicators": ["cross_role_access"],
    "reasoning": "Both roles received equivalent successful responses.",
    "artifacts": [],
    "timestamp": "2026-04-14T19:00:00Z"
  }
}
```

Response JSON:

```json
{
  "evidence_id": "ev_001",
  "status": "stored"
}
```

Logic:
- Validate evidence schema.
- Persist evidence under the active `TestSession`.
- Return stable reference id.

Safety restrictions:
- Reject malformed evidence.
- Redact sensitive headers or tokens if they slipped into the payload.
- Apply size limits for artifact lists and previews.

---

## POST /v1/findings/store

Purpose:
- Persist one confirmed finding after Judge confirmation.

Request JSON:

```json
{
  "session_id": 189,
  "finding": {
    "id": "finding_authz_bola_001",
    "title": "Broken Object Level Authorization",
    "vuln_type": "BOLA",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
    "method": "GET",
    "severity": "high",
    "confidence": 0.93,
    "evidence_summary": "Two different roles accessed the same object and received equivalent data.",
    "reproduction_steps": [
      "Authenticate as user_a",
      "Request the endpoint",
      "Authenticate as user_b",
      "Repeat the same request"
    ],
    "remediation": "Enforce object ownership checks before returning resource data."
  }
}
```

Response JSON:

```json
{
  "finding_id": "finding_authz_bola_001",
  "status": "stored"
}
```

Logic:
- Validate finding schema.
- Persist confirmed finding and link to the active session.
- Optionally deduplicate against prior confirmed findings in the same session.

Safety restrictions:
- Accept only Judge-confirmed findings.
- Reject invalid severity/confidence values.
- Keep canonical audit trail of when and how the finding was stored.
