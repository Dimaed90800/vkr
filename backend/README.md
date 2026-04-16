# Multi-Agent DAST Toolbox MVP

Minimal FastAPI backend for a Dify multi-agent REST API DAST workflow.

## Requirements

- Python 3.11+
- pip

## Install

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Run

```bash
cd backend
source .venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

## Health check

```bash
curl http://localhost:8000/health
```

## Example: parse OpenAPI from URL

```bash
curl -X POST http://localhost:8000/v1/recon/openapi \
  -H 'Content-Type: application/json' \
  -d '{
    "target_url": "http://host.docker.internal:8888",
    "openapi_url": "http://host.docker.internal:8888/openapi.json"
  }'
```

## Example: parse OpenAPI from spec text

```bash
curl -X POST http://localhost:8000/v1/recon/openapi \
  -H 'Content-Type: application/json' \
  -d '{
    "target_url": "http://host.docker.internal:8888",
    "openapi_spec_text": "{\"openapi\":\"3.0.0\",\"paths\":{\"/items/{id}\":{\"get\":{\"parameters\":[{\"name\":\"id\",\"in\":\"path\",\"required\":true,\"schema\":{\"type\":\"string\"}}]}}}}"
  }'
```

## Example: authorization test

```bash
curl -X POST http://localhost:8000/v1/auth/test-access \
  -H 'Content-Type: application/json' \
  -d '{
    "execution_context": {
      "target_url": "http://host.docker.internal:8888",
      "allowed_hosts": ["host.docker.internal:8888"],
      "max_requests": 100,
      "max_duration_sec": 900,
      "max_retries_per_task": 1
    },
    "task": {
      "id": "task_authz_bola_001",
      "class": "authorization",
      "subtype": "bola",
      "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
      "method": "GET",
      "params": {
        "path_params": ["id"],
        "query_params": [],
        "body_fields": [],
        "object_id_candidates": ["123"]
      },
      "auth_context": {
        "owner_role": "user_a",
        "other_role": "user_b",
        "token_strategy": "cross_role_replay"
      },
      "hypothesis": "Cross-role object access may be possible.",
      "priority": 90,
      "retry_count": 0,
      "rework_hint": null,
      "status": "pending",
      "allowed_tools": ["auth_test_access"]
    },
    "tool_name": "auth_test_access",
    "arguments": {
      "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
      "method": "GET",
      "owner_role": "user_a",
      "other_role": "user_b",
      "object_id": "123"
    }
  }'
```

## Example: injection test

```bash
curl -X POST http://localhost:8000/v1/injection/test \
  -H 'Content-Type: application/json' \
  -d '{
    "execution_context": {
      "target_url": "http://host.docker.internal:8888",
      "allowed_hosts": ["host.docker.internal:8888"]
    },
    "task": {
      "id": "task_injection_001",
      "class": "injection",
      "subtype": "sqli",
      "endpoint": "http://host.docker.internal:8888/api/search",
      "method": "GET",
      "params": {
        "query_params": ["q"]
      },
      "auth_context": {},
      "hypothesis": "Search input may be injectable.",
      "priority": 60,
      "retry_count": 0,
      "rework_hint": null,
      "status": "pending",
      "allowed_tools": ["injection_test"]
    },
    "tool_name": "injection_test",
    "arguments": {
      "endpoint": "http://host.docker.internal:8888/api/search?q=test",
      "method": "GET",
      "payload": "' OR '1'='1"
    }
  }'
```

## Example: store evidence

```bash
curl -X POST http://localhost:8000/v1/evidence/store \
  -H 'Content-Type: application/json' \
  -d '{
    "session_id": 1,
    "evidence": {
      "task_id": "task_authz_bola_001",
      "worker_type": "authorization",
      "request_summary": {"method": "GET", "endpoint": "http://host.docker.internal:8888/..."},
      "response_summary": {"status_codes": [200, 200]},
      "raw_status": "ok",
      "indicators": ["possible_bola"],
      "reasoning": "Both roles got the same object.",
      "artifacts": [],
      "timestamp": "2026-04-14T19:00:00Z"
    }
  }'
```

## Example: store finding

```bash
curl -X POST http://localhost:8000/v1/findings/store \
  -H 'Content-Type: application/json' \
  -d '{
    "session_id": 1,
    "finding": {
      "title": "Broken Object Level Authorization",
      "vuln_type": "BOLA",
      "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/123/location",
      "method": "GET",
      "severity": "high",
      "confidence": 0.93,
      "evidence_summary": "Two roles accessed the same object.",
      "reproduction_steps": ["Authenticate as user_a", "Authenticate as user_b", "Repeat request"],
      "remediation": "Enforce object ownership checks."
    }
  }'
```
