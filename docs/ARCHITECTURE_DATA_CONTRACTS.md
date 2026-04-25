# ARCHITECTURE_DATA_CONTRACTS.md

## Purpose

This document defines target data contracts between Dify, backend, workers, tools, judge and reporter.

## 1. Initial Dify input

```json
{
  "target_url": "http://host.docker.internal:8888",
  "toolbox_url": "http://toolbox:8000",
  "openapi_url": "http://target/openapi.json",
  "allowed_hosts": ["host.docker.internal", "localhost"],
  "profile": "safe",
  "roles_json": [
    {
      "name": "user_a",
      "auth_type": "bearer",
      "token": "..."
    },
    {
      "name": "user_b",
      "auth_type": "bearer",
      "token": "..."
    },
    {
      "name": "admin",
      "auth_type": "bearer",
      "token": "..."
    }
  ],
  "limits": {
    "max_requests": 1000,
    "max_duration_sec": 1800,
    "max_iterations": 50,
    "max_retries_per_task": 2
  }
}
```

## 2. Campaign

```json
{
  "campaign_id": "cmp_...",
  "target_url": "http://target",
  "openapi_url": "http://target/openapi.json",
  "allowed_hosts": ["target"],
  "profile": "safe",
  "status": "running",
  "created_at": "2026-04-25T00:00:00Z",
  "limits": {
    "max_requests": 1000,
    "max_duration_sec": 1800,
    "max_iterations": 50
  }
}
```

## 3. Operation node

```json
{
  "operation_id": "op_get_vehicle_by_id",
  "method": "GET",
  "path_template": "/identity/api/v2/vehicle/{vehicleId}",
  "operation_id_from_spec": "getVehicleById",
  "tags": ["vehicle"],
  "auth_required": true,
  "security": ["bearerAuth"],
  "path_params": ["vehicleId"],
  "query_params": [],
  "body_fields": [],
  "response_fields": ["id", "vin", "ownerId"],
  "risk_hints": ["object_id_in_path", "user_owned_resource"],
  "owasp_candidates": ["API1_BOLA", "API3_BOPLA"]
}
```

## 4. Request corpus item

```json
{
  "request_id": "req_...",
  "campaign_id": "cmp_...",
  "operation_id": "op_get_vehicle_by_id",
  "source": "openapi_smoke",
  "method": "GET",
  "url": "http://target/identity/api/v2/vehicle/123",
  "path_template": "/identity/api/v2/vehicle/{vehicleId}",
  "auth_profile": "user_a",
  "headers_redacted": {
    "Authorization": "<redacted>"
  },
  "body_redacted": null,
  "status_code": 200,
  "response_body_redacted": {
    "id": "123",
    "ownerId": "user_a"
  },
  "response_schema_hash": "sha256:...",
  "extracted_ids": {
    "vehicleId": ["123"],
    "ownerId": ["user_a"]
  },
  "sensitive_fields": ["ownerId"],
  "created_at": "..."
}
```

## 5. Task

```json
{
  "task_id": "task_...",
  "campaign_id": "cmp_...",
  "class": "access_control",
  "owasp_category": "API1_BOLA",
  "strategy": "role_swap_object_access",
  "operation_id": "op_get_vehicle_by_id",
  "seed_request_id": "req_...",
  "hypothesis": "Object-level authorization may be missing for vehicle access.",
  "required_evidence": [
    "baseline_owner_access",
    "attacker_access_same_object",
    "ownership_proof",
    "negative_control"
  ],
  "priority": 92,
  "status": "pending",
  "retry_count": 0,
  "allowed_tools": ["custom_request_executor"],
  "preferred_tool": "custom_request_executor",
  "fallback_tools": []
}
```

Compatibility mapping from old classes:

```text
authorization  -> access_control
injection      -> contract_fuzzing
business_logic -> stateful_flow
```

## 6. Worker command

```json
{
  "command_id": "cmd_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "worker_class": "access_control",
  "strategy": "role_swap_object_access",
  "tool_name": "custom_request_executor",
  "inputs": {
    "seed_request_id": "req_...",
    "owner_role": "user_a",
    "attacker_role": "user_b",
    "object_id": "123"
  },
  "budget": {
    "max_requests": 4,
    "timeout_sec": 30
  }
}
```

## 7. Tool result

```json
{
  "schema_version": "tool-result/v1",
  "tool_run_id": "toolrun_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "tool_name": "custom_request_executor",
  "status": "finished",
  "summary": {
    "request_count": 3,
    "success_count": 2,
    "client_error_count": 1,
    "server_error_count": 0
  },
  "requests": [
    {
      "request_id": "req_baseline",
      "role": "user_a",
      "method": "GET",
      "url": "/vehicle/123"
    },
    {
      "request_id": "req_attack",
      "role": "user_b",
      "method": "GET",
      "url": "/vehicle/123"
    }
  ],
  "responses": [
    {
      "request_id": "req_baseline",
      "status_code": 200
    },
    {
      "request_id": "req_attack",
      "status_code": 200
    }
  ],
  "observations": [
    {
      "type": "cross_role_object_access",
      "confidence": 0.8
    }
  ],
  "artifacts": [],
  "errors": []
}
```

## 8. Evidence pack

```json
{
  "schema_version": "evidence-pack/v1",
  "evidence_id": "ev_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "owasp_category": "API1_BOLA",
  "hypothesis": "Object-level authorization may be missing.",
  "baseline": {
    "role": "user_a",
    "request_id": "req_baseline",
    "status_code": 200,
    "object_id": "123"
  },
  "attack": {
    "role": "user_b",
    "request_id": "req_attack",
    "status_code": 200,
    "object_id": "123"
  },
  "controls": [
    {
      "type": "attacker_collection_check",
      "role": "user_b",
      "result": "object_not_listed"
    }
  ],
  "diff": {
    "same_object": true,
    "same_sensitive_fields": ["id", "ownerId"]
  },
  "derived_signals": [
    "cross_role_same_object_access",
    "sensitive_object_data_exposed"
  ],
  "missing_evidence": [],
  "replay": {
    "steps": [
      "GET /vehicle/123 as user_a",
      "GET /vehicle/123 as user_b"
    ]
  },
  "artifact_refs": []
}
```

## 9. Judge verdict

```json
{
  "schema_version": "judge-verdict/v1",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "evidence_id": "ev_...",
  "verdict": "confirmed",
  "confidence": 0.92,
  "severity": "high",
  "reason": "The attacker role accessed the same user-owned object and received sensitive fields.",
  "missing_evidence": [],
  "rework_actions": [],
  "finding_candidate": {
    "title": "Broken Object Level Authorization on GET /vehicle/{vehicleId}",
    "owasp_category": "API1_BOLA",
    "endpoint": "/vehicle/{vehicleId}",
    "method": "GET",
    "evidence_summary": "...",
    "reproduction_steps": [
      "Authenticate as user_a and obtain vehicle id 123.",
      "Authenticate as user_b.",
      "Request GET /vehicle/123 with user_b token.",
      "Observe 200 OK and same vehicle data."
    ],
    "remediation": "Enforce object ownership checks server-side."
  }
}
```

## 10. Confirmed finding

```json
{
  "finding_id": "finding_...",
  "campaign_id": "cmp_...",
  "title": "Broken Object Level Authorization on GET /vehicle/{vehicleId}",
  "owasp_category": "API1_BOLA",
  "endpoint": "/vehicle/{vehicleId}",
  "method": "GET",
  "severity": "high",
  "confidence": 0.92,
  "evidence_id": "ev_...",
  "baseline_request_id": "req_baseline",
  "attack_request_id": "req_attack",
  "reproduction_steps": [],
  "remediation": "...",
  "created_at": "..."
}
```

## 11. Report context

```json
{
  "campaign_id": "cmp_...",
  "target": {
    "url": "http://target",
    "openapi_url": "http://target/openapi.json"
  },
  "coverage": {
    "operations_total": 50,
    "operations_tested": 31,
    "requests_executed": 420
  },
  "confirmed_findings": [],
  "tool_runs": [],
  "limitations": []
}
```
