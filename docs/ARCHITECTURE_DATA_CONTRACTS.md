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

---

# Additional contracts: ToolRun, Observation, VerificationPlan

## ToolRun

`ToolRun` is the runtime record for a tool execution. Short tools can finish synchronously. Long-running tools must return `tool_run_id` first and finish later.

Long-running tools include:

```text
RESTler
Schemathesis with many examples
CATS
OWASP ZAP active scan
nuclei with many templates
ffuf / Kiterunner with large wordlists
Playwright crawl
```

Example:

```json
{
  "schema_version": "tool-run/v1",
  "tool_run_id": "toolrun_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "command_id": "cmd_...",
  "tool_name": "schemathesis",
  "execution_mode": "async",
  "status": "running",
  "started_at": "2026-04-25T00:00:00Z",
  "finished_at": null,
  "progress": {
    "requests_sent": 42,
    "max_requests": 100,
    "elapsed_sec": 27
  },
  "result_ready": false,
  "artifact_refs": []
}
```

Allowed statuses:

```text
accepted
queued
running
finished
failed
timeout
cancelled
skipped
```

The Judge must not be called while `ToolRun.status` is `accepted`, `queued`, or `running`.

---

## Observation

`Observation` is a normalized signal produced from tool output. It is not a confirmed vulnerability.

Examples of observations:

```text
unexpected_500
schema_mismatch
auth_anomaly
cross_role_access_signal
zap_alert
nuclei_match
discovered_endpoint
hidden_parameter
sensitive_field_seen
state_changed_after_invalid_payload
```

Example:

```json
{
  "schema_version": "observation/v1",
  "observation_id": "obs_...",
  "campaign_id": "cmp_...",
  "tool_run_id": "toolrun_...",
  "task_id": "task_...",
  "type": "unexpected_500",
  "operation_id": "op_create_order",
  "request_id": "req_...",
  "confidence": 0.7,
  "security_relevance": "unknown",
  "judge_worthy": false,
  "recommended_next_action": "replay_minimized_payload",
  "artifact_refs": [
    "artifact://toolrun_.../case_001.json"
  ]
}
```

Rules:

```text
ordinary 400/404/422 -> store but do not judge;
single 500 -> observation, usually replay/rework first;
auth bypass signal -> may be judge-worthy;
cross-role access signal -> usually requires ownership proof;
ZAP/nuclei alert -> requires replay/impact check before confirmation.
```

---

## VerificationPlan

`VerificationPlan` describes how an agent plans to turn a signal into proof.

The agent does not confirm the vulnerability. It creates a controlled plan for backend execution.

Example:

```json
{
  "schema_version": "verification-plan/v1",
  "campaign_id": "cmp_...",
  "parent_observation_id": "obs_...",
  "parent_task_id": "task_...",
  "goal": "prove_ownership",
  "worker_class": "access_control",
  "strategy": "prove_ownership",
  "required_evidence": [
    "owner_collection_contains_object",
    "attacker_collection_does_not_contain_object"
  ],
  "commands": [
    {
      "tool_name": "custom_request_executor",
      "strategy": "collection_check",
      "inputs": {
        "owner_role": "user_a",
        "attacker_role": "user_b",
        "object_id": "123"
      },
      "budget": {
        "max_requests": 3,
        "timeout_sec": 30
      }
    }
  ]
}
```

Typical verification plans:

```text
prove_ownership
replay_minimized_payload
cors_replay_validation
mass_assignment_followup
admin_endpoint_low_privilege_replay
jwt_tamper_replay
ssrf_callback_confirmation
undocumented_endpoint_auth_check
```

---

## Tool execution response

`POST /v1/tools/execute` may return either a finished `ToolResult` or an accepted `ToolRun`.

Synchronous response:

```json
{
  "status": "finished",
  "execution_mode": "sync",
  "tool_result": {
    "schema_version": "tool-result/v1",
    "tool_run_id": "toolrun_...",
    "status": "finished"
  }
}
```

Asynchronous response:

```json
{
  "status": "accepted",
  "execution_mode": "async",
  "tool_run_id": "toolrun_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "tool_name": "schemathesis",
  "poll_after_sec": 5
}
```

The workflow must collect the final result later:

```http
GET /v1/tools/runs/{tool_run_id}
POST /v1/tools/runs/{tool_run_id}/collect
```

---

## Updated processing rule

```text
ToolResult does not automatically go to Judge.

ToolResult
  -> raw artifact storage
  -> request corpus update
  -> API/dependency graph update
  -> Observation normalization
  -> VerificationPlan if more proof is needed
  -> EvidencePack only for judge-worthy candidates
  -> Judge
```
