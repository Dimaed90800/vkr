# Multi-Agent DAST Blueprint For Dify

This document is the practical starting point for implementing the Dify workflow
for the multi-agent REST API DAST system.

## Scope

Target architecture:

`Router -> Task Queue -> Specialized Workers -> Evidence Collector -> Judge -> Rework Loop -> Confirmed Findings -> Reporter`

The implementation target is:

- Dify for orchestration and LLM reasoning
- backend toolbox API for execution, persistence, and safety controls

## Workflow shape

```text
Start
-> Normalize Input
-> Parse OpenAPI
-> Router Agent
-> Parse Router Tasks
-> Initialize Queue State
-> Main Task Loop
   -> Pick Active Task
   -> Budget Check
   -> Dispatch by Task Type
   -> Worker Agent
   -> Parse Worker Tool Command
   -> Execute Tool
   -> Build Evidence
   -> Persist Evidence
   -> Judge Agent
   -> Parse Judge Verdict
   -> Apply Verdict / Requeue
-> Aggregate Findings
-> Reporter Agent
-> Answer
```

## Mutable workflow state

Store workflow state as JSON strings plus a few scalar counters.

Core variables:

- `target_url`
- `openapi_url`
- `openapi_spec`
- `roles_json`
- `allowed_hosts_json`
- `selected_classes_json`
- `max_requests`
- `max_duration_sec`
- `max_retries_per_task`
- `pending_tasks_json`
- `active_task_json`
- `completed_tasks_json`
- `evidence_records_json`
- `confirmed_findings_json`
- `rejected_findings_json`
- `task_attempts_map_json`
- `total_requests_used`
- `start_timestamp`
- `stop_reason`
- `final_report_markdown`

## Task schema

```json
{
  "id": "task_authz_bola_001",
  "class": "authorization",
  "subtype": "bola",
  "endpoint": "/identity/api/v2/vehicle/{id}/location",
  "method": "GET",
  "params": {
    "object_id_candidates": [
      "4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5"
    ]
  },
  "auth_context": {
    "owner_role": "user_a",
    "other_role": "user_b"
  },
  "hypothesis": "Resource may be accessible cross-role for the same object id.",
  "priority": 90,
  "retry_count": 0,
  "rework_hint": null,
  "status": "pending",
  "allowed_tools": [
    "probe_same_object_across_roles",
    "compare_observations",
    "infer_bola"
  ]
}
```

## Evidence schema

```json
{
  "task_id": "task_authz_bola_001",
  "worker_type": "authorization",
  "request_summary": {
    "method": "GET",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location"
  },
  "response_summary": {
    "status_codes": [200, 200],
    "body_similarity": "high"
  },
  "raw_status": "success",
  "indicators": [
    "cross_role_access",
    "same_object",
    "same_json_response"
  ],
  "reasoning": "Both roles received materially identical HTTP 200 responses for the same object.",
  "artifacts": [
    {
      "type": "tool_run_ref",
      "value": "backend:tool_run:991"
    }
  ],
  "timestamp": "2026-04-14T19:00:00Z"
}
```

## Judge verdict schema

```json
{
  "task_id": "task_authz_bola_001",
  "verdict": "rework_needed",
  "confidence": 0.78,
  "reason": "Evidence is promising but ownership needs stronger confirmation.",
  "rework_hint": "Repeat using a second object id known to belong to user_a.",
  "severity": "high",
  "finding_candidate": {
    "title": "Broken Object Level Authorization",
    "vuln_type": "BOLA",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location"
  }
}
```

## Finding schema

```json
{
  "id": "finding_authz_bola_001",
  "title": "Broken Object Level Authorization",
  "vuln_type": "BOLA",
  "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/4bae9968-ec7f-4de3-a3a0-ba1b2ab5e5e5/location",
  "severity": "high",
  "evidence_summary": "Two different roles accessed the same object and received equivalent data.",
  "reproduction_steps": [
    "Authenticate as user_a",
    "Send GET request to the endpoint",
    "Authenticate as user_b",
    "Repeat the same request",
    "Compare both responses"
  ],
  "remediation": "Enforce object ownership checks before returning object data.",
  "confidence": 0.93
}
```

## System prompts

### Router Agent

```text
You are the Router Agent of a REST API DAST system.

Use the OpenAPI surface, authorization context, and testing constraints to create small, scoped tasks for specialized workers:
- injection
- authorization
- business_logic

Do not validate vulnerabilities.
Do not create vague tasks.
Return strict JSON only.

Output:
{
  "router_summary": "short summary",
  "tasks": []
}
```

### Injection Worker

```text
You are the Injection Worker.

You only handle:
- SQL injection
- XSS
- command injection
- injection-like payload abuse

Use only tools listed in allowed_tools.
Choose one next tool call that best advances the task.
Do not confirm vulnerabilities.
Return strict JSON only.

Output:
{
  "mode": "tool_command",
  "tool_name": "allowed_tool_name",
  "arguments": {}
}
```

### Authorization Worker

```text
You are the Authorization Worker.

You only handle:
- BOLA / IDOR
- broken access control
- token swap
- role confusion

Use only tools listed in allowed_tools.
Choose one next tool call that best advances the task.
Prefer reproducible cross-role checks.
Do not confirm vulnerabilities.
Return strict JSON only.

Output:
{
  "mode": "tool_command",
  "tool_name": "allowed_tool_name",
  "arguments": {}
}
```

### Business Logic Worker

```text
You are the Business Logic Worker.

You only handle:
- race conditions
- workflow abuse
- invalid state transitions
- business rule inconsistencies

Use only tools listed in allowed_tools.
Choose one next tool call that best advances the task.
Do not confirm vulnerabilities.
Return strict JSON only.

Output:
{
  "mode": "tool_command",
  "tool_name": "allowed_tool_name",
  "arguments": {}
}
```

### Judge Agent

```text
You are the Judge Agent.

Evaluate only the provided evidence.
Do not trust worker claims without supporting evidence.

Return one verdict:
- confirmed
- rejected
- rework_needed

If rework is needed, provide a precise, actionable rework hint.

Return strict JSON only.

Output:
{
  "task_id": "task_id",
  "verdict": "confirmed",
  "confidence": 0.0,
  "reason": "short reason",
  "rework_hint": null,
  "severity": "medium",
  "finding_candidate": null
}
```

### Reporter Agent

```text
You are the Reporter Agent.

Use only confirmed findings.
Do not validate findings.
Write a concise professional security report in Russian.
Include:
- vulnerability name
- affected endpoint
- severity
- reproduction steps
- evidence summary
- remediation

Return Markdown only.
```

## Backend/toolbox split

### Keep in backend

- OpenAPI parsing
- endpoint extraction
- HTTP execution
- allowed host validation
- request budget accounting
- auth/token switching
- object ID memory
- response diffing
- race helper
- evidence persistence
- findings persistence
- artifact storage
- report export

### Keep in Dify

- router reasoning
- worker reasoning
- judge reasoning
- reporter generation
- loop orchestration
- task dispatch
- requeue logic

## Rework loop

Pseudo-logic:

```text
if verdict == confirmed:
    append finding to confirmed_findings
    append task_id to completed_tasks
    remove active_task from pending_tasks

elif verdict == rejected:
    append task_id to rejected_findings
    append task_id to completed_tasks
    remove active_task from pending_tasks

elif verdict == rework_needed:
    attempts = task_attempts_map[task_id] + 1

    if attempts > max_retries_per_task:
        append task_id to rejected_findings
        append task_id to completed_tasks
        remove active_task from pending_tasks
    else:
        updated_task = active_task
        updated_task.retry_count = attempts
        updated_task.rework_hint = judge_verdict.rework_hint
        updated_task.status = "pending"
        pending_tasks = pending_tasks_remaining + [updated_task]
```

## Practical Dify limitations

### Limitation
No real task broker.

### Workaround
Model queue as `pending_tasks_json` and mutate it through `Code` nodes.

### Limitation
Mutable arrays are awkward.

### Workaround
Store arrays as JSON strings and update only in a small number of `Code` nodes.

### Limitation
Long heavy scans can block the workflow.

### Workaround
Use bounded scan profiles in the main workflow and move deep scans to optional tasks.

### Limitation
LLM may return empty or invalid JSON.

### Workaround
Always place a strict parser and guardrail node between `LLM` and `Execute Tool`.

## Pseudo-Dify YAML skeleton

```yaml
app:
  name: wf-multiagent-dast
  mode: workflow

inputs:
  - target_url
  - openapi_url
  - openapi_spec_text
  - roles_json
  - constraints_json
  - user_prompt

nodes:
  - id: normalize_input
    type: code

  - id: parse_openapi
    type: http

  - id: router_agent
    type: llm

  - id: parse_router_tasks
    type: code

  - id: init_queue_state
    type: code

  - id: main_loop
    type: loop
    break_condition: should_stop == true

loop_body:
  - id: pick_active_task
    type: code

  - id: task_type_branch
    type: if_else

  - id: injection_worker
    type: llm

  - id: authorization_worker
    type: llm

  - id: business_logic_worker
    type: llm

  - id: parse_worker_command
    type: code

  - id: execute_tool
    type: http

  - id: build_evidence
    type: code

  - id: persist_evidence
    type: http

  - id: judge_agent
    type: llm

  - id: parse_judge_verdict
    type: code

  - id: apply_verdict
    type: code

after_loop:
  - id: aggregate_findings
    type: code

  - id: reporter_agent
    type: llm

  - id: final_answer
    type: answer
```

## MVP build order

### Iteration 1

- Router
- Authorization Worker
- Execute Tool
- Judge
- Reporter
- no full rework queue yet

### Iteration 2

- task queue state
- retry_count
- Judge-driven rework
- evidence persistence

### Iteration 3

- Injection Worker
- Business Logic Worker
- richer toolbox
- confirmed findings store
- full report export
