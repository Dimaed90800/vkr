# Main Workflow Blueprint

This is the current recommended Dify implementation for the project.

## Workflow Name

`wf-agentic-main`

## Goal

One orchestration workflow should manage:

- session start
- auth preparation
- probe seeding
- BOLA worker execution
- worker-result ingestion
- LLM judge decision
- final report

## Recommended Vertical Slice

The first fully working Dify slice is now:

1. `POST /agentic/start`
2. `POST /agentic/session/{session_id}/prepare-auth`
3. `POST /agentic/session/{session_id}/prepare-probe-seeds`
4. `GET /agentic/session/{session_id}/worker-tasks/bola`
5. `POST /agentic/tools/execute`
6. `POST /agentic/session/{session_id}/worker-result`
7. `GET /agentic/session/{session_id}/judge-package/{finding_id}`
8. `LLM Judge`
9. `POST /agentic/session/{session_id}/judge-verdict`
10. `GET /agentic/session/{session_id}/report-package`
11. `LLM Report`

This path is already backed by working backend endpoints.

## Node-By-Node Skeleton

### 1. `Start`

Inputs:

- `target_name`
- `target_url`
- `user_prompt`
- `allowed_test_classes`
- `max_rounds`
- `budget_requests_total`
- `budget_time_total`

### 2. `Code` — Normalize Campaign Input

Responsibilities:

- clean empty fields
- set defaults
- normalize classes

### 3. `HTTP Request` — Start Session

Call:

- `POST /agentic/start`

Expected result:

- session id
- next endpoints
- prompt focus

### 4. `HTTP Request` — Prepare Auth

Call:

- `POST /agentic/session/{session_id}/prepare-auth`

Purpose:

- create roles
- register roles
- login roles
- obtain two authenticated tokens

### 5. `HTTP Request` — Prepare Probe Seeds

Call:

- `POST /agentic/session/{session_id}/prepare-probe-seeds`

Purpose:

- seed API inventory
- execute bounded authenticated probes
- create object-bearing observations for BOLA

### 6. `HTTP Request` — Get Session Context

Call:

- `GET /agentic/session/{session_id}/context`

Use:

- check role state
- inspect recent observations
- expose available tools to the orchestrator

### 7. `HTTP Request` — Get BOLA Worker Tasks

Call:

- `GET /agentic/session/{session_id}/worker-tasks/bola`

Expected result:

- structured BOLA worker tasks
- allowed tools
- execution limits

### 8. `Code` — Pick First BOLA Task

Responsibilities:

- select the highest-priority BOLA task
- extract `task_id`
- extract `endpoint`
- extract `owner_role`
- extract `other_role`

### 9. `HTTP Request` — Execute BOLA Tool

Call:

- `POST /agentic/tools/execute`

Body:

```json
{
  "tool_name": "probe_same_object_across_roles",
  "arguments": {
    "session_id": 159,
    "owner_role": "user_a",
    "other_role": "user_b",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/{vehicle_id}/location",
    "method": "GET"
  }
}
```

### 10. `HTTP Request` — Save Worker Result

Call:

- `POST /agentic/session/{session_id}/worker-result`

Purpose:

- create or update a candidate finding
- normalize evidence summary

### 11. `HTTP Request` — Get Judge Package

Call:

- `GET /agentic/session/{session_id}/judge-package/{finding_id}`

Purpose:

- provide the LLM judge with structured evidence only

### 12. `LLM` — Judge Agent

Input:

- judge package JSON

Output:

- strict verdict JSON only

### 13. `HTTP Request` — Save Judge Verdict

Call:

- `POST /agentic/session/{session_id}/judge-verdict`

Purpose:

- persist `confirmed`, `candidate`, or `rejected`

### 14. `HTTP Request` — Get Judge State

Call:

- `GET /agentic/session/{session_id}/judge-state`

Purpose:

- show confirmed findings
- show candidate findings

### 15. `HTTP Request` — Get Report Package

Call:

- `GET /agentic/session/{session_id}/report-package`

### 16. `LLM` — Final Report

Use:

- confirmed findings only as primary findings

### 17. `Output`

Return:

- session id
- confirmed findings total
- final Markdown report

## Loop Guidance

After the first vertical slice works, extend it with a loop over:

- remaining BOLA tasks
- remaining BOPLA tasks
- retry on `needs_retry`
- stop on `confirmed`, `rejected`, or exhausted budget

The initial loop does not need to cover all workers. Start with:

- `prepare-auth`
- `prepare-probe-seeds`
- one BOLA worker task
- one judge pass
- then add one BOPLA worker task family using `infer_bopla`
