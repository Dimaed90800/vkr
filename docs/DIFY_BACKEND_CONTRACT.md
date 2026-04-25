# DIFY_BACKEND_CONTRACT.md

## Purpose

This document defines what Dify should do and what must stay in the backend.

## Principle

Dify is an orchestrator, not a database and not a tool runtime.

Dify should carry:

```text
campaign_id
active_task_id
active_command
latest_tool_result_summary
latest_evidence_id
latest_judge_verdict
compact_state_summary
```

Dify should not carry:

```text
full API graph
full request corpus
full evidence store
raw logs
large artifacts
all pending tasks
all findings
```

## Target Dify workflow

```text
Start
  ↓
Normalize Input
  ↓
Create Campaign
  ↓
Ingest OpenAPI
  ↓
Surface Acquisition
  ↓
Merge / Enrich Surface
  ↓
Build / Update Graph
  ↓
Bootstrap Corpus
  ↓
Plan Initial Tasks
  ↓
Loop
    ↓
    Get Next Task
    ↓
    Select Worker Command
    ↓
    Execute Worker Command
    ↓
    Build Evidence Pack
    ↓
    Judge Evidence
    ↓
    Apply Judge Verdict
    ↓
    Should Continue?
  ↓
Get Report Context
  ↓
Report Agent
  ↓
End
```

## Required backend endpoints

Recommended target endpoints:

```text
POST /v1/campaigns
POST /v1/ingest/openapi
POST /v1/surface/discover
POST /v1/surface/import-traffic
POST /v1/graph/build
POST /v1/corpus/bootstrap
POST /v1/tasks/plan
POST /v1/tasks/next
POST /v1/workers/command
POST /v1/tools/execute
POST /v1/evidence/build
POST /v1/judge/apply
GET  /v1/campaigns/{campaign_id}/summary
GET  /v1/report/{campaign_id}/context
```

Compatibility with current endpoints is allowed.

## Loop contract

One loop iteration should process exactly one task.

Input to `Get Next Task`:

```json
{
  "campaign_id": "cmp_..."
}
```

Output:

```json
{
  "task": {
    "task_id": "task_...",
    "class": "access_control",
    "strategy": "role_swap_object_access"
  },
  "state_summary": {
    "pending_tasks": 10,
    "confirmed_findings": 2,
    "budget_left": 500
  },
  "should_stop": false
}
```

## Worker command selector

Dify may use an LLM node to select a strategy only if the backend validates the result.

The worker command must be JSON only.

If invalid, backend should either:
- repair safely,
- fallback to deterministic command,
- or return structured `invalid_command`.

## Evidence and judge

Dify Judge should receive only compact judge-ready evidence.

If evidence has `missing_evidence`, judge should usually return `rework`, not `confirmed`.

## Stop conditions

Backend owns stop conditions:

```text
no_pending_tasks
budget_exhausted
max_iterations_reached
all_class_budgets_exhausted
time_limit_reached
fatal_tooling_error
```

Dify should display the final backend-provided stop reason.

## Reporting

Report node must call backend report context and write only confirmed findings.

Rejected/rework/inconclusive candidates can be mentioned only in a limitations section, not as vulnerabilities.
