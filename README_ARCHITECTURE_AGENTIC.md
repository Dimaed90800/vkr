# Agentic Architecture

## Purpose

This document fixes the target architecture for the diploma project:

`реализация адаптивной системы для поиска уязвимостей в REST API с помощью обучаемых атакующих агентов`

The implementation goal is an adaptive multi-agent REST API pentest platform where:

- an orchestrator controls the attack flow
- specialized worker agents use a constrained class of tools
- the backend acts as an execution environment and evidence store
- a judge confirms vulnerabilities only from evidence
- a report agent generates the final report from confirmed findings

## Core Principles

1. The backend is not the only "brain".
2. LLM agents may control the sequence of actions.
3. Tool access must be strict and allow-listed.
4. The judge must evaluate artifacts, not free-form reasoning.
5. The cycle must be finite and budget-limited.
6. The existing BOLA pipeline and experiment/reporting layers must remain usable.

## Target Vulnerability Classes

### MVP Scope

- `BOLA`
- `BOPLA`
- `Broken Authentication`
- `Injection`
- `SSRF`
- `Unsafe Consumption of APIs`

### Stage 2 Scope

- `XSS`
- `BFLA`
- `Path Traversal`
- `Mass Assignment`

Notes:

- `XSS` is treated as an extension class because it is often downstream from API data being rendered by a client.
- The primary API-centric classes remain BOLA, BOPLA, auth, SSRF, injection, and unsafe API consumption.

## High-Level Flow

```text
User Prompt
-> Entry Agent
-> Orchestrator Agent
-> Worker Agent
-> Tool Command
-> Backend Tool Executor
-> Tool Result
-> Orchestrator Summary
-> Judge
-> Retry / Next Agent / Stop
-> Report Agent
```

## Main Roles

### 1. Entry Agent

Responsibilities:

- accept user prompt
- normalize target and limits
- create the test session
- start orchestration

### 2. Orchestrator Agent

Responsibilities:

- choose which worker should act next
- maintain short attack-state summaries
- select the next tool-backed action
- decide whether to continue, retry, switch worker, or stop

The orchestrator does not confirm vulnerabilities.

### 3. Worker Agents

Each worker is specialized and limited to one class of tools or one narrow action family.

Current target worker families:

- `auth_worker`
- `replay_agent`
- `comparison_agent`
- `zap_agent`
- `schemathesis_agent`
- `ffuf_agent`
- `injection_agent`
- `ssrf_agent`

### 4. Judge Agent

Responsibilities:

- evaluate evidence only
- decide `confirmed`, `needs_retry`, `rejected`, or `progress`
- provide the next action recommendation

The judge must not trust agent claims without stored artifacts.

### 5. Report Agent

Responsibilities:

- generate a final Markdown/JSON report
- use confirmed findings as primary findings
- place unconfirmed issues into an additional observations section

## Tool Model

The system uses two types of tools.

### 1. Scanner Tools

External tools used for discovery and broad signals:

- `OWASP ZAP`
- `Schemathesis`
- `ffuf`
- optionally `Nmap` later

### 2. Verification Tools

Backend-native tools used for exploit confirmation:

- `replay_request`
- `probe_same_object_across_roles`
- `compare_observations`
- `infer_bola`
- future `field_diff`
- future `auth_boundary_probe`
- future `ssrf_probe`
- future `injection_probe`

## Why This Hybrid Model

Large scanners are useful for:

- discovery
- API surface mapping
- passive and active findings
- anomaly detection

But scanners alone are not sufficient for strong confirmation of:

- BOLA
- BOPLA
- object-level replay attacks
- role-aware exploit validation

Therefore the architecture combines:

- scanner agents for discovery and signal generation
- verification agents for exploit confirmation

## Backend Role

The backend is the execution environment, not the only decision-maker.

Backend responsibilities:

- create and manage `TestSession`
- store observations, findings, decisions, and strategy state
- validate tool commands
- execute allow-listed tools
- normalize results into structured outputs
- expose orchestrator-friendly APIs

The backend must preserve:

- existing BOLA functionality
- experiment endpoints
- metrics and reporting
- fallback and recovery behavior

## Main Entities

- `TestSession`
- `Observation`
- `Hypothesis`
- `Finding`
- `JudgeDecision`
- `RoleCredential`

Planned logical entities at API/service level:

- `WorkerTask`
- `ToolCommand`
- `ToolResult`
- `EvidencePackage`

## Main Contracts

### WorkerTask

```json
{
  "task_id": "bola_probe::inventory::endpoint::user_a::user_b",
  "session_id": 159,
  "worker_type": "replay_agent",
  "vulnerability_class": "BOLA",
  "goal": "Verify cross-role access to the same object",
  "inputs": {
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/abc/location",
    "method": "GET",
    "owner_role": "user_a",
    "other_role": "user_b"
  },
  "allowed_tools": [
    "probe_same_object_across_roles",
    "compare_observations",
    "infer_bola"
  ],
  "limits": {
    "max_tool_calls": 3,
    "max_retries": 2
  }
}
```

### ToolCommand

```json
{
  "tool_name": "probe_same_object_across_roles",
  "arguments": {
    "session_id": 159,
    "owner_role": "user_a",
    "other_role": "user_b",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/abc/location",
    "method": "GET"
  }
}
```

### ToolResult

```json
{
  "tool_name": "probe_same_object_across_roles",
  "status": "ok",
  "result": {
    "session_id": 159,
    "owner_observation": {
      "id": 101,
      "status_code": 200
    },
    "other_observation": {
      "id": 102,
      "status_code": 200
    },
    "analysis": {
      "inference": "possible_bola"
    }
  }
}
```

### JudgeVerdict

```json
{
  "status": "confirmed | needs_retry | rejected | progress",
  "finding_type": "BOLA | BOPLA | AUTH | INJECTION | SSRF | XSS | NONE",
  "reason": "short explanation",
  "next_action": "save_finding | retry_same_class | switch_agent | expand_discovery | stop"
}
```

## Evidence-Based Judge Rules

Examples:

- `BOLA confirmed`:
  the same object is accessible to both owner and non-owner roles

- `BOPLA confirmed`:
  unauthorized fields are exposed or writable

- `Broken Authentication confirmed`:
  anonymous or invalid-token access is accepted on a protected endpoint

- `Injection confirmed`:
  a payload causes a reproducible effect

- `SSRF confirmed`:
  an outbound request or controlled interaction is reproduced

- `XSS confirmed`:
  payload reflection or storage is shown with realistic rendering risk

## Finite Loop Constraints

The orchestration loop must be bounded by:

- `max_rounds_per_session`
- `max_tool_calls_per_task`
- `max_retries_per_candidate`
- `stall_round_limit`

The system must stop when:

- the round budget is exhausted
- the request or time budget is exhausted
- no useful progress is made for several rounds
- the task space is exhausted

## Dify Role

Dify is used as the orchestration layer and agent runtime:

- entry interaction
- orchestrator logic
- worker prompts
- judge prompt
- report generation

The backend exposes a stable toolbox API to Dify.

## Current Implementation Status

Implemented:

- `agentic` session bootstrap
- router plan endpoint
- judge state endpoint
- loop state endpoint
- report package endpoint
- `run-round` endpoint
- session context endpoint
- BOLA worker-task endpoint
- strict tool execution endpoint

Current first worker/tool layer:

- `GET /agentic/session/{id}/context`
- `GET /agentic/session/{id}/worker-tasks/auth`
- `GET /agentic/session/{id}/worker-tasks/probe`
- `GET /agentic/session/{id}/worker-tasks/bola`
- `POST /agentic/tools/execute`
- `POST /agentic/session/{id}/prepare-auth`
- `POST /agentic/session/{id}/prepare-probe-seeds`
- `POST /agentic/session/{id}/worker-result`
- `GET /agentic/session/{id}/judge-package/{finding_id}`
- `POST /agentic/session/{id}/judge-verdict`

Current allow-listed agentic tools:

- `bootstrap_roles`
- `get_session_context`
- `login_role`
- `list_roles`
- `list_observations`
- `replay_request`
- `probe_same_object_across_roles`
- `compare_observations`
- `infer_bola`
- `register_role`

## Immediate Next Step

The current immediate milestone is:

1. bootstrap two roles
2. register them
3. authenticate them
4. obtain tokens
5. then pass execution to BOLA worker tasks

Without two authenticated roles, BOLA worker tasks remain empty.

An implementation helper exists for this stage:

- `POST /agentic/session/{id}/prepare-auth`
- `POST /agentic/session/{id}/prepare-probe-seeds`

This endpoint runs a bounded auth preparation loop using the same worker-task and tool APIs:

- `bootstrap_roles`
- `register_role`
- `login_role`

It is intended as a bridge toward fuller orchestrator-driven loops, not as a replacement for the final agentic design.

The probe helper seeds the inventory and executes a bounded number of authenticated probe tasks so that object-bearing observations become available for BOLA generation.

The judge flow for the new architecture is:

1. worker executes a tool command
2. orchestrator posts the worker result to `/agentic/session/{id}/worker-result`
3. backend creates or updates a candidate finding
4. orchestrator fetches `/agentic/session/{id}/judge-package/{finding_id}`
5. LLM judge returns a structured verdict
6. orchestrator posts the verdict to `/agentic/session/{id}/judge-verdict`

## Implementation Strategy

The project will evolve incrementally:

1. keep the current BOLA pipeline intact
2. add orchestrator/worker/tool contracts over the existing backend
3. enable auth worker flow
4. enable BOLA tool-backed worker flow
5. expand to injection and SSRF
6. extend to XSS and additional classes

This architecture is the reference design for the next implementation stages.
