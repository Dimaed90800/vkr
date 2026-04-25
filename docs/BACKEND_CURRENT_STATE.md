# BACKEND_CURRENT_STATE.md

## Purpose

This document describes the current backend shape so an AI coding agent can refactor the project safely.

## Repository-level files already present

Important existing documents:

```text
README.md
README_ARCHITECTURE_AGENTIC.md
MIGRATION_NOTES.md
AGENTS.md
RUN_DIAGNOSIS.md
TOOLING_RUNTIME_PATCH_PLAN.md
TOOLING_RUNTIME_LOCAL_STACK_GUIDE.md
AUTH_BOOTSTRAP_DIAGNOSIS.md
AUTH_OBJECT_PREPARATION_DIAGNOSIS.md
JUDGE_HANDOFF_DIAGNOSIS.md
MATERIALIZATION_DIAGNOSIS.md
OPENAPI_AUTH_BOOTSTRAP_DIAGNOSIS.md
schema.html
dify/wf-multiagent-dast-multiworker.yml
```

These documents are useful but currently mix several historical architecture stages.

## Important observation

The repository contains two backend surfaces:

### 1. Dify/toolbox backend

```text
backend/main.py
backend/api/*
backend/models/*
backend/services/*
backend/storage/*
```

This backend exposes `/v1/*` routes and is closest to the target Dify toolbox architecture.

Included route groups:

```text
backend/api/routes_recon.py
backend/api/routes_discovery.py
backend/api/routes_traffic_discovery.py
backend/api/routes_surface_acquisition.py
backend/api/routes_planning.py
backend/api/routes_scheduling.py
backend/api/routes_tests.py
backend/api/routes_tool_wrappers.py
backend/api/routes_store.py
```

Important services:

```text
backend/services/graph_state_service.py
backend/services/task_planner.py
backend/services/task_scheduler.py
backend/services/task_tooling_service.py
backend/services/evidence_builder_service.py
backend/services/followup_task_generation_service.py
backend/services/wrapper_observability.py
backend/services/traffic_capture_service.py
backend/services/browser_capture_service.py
backend/services/js_analysis_service.py
backend/services/surface_merge_service.py
backend/services/surface_enrichment_service.py
backend/services/openapi_normalizer.py
backend/services/openapi_baseline_synthesis_service.py
```

This is the preferred base for the new architecture.

### 2. Legacy/experiment backend

```text
backend/app/main.py
backend/app/routers/*
backend/app/services/*
backend/app/models.py
backend/app/schemas.py
backend/app/db.py
```

This layer contains older session/campaign/experiment/report APIs.

It should not be removed immediately because it contains useful functionality:

```text
agentic orchestration
session lifecycle
role setup
BOLA services
BOPLA services
experiment runner
metrics
reporting
automation jobs
legacy Dify fallback
```

It should be gradually bridged or deprecated.

## Current tool state

The Dockerfile already attempts to include:

```text
RESTler
CATS
ASTF
nuclei
httpx
ffuf
Schemathesis
ZAP service
Playwright runner service
mitmproxy service
```

Current wrappers appear to include real or scaffolded support for:

```text
Schemathesis
RESTler
CATS
Akto
ASTF
```

The refactor should preserve wrapper-first execution and preflight capability reporting.

## Current task classes

Existing task schema currently uses:

```text
authorization
injection
business_logic
```

Target architecture should introduce richer strategy classes:

```text
access_control
contract_fuzzing
stateful_flow
discovery_inventory
misconfiguration
ssrf_external
```

Do this through a compatibility mapping first:

```text
authorization     -> access_control
injection         -> contract_fuzzing
business_logic    -> stateful_flow
```

Then extend the schema after tests pass.

## Existing schema files

Current schema files:

```text
backend/schemas/task.json
backend/schemas/evidence.json
backend/schemas/verdict.json
backend/schemas/finding.json
```

They are useful and should be evolved, not discarded.

## Biggest architectural gaps

1. State is not yet clearly campaign-centered.
2. Request corpus is not yet treated as the central reusable asset.
3. API graph and dependency graph exist partially but are not the canonical source for planner decisions.
4. Dify workflow still carries too much temporary state.
5. Worker dispatch and tool execution are partly mixed.
6. Evidence building exists but should become fully backend-owned.
7. Reporting should read confirmed findings from backend, not from transient workflow state.
8. Tool capabilities need a clearer registry and per-tool preflight status.
9. There is no single source-of-truth document describing data contracts for the target architecture.
10. There is no phased migration plan that tells an AI coding agent what to change first.

## Refactor risk points

Be careful around:

```text
Dify workflow contract
wrapper-first dispatch
Schemathesis execution path
judge-ready evidence
final stop reason resolution
auth bootstrap/materialization
object replay
BOLA/BOPLA finding dedup
experiment reports
runtime logs under logs/dast_runs
```

These parts already had fixes and tests. Avoid regressions.
