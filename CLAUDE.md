# CLAUDE.md

## Project goal

This repository is a diploma project backend for an adaptive multi-agent REST API DAST system.

The target architecture is:

```text
Dify workflow = orchestration + compact LLM decisions
Backend = source of truth for state, graph, corpus, queue, tools, evidence, findings
Tools = bounded deterministic executors
Judge = the only component that can confirm vulnerabilities
Reporter = reads confirmed findings only
```

The project must evolve from the current mixed/legacy backend into a campaign-based, graph/corpus/evidence-driven REST API security testing platform.

## Non-negotiable rules

1. Do not remove the currently working BOLA / object replay / judge pipeline until the replacement has tests.
2. Do not move business logic into Dify YAML.
3. Dify must not own the full state. It should pass `campaign_id`, active task, compact summaries and current results.
4. Backend must own:
   - campaign state
   - API graph
   - dependency graph
   - request corpus
   - resource instances
   - task queue
   - tool runs
   - evidence packs
   - judge decisions
   - confirmed findings
5. One loop iteration must execute one bounded task:
   ```text
   next_task -> worker command -> tool execution -> evidence pack -> judge verdict -> queue update
   ```
6. Never report a vulnerability unless the judge returns `confirmed`.
7. All tool wrappers must return normalized results.
8. Existing tests are important. Prefer incremental migration with compatibility adapters.

## Current important backend entrypoints

There are currently two backend shapes in the repository:

### Toolbox backend

Main file:

```text
backend/main.py
```

This is the Dify/toolbox-oriented backend. It exposes `/v1/*` routes:

```text
/v1/recon/*
/v1/discovery/*
/v1/traffic/*
/v1/surface/*
/v1/planning/*
/v1/scheduling/*
/v1/tests/*
/v1/tools/wrappers/*
/v1/store/*
```

This backend is used by the current Dify workflow.

### Legacy / experiment backend

Main file:

```text
backend/app/main.py
```

This exposes older session/experiment/report routes:

```text
/session/*
/campaign/*
/agentic/*
/judge/*
/report/*
/experiments/*
/automation/*
/agents/*
/tools/*
```

Do not delete this layer immediately. Treat it as legacy-compatible functionality that should either be preserved or gradually bridged into the campaign-based `/v1` architecture.

## Recommended source of truth after refactor

Use `backend/main.py` and `/v1/*` as the main Dify-facing toolbox API.

The target API should use these conceptual groups:

```text
/v1/campaigns
/v1/ingest/openapi
/v1/surface/*
/v1/graph/*
/v1/corpus/*
/v1/tasks/*
/v1/workers/*
/v1/tools/*
/v1/evidence/*
/v1/judge/*
/v1/findings/*
/v1/report/*
```

Existing endpoints can remain as compatibility routes.

## Worker model

Do not create one agent per OWASP class. Use strategy workers:

```text
access_control       -> API1 BOLA, API2 Auth, API3 BOPLA, API5 BFLA
contract_fuzzing     -> schema violations, negative testing, API3/API4
stateful_flow        -> RESTler/stateful sequences, API6/business flows
discovery_inventory  -> OpenAPI gaps, hidden endpoints, API9
misconfiguration     -> ZAP/nuclei/httpx checks, API8
ssrf_external        -> URL/callback/webhook checks, API7/API10
```

## Tool layer

All tools must be hidden behind backend wrappers:

```text
custom request executor
OpenAPI parser
OWASP ZAP
Schemathesis
RESTler
CATS
Playwright
mitmproxy
nuclei
httpx
ffuf / Kiterunner
Arjun
jwt_tool
```

A worker produces a normalized `WorkerCommand`; backend executes it; tools do not write findings directly.

## Judge contract

Judge verdicts:

```text
confirmed
rejected
rework
duplicate
out_of_scope
inconclusive
```

For compatibility, existing code may still use only:

```text
confirmed
rejected
rework
```

but new schema should allow extension.

The judge must evaluate evidence artifacts, not free-form worker reasoning.

## Refactor style

Prefer small pull-request-sized steps:

1. Add target docs and schemas.
2. Add compatibility campaign model around current `run_id`.
3. Add request corpus service.
4. Add graph state service.
5. Replace in-memory state with campaign-backed state.
6. Normalize worker commands.
7. Normalize tool results.
8. Move evidence building to backend.
9. Make Dify loop thin.
10. Add full report context from backend.

## Test expectations

Before and after each phase run:

```bash
python -m pytest tests
```

or, if the project currently uses unittest-compatible discovery:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

Also run focused tests around:

```text
test_dify_workflow_dispatch_contract.py
test_graph_state_integration.py
test_replay_service.py
test_judge_service.py
test_unified_judge_service.py
test_task_tooling_integration.py
test_routes_scheduling_diagnostics.py
test_task_contract_alignment.py
```

## What not to do

Do not perform a big-bang rewrite.

Do not delete:
- existing judge services
- existing report endpoints
- existing BOLA/object replay tests
- existing Dify workflow contract tests
- existing wrapper observability and run logs

Do not let LLM-generated nodes become the canonical source of state.

Do not let tool alerts become confirmed findings without judge confirmation.
