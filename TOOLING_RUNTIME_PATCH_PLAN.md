# Tooling runtime patch plan

## What is already fixed in code

- Added `/v1/tools/capabilities` and `/v1/tools/preflight` to expose real tool readiness.
- Added health preflight summary under `/health`.
- Reordered tool priorities so agents prefer robust direct tools before scaffold-only runtimes.
- Marked degraded/planner-only adapter paths more explicitly for RESTler, CATS and Akto.

## What still must be done to get every tool to true runtime mode

### 1) Schemathesis

Status: closest to production-ready.

Requirements:
- keep `schemathesis>=4,<5` installed;
- ensure OpenAPI is reachable from toolbox;
- pass auth headers for protected endpoints.

### 2) RESTler

Current state:
- compile/fuzz/replay still degrade without a real RESTler binary.

To finish:
- install a real RESTler runtime or provide a dedicated `restler-runner` container;
- set `RESTLER_BIN` to a real executable path;
- keep `RESTLER_WRAPPER_COMMAND` pointing to `scripts/runtime/restler_runtime_adapter.py`;
- extend adapter so replay uses a real sequence file instead of scaffold-only artifacts.

Suggested runtime strategy:
- dedicated service `restler-runner` is cleaner than bundling everything into toolbox.

### 3) CATS

Current state:
- adapter works, but without `CATS_BIN` it only emits a negative-testing plan.

To finish:
- install a real CATS CLI/runtime in toolbox or a dedicated runner container;
- set `CATS_BIN` accordingly;
- extend adapter parsing so stdout/stderr produce normalized candidate findings.

### 4) Akto

Current state:
- inventory mode is useful even now;
- authz scan path is still planner-oriented without upstream runtime.

To finish:
- decide whether Akto is planner/inventory only or full execution runtime;
- if full runtime is desired, add a real Akto runner/API integration and set `AKTO_BIN` or wrapper endpoint;
- otherwise keep `akto_inventory_discovery` and demote `akto_authz_scan` to non-preferred helper mode.

### 5) ASTF

Current state:
- not safe as a preferred runtime until `ASTF_WRAPPER_COMMAND` or `ASTF_BIN` is real.

To finish:
- either wire a real ASTF wrapper command/service;
- or remove `astf_top10_suite` from the preferred path entirely.

## Recommended docker direction

### Better long-term architecture

- `toolbox` — orchestration backend and direct probes
- `zap` — discovery/scan service
- `playwright-runner` — browser-backed flows
- `restler-runner` — RESTler only
- `cats-runner` — CATS only
- `akto-runner` — Akto only

This avoids a giant toolbox image and makes capability reporting honest.

## Immediate operational rule

Do not let the workflow prefer a tool unless `/v1/tools/capabilities` reports it as `available`.
For `planner_only` tools, use them only for enrichment or planning, not as the first executor.
