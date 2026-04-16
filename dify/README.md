# Dify Blueprint For Agentic REST API Pentest

This directory contains the Dify-side blueprint for the diploma project.

- `apps.md`: recommended Dify application layout
- `workflow-build-order.md`: recommended implementation order
- `main_workflow_blueprint.md`: backend-aligned main workflow design
- `wf-agentic-loop-design.md`: canonical finite judge-driven loop design for the main workflow
- `wf-agentic-main-node-by-node.md`: exact manual node order and payloads for Dify Studio
- `wf-agentic-main-v2.yml`: best-effort importable BOLA-first workflow aligned with the new backend pipeline
- `wf-agentic-main-v3.yml`: best-effort importable workflow with both BOLA and BOPLA worker/judge branches
- `wf-agentic-main-v4.yml`: loop-ready baseline that keeps the working v3 path and adds backend loop-state awareness for bounded retry evolution
- `wf-agentic-main-v5.yml`: first importable BOLA-loop baseline with fixed loop-local bindings
- `wf-agentic-main-v6.yml`: BOLA-loop baseline that replaces LLM worker-result normalization with deterministic code
- `wf-agentic-main-v7.yml`: current working baseline; unwraps the backend tool-execution envelope before BOLA worker-result ingestion so BOLA candidate findings are created reliably
- `wf-agentic-main-v8.yml`: extends the same deterministic worker-result pattern to BOPLA
- `wf-agentic-main-v9.yml`: practical baseline with a bounded `BOLA` loop and linear `BOPLA` branch
- `wf-agentic-main-v10.yml`: current practical baseline; uses bounded loops for both `BOLA` and `BOPLA`, keeps deterministic worker-result building, and preserves the final `loop-state -> report` tail
- `wf-agentic-orchestrated-v1.yml`: orchestrated workflow baseline; starts with a logical-agent orchestrator plan and then runs the existing bounded access-control loops
- `wf-agentic-orchestrated-v2.yml`: orchestration-first baseline with executable `Discovery Agent` and `DAST Agent` loops added around the existing bounded access-control loops
- `worker-agent-contracts.md`: strict JSON contracts for Dify worker agents
- `prompts/bopla_worker_system_prompt.md`: system prompt for the BOPLA worker agent
- `prompts/`: system prompts for Dify agents
- `contracts/agentic_toolbox_api.json`: HTTP contract expected from the backend toolbox

## Current Toolbox Notes

The agentic toolbox now exposes both backend-native exploitation tools and the first
external discovery/DAST adapters through `POST /agentic/tools/execute`.

Available external adapters in the strict toolbox:

- `discover_openapi`
- `zap_spider`
- `zap_ajax_spider`
- `zap_active_scan`
- `zap_baseline_scan`

The next planned adapters are `schemathesis`, `ffuf`, `nmap`, and `RESTler`.

## Recommended Dify Strategy

For the current stage of the project, the recommended approach is:

- one main `Workflow` in Dify as the orchestration brain
- one external backend toolbox for execution, evidence storage, and judge persistence
- one optional `Chatflow` only as a user-facing entry point

This means:

- use Dify for orchestration, branching, and LLM-based judging/reporting
- use the backend for strict tool execution, observations, findings, and session state
- avoid putting raw scanner execution or evidence storage directly inside Dify

## Current Backend-Aligned Vertical Slice

The currently implemented path is:

1. `POST /agentic/start`
2. `POST /agentic/session/{session_id}/prepare-auth`
3. `POST /agentic/session/{session_id}/prepare-probe-seeds`
4. `GET /agentic/session/{session_id}/worker-tasks/bola`
5. `POST /agentic/tools/execute`
6. `POST /agentic/session/{session_id}/worker-result`
7. `GET /agentic/session/{session_id}/judge-package/{finding_id}`
8. `LLM judge`
9. `POST /agentic/session/{session_id}/judge-verdict`
10. `GET /agentic/session/{session_id}/report-package`
11. `LLM report`

This is the main path that should be built and tested first in Dify.

## Current Loop Recommendation

After the linear vertical slice works, extend it using the canonical loop in
[wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md).

The main loop should:

- stay inside one `wf-agentic-main` workflow
- iterate over `BOLA` and then `BOPLA` worker-task bundles
- let the judge decide `retry / next / stop`
- remain finite through `max_rounds`, retry limits, and backend `loop-state`

## Current Working Baseline

The current practical Dify baseline is:

- [wf-agentic-main-v10.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-main-v10.yml)

The current orchestration-first Dify baseline is:

- [wf-agentic-orchestrated-v2.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-orchestrated-v2.yml)

Why `v10` is the current baseline:

- it keeps the working `BOLA -> judge -> BOPLA -> report` path
- it uses a bounded `BOLA` loop
- it uses a bounded `BOPLA` loop
- it avoids LLM drift on both `BOLA` and `BOPLA` worker-result normalization
- it unwraps the backend tool-execution envelope before `worker-result` ingestion
- it uses a simple and honest retry cap for both families through `loop_count=2`

Why `wf-agentic-orchestrated-v2` exists:

- it keeps the working `v10` access-control loops
- it introduces the new `orchestrator-plan` step for logical agents such as `replay_auth_agent`, `discovery_agent`, `access_control_agent`, and `dast_agent`
- it adds deterministic `Discovery Agent` and `DAST Agent` loops that execute `discover_openapi`, `zap_spider`, `zap_ajax_spider`, `zap_baseline_scan`, and `zap_active_scan` through the same `worker-result` ingestion path
- it is the right base for moving from direct BOLA/BOPLA naming toward higher-level agent orchestration without breaking the current worker-family pipeline

This last point is important because backend `worker-result` ingestion expects the
inner tool `result`, not the outer Dify HTTP response envelope.

## Target Architecture

`Chatflow -> Orchestrator -> Worker -> Tool -> Judge -> Report`

Principles:

- Dify orchestrates.
- Backend toolbox executes strict allow-listed tools.
- Worker results are ingested before the judge sees them.
- Judge validates evidence, not agent intentions.
- Final report is based on confirmed findings.
- Router prose is optional; structured worker-task bundles are the main source of truth.
