# CLAUDE.md

## Project goal

This repository is a diploma project backend for an adaptive multi-agent REST API DAST system with a Judge/Arbiter.

The target architecture is:

```text
Dify workflow = orchestration + compact LLM decisions
Backend = source of truth for campaign state, graph, corpus, queue, tools, observations, evidence, findings
Agents = strategy / verification planners, not direct tool runners
Tools = bounded deterministic executors or long-running ToolRun jobs
Judge = the only component that can confirm vulnerabilities
Reporter = reads confirmed findings only
```

The project must evolve from the current mixed/legacy backend into a campaign-based, graph/corpus/evidence-driven REST API security testing platform.

The system must not become a simple scanner orchestrator. The core value is:

```text
successful requests -> reusable corpus seeds
tool signals -> normalized observations
agents -> verification / exploitation plans
backend -> safe bounded execution + state updates
evidence builder -> replay-ready EvidencePack
judge -> confirmed / rework / rejected
reporter -> confirmed findings only
```

---

## Non-negotiable rules

1. Do not remove the currently working BOLA / object replay / judge pipeline until the replacement has tests.
2. Do not move business logic into Dify YAML.
3. Dify must not own the full state. It should pass only:
   - `campaign_id`
   - active task id
   - active command id
   - latest tool run id
   - latest evidence id
   - compact summaries
   - current verdict/result references
4. Backend must own:
   - campaign state
   - API graph
   - dependency graph
   - request/response corpus
   - resource instances
   - task queue
   - WorkerCommand validation
   - ToolRegistry
   - ToolRun jobs
   - ToolResult normalization
   - observation store
   - evidence packs
   - judge decisions
   - confirmed findings
   - report context
5. Short synchronous tools may complete in one iteration:
   ```text
   next_task -> worker command -> tool result -> observations -> evidence pack -> judge verdict -> judge apply
   ```
6. Long-running tools must run as ToolRun jobs:
   ```text
   next_task -> worker command -> start ToolRun -> poll/collect -> ToolResult -> observations -> optional EvidencePack -> judge verdict -> judge apply
   ```
7. Judge must not be called while a ToolRun is `accepted`, `queued`, or `running`.
8. Never report a vulnerability unless the Judge returns `confirmed`.
9. All tool wrappers must return normalized `ToolResult` or start/collect a `ToolRun`.
10. Tool alerts, fuzzer crashes, scanner matches, and 500 responses are not confirmed findings by themselves.
11. Existing tests are important. Prefer incremental migration with compatibility adapters.

---

## Core architecture principles

### Tools produce signals, not confirmed vulnerabilities

Tools may produce:

```text
successful requests
HTTP exchanges
unexpected 500
schema mismatch
auth anomaly
cross-role access signal
ZAP alert
nuclei match
discovered endpoint
hidden parameter
state transition signal
raw artifacts
```

These are observations/signals. They must be normalized and stored, not reported directly.

### Agents plan verification/exploitation, not direct execution

Agents should:

```text
- interpret graph/corpus/task context;
- interpret observations;
- create vulnerability hypotheses;
- choose a verification strategy;
- select seed requests from corpus;
- choose roles, object IDs, fields, payloads;
- request replay, role swap, ownership proof, payload minimization, impact checks;
- emit one bounded WorkerCommand or VerificationPlan.
```

Agents must not:

```text
- run tools directly;
- create confirmed findings;
- bypass backend validation;
- mutate graph/corpus directly;
- pass raw scanner/fuzzer output to Judge as final evidence.
```

### Backend validates and executes

Backend must validate every command:

```text
campaign exists
task exists
task status allows execution
worker class matches task class
strategy is allowed
tool is in allowed_tools
tool exists in ToolRegistry
budget is not exceeded
target is inside allowed_hosts
seed_request exists if required
auth profiles exist if required
command fingerprint is not an unhelpful duplicate
```

### Judge receives EvidencePack only

Judge should evaluate structured evidence artifacts, not free-form worker reasoning or raw scanner output.

---

## Current important backend entrypoints

There are currently two backend shapes in the repository.

### Toolbox backend

Main file:

```text
backend/main.py
```

This is the Dify/toolbox-oriented backend. It exposes `/v1/*` routes such as:

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

This backend is used by the current Dify workflow and should become the main Dify-facing API.

### Legacy / experiment backend

Main file:

```text
backend/app/main.py
```

This exposes older session/experiment/report routes such as:

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

---

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
/v1/tools/runs/*
/v1/observations/*
/v1/evidence/*
/v1/judge/*
/v1/findings/*
/v1/report/*
```

Existing endpoints can remain as compatibility routes.

---

## Worker model

Do not create one agent per OWASP API Top 10 class. Use strategy workers:

```text
access_control       -> API1 BOLA, API2 Auth, API3 BOPLA, API5 BFLA
contract_fuzzing     -> schema violations, negative testing, API3/API4
stateful_flow        -> RESTler/stateful sequences, API6/business flows
discovery_inventory  -> OpenAPI gaps, hidden endpoints, API9
misconfiguration     -> ZAP/nuclei/httpx checks, API8
ssrf_external        -> URL/callback/webhook checks, API7/API10
```

Workers return normalized `WorkerCommand` or `VerificationPlan`.

Workers do not confirm findings.

---

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

A worker produces a normalized `WorkerCommand`; backend validates and executes it.

Tools do not write findings directly.

---

## Long-running tools

Long-running tools must use the ToolRun flow:

```text
RESTler
Schemathesis with many examples
CATS
OWASP ZAP active scan
nuclei with many templates
ffuf / Kiterunner with large wordlists
Playwright crawl
```

ToolRun statuses:

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

Required conceptual flow:

```text
POST /v1/tools/runs/start
GET  /v1/tools/runs/{tool_run_id}
POST /v1/tools/runs/{tool_run_id}/collect
```

Compatibility is allowed: `POST /v1/tools/execute` may internally either return a finished `ToolResult` or start an async `ToolRun`.

Rules:

```text
- Do not send running ToolRun to Judge.
- Do not send raw fuzzer/scanner output to Judge.
- Collect ToolResult after ToolRun finishes.
- Normalize ToolResult into observations.
- Build EvidencePack only for judge-worthy observations or completed verification plans.
```

---

## Observation and verification model

Add a separation between tool output and judge-ready evidence.

```text
ToolResult
  -> raw artifact storage
  -> request corpus update
  -> API/dependency graph update
  -> Observation normalization
  -> Observation triage
  -> VerificationPlan if proof is incomplete
  -> EvidencePack only for judge-worthy candidates
  -> Judge
```

Examples:

```text
Schemathesis found one 500
  -> Observation: unexpected_500
  -> VerificationPlan: replay_minimized_payload
  -> not confirmed finding yet

ZAP found CORS alert
  -> Observation: zap_alert
  -> VerificationPlan: cors_replay_validation
  -> not confirmed finding yet

user_b received 200 for user_a object
  -> Observation: cross_role_access_signal
  -> VerificationPlan: prove_ownership if ownership proof is missing
  -> confirmed only after EvidencePack is complete and Judge confirms
```

---

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

Judge must evaluate EvidencePack, not raw tool output and not free-form worker reasoning.

---

## JudgeApply contract

JudgeApply must be the only backend path that creates confirmed findings.

Rules:

```text
confirmed:
  - create confirmed finding;
  - link evidence_id;
  - mark task confirmed;
  - deduplicate similar tasks.

rework:
  - create bounded follow-up task;
  - preserve parent_task_id;
  - enforce max_retries and max_rework_depth;
  - preserve missing_evidence.

rejected:
  - mark task rejected;
  - store reason;
  - do not create finding.

duplicate:
  - link to existing finding;
  - do not create new finding.

out_of_scope:
  - mark task out_of_scope;
  - optionally suppress similar tasks.
```

---

## Refactor style

Prefer small pull-request-sized steps:

1. Add target docs and schemas.
2. Add compatibility campaign model around current `run_id`.
3. Add request corpus service.
4. Add API graph / dependency graph as planner input.
5. Replace in-memory/transient state with campaign-backed state where safe.
6. Normalize WorkerCommand.
7. Add CommandValidator.
8. Normalize ToolResult.
9. Add ToolRun model and start/status/collect flow.
10. Add Observation model and observation triage.
11. Add VerificationPlan and follow-up task generation.
12. Move evidence building to backend-owned EvidencePack.
13. Add JudgeApply as the only confirmed finding writer.
14. Make Dify loop thin.
15. Add full report context from backend.
16. Add wrappers one by one.

Do not implement all phases in one task.

---

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
test_judge_handoff_preservation.py
test_agentic_judge_service.py
test_final_stop_reason_service.py
test_traffic_capture_service.py
```

New target tests should include:

```text
test_campaign_create_returns_campaign_id
test_campaign_summary_contains_budget_and_counts
test_legacy_run_id_maps_to_campaign_id

test_corpus_stores_successful_2xx_request
test_corpus_stores_403_as_auth_baseline
test_corpus_redacts_authorization_header
test_corpus_extracts_object_ids
test_corpus_finds_cross_role_candidates

test_worker_command_validates_allowed_tool
test_worker_command_rejects_out_of_scope_host
test_worker_command_uses_seed_request

test_start_async_tool_run_returns_tool_run_id
test_running_tool_run_does_not_call_judge
test_finished_tool_run_can_be_collected
test_timeout_tool_run_returns_structured_error

test_unexpected_500_creates_observation_not_finding
test_schema_mismatch_not_judged_without_impact
test_auth_bypass_observation_marked_judge_worthy
test_cross_role_signal_requires_ownership_proof
test_observation_can_create_verification_task

test_evidence_pack_contains_baseline_and_attack
test_bola_missing_ownership_proof_sets_missing_evidence
test_evidence_pack_contains_replay_steps

test_confirmed_verdict_creates_finding
test_rework_verdict_creates_followup_task
test_rejected_verdict_does_not_create_finding
test_duplicate_verdict_does_not_create_new_finding
```

---

## First MVP flow to preserve/build

The first full end-to-end target should be:

```text
BOLA signal-to-proof
```

Expected flow:

```text
1. campaign created
2. OpenAPI/traffic creates operation
3. corpus has successful user_a request
4. planner creates access_control task
5. worker creates role_swap_object_access command
6. backend validates and executes user_a/user_b replay
7. observation is created
8. EvidencePack/Judge returns rework if ownership proof is missing
9. agent creates prove_ownership verification task
10. backend executes owner/attacker collection checks
11. EvidencePack contains baseline, attack, ownership proof, negative control, replay steps
12. Judge confirms
13. JudgeApply creates confirmed finding
14. report context includes finding
```

Do not start by integrating every scanner. First make this one complete flow reliable.

---

## What not to do

Do not perform a big-bang rewrite.

Do not delete:

```text
existing judge services
existing report endpoints
existing BOLA/object replay tests
existing Dify workflow contract tests
existing wrapper observability and run logs
legacy backend layer
```

Do not let LLM-generated nodes become the canonical source of state.

Do not let tool alerts become confirmed findings without Judge confirmation.

Do not send raw scanner/fuzzer output directly to Judge.

Do not allow tools to write confirmed findings.

Do not run long fuzzers/scanners synchronously without explicit timeout/budget.

Do not skip scope validation or redaction.

---

## Required behavior summary

The correct system behavior is:

```text
Input -> Campaign
Campaign -> Surface
Surface -> API Graph + Dependency Graph
Graph + Corpus -> Task Queue
Task -> Agent WorkerCommand
WorkerCommand -> Backend validation
Backend -> ToolResult or ToolRun
ToolResult -> Corpus + Graph + Observations
Observations -> VerificationPlan or EvidencePack
EvidencePack -> Judge
Judge verdict -> JudgeApply
Confirmed findings -> Report
```

If a change violates this flow, stop and ask for clarification.
