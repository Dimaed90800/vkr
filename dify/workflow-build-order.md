# Workflow Build Order

Build the Dify side in this order:

## Step 1. Create `wf-agentic-main`

At first, keep everything in one orchestration workflow.

Initial chain:

- `Start`
- `HTTP Request`: `POST /agentic/start`
- `HTTP Request`: `POST /agentic/session/{session_id}/prepare-auth`
- `HTTP Request`: `POST /agentic/session/{session_id}/prepare-probe-seeds`
- `HTTP Request`: `GET /agentic/session/{session_id}/worker-tasks/bola`
- `Code`: pick first task
- `HTTP Request`: `POST /agentic/tools/execute`
- `HTTP Request`: `POST /agentic/session/{session_id}/worker-result`
- `HTTP Request`: `GET /agentic/session/{session_id}/judge-package/{finding_id}`
- `LLM`: judge agent
- `HTTP Request`: `POST /agentic/session/{session_id}/judge-verdict`
- `HTTP Request`: `GET /agentic/session/{session_id}/judge-state`
- `HTTP Request`: `GET /agentic/session/{session_id}/report-package`
- `LLM`: final report
- `Output`

At this point, no loop is required.

## Step 2. Add the main `Loop`

Goal:

- keep retry and exit conditions in one place
- iterate across BOLA worker tasks
- avoid early cross-workflow fragmentation

Success condition:

- one BOLA task can be retried and the loop exits cleanly
- the BOLA loop still creates a non-null `candidate_finding`

Reference:

- [wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md)

## Step 3. Keep router optional, not mandatory

Goal:

- do not block the working vertical slice on router LLM prose
- use backend worker-task bundles as the main source of truth

Success condition:

- the workflow works even if no router-agent node is used

## Step 4. Add access-control execution inside `wf-agentic-main`

Start with only:

- `bola_probe`
- `judge_package`
- `judge_verdict`

Success condition:

- it can consume one BOLA worker task and return normalized evidence
- for BOLA, prefer deterministic worker-result construction over an LLM summary step when the backend tool already returns structured `analysis`

## Step 5. Add judge inside `wf-agentic-main`

Goal:

- feed structured evidence into an LLM judge
- persist the strict verdict back to backend

Success condition:

- it returns a strict JSON verdict without free-form drift

## Step 6. Add final report inside `wf-agentic-main`

- generate Markdown from confirmed findings only

## Step 7. Add optional `Chatflow`

Only after the main workflow works.

The Chatflow should:

- collect inputs
- call `wf-agentic-main`
- show progress and final output

## Step 8. Split into helper workflows only if needed

If the main workflow becomes too large, extract:

- `wf-router`
- `wf-discovery`
- `wf-access-control`
- `wf-judge`
- `wf-report`

## Loop Condition

The main workflow loop continues while:

- judge says `needs_retry`
- worker tasks remain
- budgets not exhausted
- `max_rounds` not reached

For the current canonical transition rules and stop conditions, use:

- [wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md)

## Extend Workers

After BOLA works, add:

- `auth` worker family
- `probe` worker family
- `bopla_probe`
- `verify_bopla`
- `auth_boundary_probe`
- `verify_auth_boundary`
- later `bfla_probe`

## Recommended MVP

The first fully working vertical slice should be:

- `wf-agentic-main`
- backend toolbox strict tool executor
- `prepare-auth`
- `prepare-probe-seeds`
- BOLA only
- worker-result ingestion
- LLM judge verdict
- final report

Current practical baseline:

- [wf-agentic-main-v10.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-main-v10.yml)

Current orchestration-first baseline:

- [wf-agentic-orchestrated-v2.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-orchestrated-v2.yml)

For the current bounded loops, the retry cap is implemented through:

- `loop_count = 2`
- judge-driven `should_exit_bola_loop`
- judge-driven `should_exit_bopla_loop`

This is preferred over a pseudo-memory field that is not persisted between iterations.

The current orchestration-first path now also includes deterministic scanner loops:

- `Discovery Agent loop`
- `DAST Agent loop`
- then the bounded `Access Control` loops for `BOLA` and `BOPLA`

## Step 9. Add `bopla` worker family

Goal:

- consume `GET /agentic/session/{session_id}/worker-tasks/bopla`
- use `infer_bopla` for stored observations
- persist candidate findings through `worker-result`

Success condition:

- a BOPLA candidate can be created and confirmed through the same judge loop
- the `BOPLA` family can also run in a bounded loop after `BOLA`
