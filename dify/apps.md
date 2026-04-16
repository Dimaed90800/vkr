# Dify Apps

## Recommended App Set For MVP

For the first working version, prefer:

- one main `Workflow`
- one optional `Chatflow`

Do not split into many workflows too early unless the main workflow is already stable.

## Main Recommendation

### 1. Workflow: `wf-agentic-main`

Purpose:

- orchestrate the whole campaign
- keep the auth, probe, worker, judge, and report state in one place
- reduce cross-workflow complexity during MVP

Suggested nodes:

- `Start`
- `Normalize Campaign Prompt`
- `HTTP Request`: `POST /agentic/start`
- `HTTP Request`: `POST /agentic/session/{session_id}/prepare-auth`
- `HTTP Request`: `POST /agentic/session/{session_id}/prepare-probe-seeds`
- `HTTP Request`: `GET /agentic/session/{session_id}/worker-tasks/bola`
- `HTTP Request`: `GET /agentic/session/{session_id}/worker-tasks/bopla`
- `Code`: pick current worker task
- `LLM`: `BOLA Worker Agent`
- `LLM`: `BOPLA Worker Agent`
- `Loop`
- inside loop:
  - `If-Else`: no tasks left / budget exhausted
  - `LLM`: build strict tool command from worker task
  - `HTTP Request`: `POST /agentic/tools/execute`
  - `LLM`: summarize tool result as worker result
  - `HTTP Request`: `POST /agentic/session/{session_id}/worker-result`
  - `HTTP Request`: `GET /agentic/session/{session_id}/judge-package/{finding_id}`
  - `LLM`: judge agent
  - `HTTP Request`: `POST /agentic/session/{session_id}/judge-verdict`
  - `Code`: update loop state and pick next task
- `HTTP Request`: `GET /agentic/session/{session_id}/judge-state`
- `HTTP Request`: `GET /agentic/session/{session_id}/report-package`
- `LLM`: final report
- `Output`

Loop control for `wf-agentic-main` should follow
[wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md).

Use a single bounded loop with:

- family order `bola -> bopla`
- one deterministic transition code node after each saved judge verdict
- a retry cap per task
- a final exit to report when all families are exhausted or the backend says stop

### 2. Optional Chatflow: `api-pentest-orchestrator`

Purpose:

- accept the user prompt
- collect target URL and guardrails
- call the main workflow
- present progress and the final report

Main inputs:

- `user_prompt`
- `target_name`
- `target_url`
- `allowed_test_classes`
- `max_rounds`
- `budget_requests_total`
- `budget_time_total`
- `profile`

## Modular Split

After the main workflow is stable, you can split it into helper workflows.

### `wf-worker-bola`

Purpose:

- consume one structured BOLA worker task
- let an LLM worker build one strict tool command
- execute one allowed tool
- let the worker summarize the tool result
- return normalized worker result

Nodes:

- `Start`
- `LLM`: `BOLA Worker Agent`
- `HTTP Request`: `POST /agentic/tools/execute`
- `LLM`: `BOLA Worker Agent`
- `HTTP Request`: `POST /agentic/session/{session_id}/worker-result`
- `Output`

### `wf-discovery`

Purpose:

- prepare API inventory
- collect high-value endpoints
- improve later attack quality

Nodes:

- `Start`
- `HTTP Request`: `POST /v1/discovery/openapi`
- `HTTP Request`: `POST /v1/discovery/spider`
- `HTTP Request`: `POST /v1/discovery/ffuf`
- `Code`: merge inventory
- `Output`

### `wf-access-control`

Purpose:

- run specialized tasks for BOLA, BOPLA, BFLA, auth-boundary

Nodes:

- `Start`
- `Iteration` over tasks
- `If-Else` by `task_type`
- `HTTP Request`: backend toolbox execution endpoint
- `HTTP Request`: worker-result ingestion endpoint
- `Output`

### `wf-judge`

Purpose:

- inspect only the evidence package prepared by the backend
- return a strict verdict JSON
- persist the verdict back to backend

Nodes:

- `Start`
- `HTTP Request`: `GET /agentic/session/{session_id}/judge-package/{finding_id}`
- `LLM`: strict verdict
- `HTTP Request`: `POST /agentic/session/{session_id}/judge-verdict`
- `Output`

### `wf-report`

Purpose:

- generate final Markdown report from confirmed findings

Nodes:

- `Start`
- `HTTP Request`: `GET /agentic/session/{session_id}/report-package`
- `LLM`
- `Output`

## Optional Chatflow Orchestration

Recommended Chatflow chain:

1. `Start`
2. `User Input`
3. `Variable Assigner`
4. `Tool`: `wf-agentic-main`
5. `Answer`

## Dify Node Usage Notes

- Use `Chatflow` only for UX and control.
- Put the main repeatable logic in one `Workflow` first.
- Use `HTTP Request` nodes for the backend toolbox.
- Use `Loop` for stateful dependent retries over worker tasks.
- Use `Iteration` only for independent batch operations.
- Use `If-Else` to branch by `task_type` and judge status.
- Use `Code` nodes for strict normalization between tools, worker results, and judge packages.
- Keep `Human Input` optional for dangerous or high-cost scans.
- Keep one canonical loop design document and evolve the DSL toward it instead of duplicating retry logic in multiple workflows.
