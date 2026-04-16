# wf-agentic-main Loop Design

This file defines the canonical finite loop for the main Dify workflow.

Use it as the source of truth before editing the importable DSL again.

## Goal

Turn the current linear vertical slice into a bounded judge-driven cycle:

`worker task -> tool command -> tool execution -> worker result -> judge -> retry/next/stop`

The loop must stay finite and reproducible.

## Scope

The first looped version should cover:

- `BOLA`
- `BOPLA`

The same control pattern can later be reused for:

- `auth`
- `probe`
- `ssrf`
- `injection`

## Main Principle

The backend remains the execution environment and state store.

Dify is responsible for:

- choosing the current worker family
- selecting the next available task
- running the worker LLM
- sending the worker result
- running the judge LLM
- deciding whether to retry, move to the next task, move to the next family, or stop

The judge does not execute tools.

The report is generated only after the loop exits.

## Canonical Control State

Keep the main loop state in Dify code nodes.

Recommended state fields:

- `current_family`
- `current_task_id`
- `current_retry_count`
- `completed_task_ids`
- `family_order`
- `family_index`
- `round_no`
- `max_rounds`
- `should_stop`
- `stop_reason`

Recommended defaults:

- `family_order = ["bola", "bopla"]`
- `current_retry_count = 0`
- `round_no = 0`

## Finite Limits

The loop must stop if any of these conditions is true:

- `round_no >= max_rounds`
- `should_stop == true`
- there are no remaining tasks in all enabled worker families
- the backend loop state says `should_continue == false`

Recommended retry limits:

- `max_retries_per_task = 1` for MVP
- later `2` if needed

This prevents infinite Dify loops and keeps runs reproducible.

## Family Order

The first practical ordering is:

1. `bola`
2. `bopla`

Rationale:

- `BOLA` already has the strongest end-to-end evidence path
- `BOPLA` can reuse the same judge/report pattern
- both map well to the existing backend worker-task bundles

## Loop Phases

Each iteration should follow the same phases.

### Phase 0. Session bootstrap

Run once before the loop:

1. `POST /agentic/start`
2. `POST /agentic/session/{session_id}/prepare-auth`
3. `POST /agentic/session/{session_id}/prepare-probe-seeds`

This creates authenticated roles and seed observations.

### Phase 1. Refresh bundle for the active family

For the current `current_family`:

- if `bola`:
  - `GET /agentic/session/{session_id}/worker-tasks/bola`
- if `bopla`:
  - `GET /agentic/session/{session_id}/worker-tasks/bopla`

The backend already filters completed task ids.

### Phase 2. Pick one task

Use a `Code` node to:

- read `tasks`
- skip empty bundles
- choose the first remaining task
- expose:
  - `has_task`
  - `task_id`
  - `worker_type`
  - `vulnerability_class`
  - `task_payload_json`

If no task exists:

- move to the next family
- if no families remain, stop and go to report

### Phase 3. Worker execution

For the chosen task:

1. run the corresponding worker LLM
2. parse strict `tool_command`
3. `POST /agentic/tools/execute`
4. run the worker LLM again in `worker_result` mode
5. parse strict `worker_result`
6. `POST /agentic/session/{session_id}/worker-result`

This returns or creates a candidate finding in backend state.

### Phase 4. Judge

After worker-result ingestion:

1. read `finding_id`
2. `GET /agentic/session/{session_id}/judge-package/{finding_id}`
3. run the judge LLM
4. parse strict `JudgeVerdict`
5. `POST /agentic/session/{session_id}/judge-verdict`

### Phase 5. Transition

Use one `Code` node to update the loop state based on:

- `status`
- `next_action`
- `current_family`
- `current_task_id`
- `current_retry_count`
- `round_no`

## Allowed Judge Outcomes

Support these statuses:

- `confirmed`
- `needs_retry`
- `rejected`
- `progress`

Support these `next_action` values:

- `save_finding`
- `retry_same_class`
- `verify_candidate`
- `switch_agent`
- `expand_discovery`
- `stop`

For the MVP loop, normalize them like this:

- `confirmed` + `save_finding`
  - mark task complete
  - move to next task in same family
- `needs_retry` + `retry_same_class`
  - retry same task if below retry limit
  - otherwise mark task complete and move on
- `needs_retry` + `verify_candidate`
  - treat as one retry in the same family
- `rejected`
  - mark task complete
  - move to next task
- `progress`
  - keep the task complete if evidence was persisted
  - move to next task
- any `next_action == stop`
  - stop loop and go to report

## Recommended Dify Node Pattern

Keep the loop in one place.

Recommended high-level node order:

1. `Start`
2. `Code`: normalize input
3. `HTTP`: start session
4. `Code`: parse session
5. `HTTP`: prepare auth
6. `HTTP`: prepare probe seeds
7. `Code`: initialize loop state
8. `Loop`
9. inside loop:
10. `Code`: pick active family
11. `HTTP`: fetch worker-task bundle
12. `Code`: pick first available task
13. `If-Else`: has task?
14. if no:
15. `Code`: advance family or stop
16. if yes:
17. `LLM`: worker agent
18. `Code`: parse tool command
19. `HTTP`: execute tool
20. `LLM`: worker result agent
21. `Code`: parse worker result
22. `HTTP`: save worker result
23. `HTTP`: get judge package
24. `LLM`: judge
25. `Code`: parse judge verdict
26. `HTTP`: save judge verdict
27. `Code`: update loop state
28. end loop when `should_stop == true`
29. `HTTP`: get report package
30. `LLM`: report agent
31. `Answer`

## Family-Specific Worker Mapping

### `bola`

Worker nodes:

- `BOLA Worker Agent`
- `BOLA Worker Result Agent`

Expected tool:

- usually `probe_same_object_across_roles`

### `bopla`

Worker nodes:

- `BOPLA Worker Agent`
- `BOPLA Worker Result Agent`

Expected tools:

- `infer_bopla`
- optionally `replay_request` for later verification branches

## Transition Rules

Use one deterministic `Code` node after each saved judge verdict.

It should:

- increment `round_no`
- inspect `status` and `next_action`
- increment `current_retry_count` only for retry paths
- reset `current_retry_count` when moving to a new task
- set `should_stop` when:
  - `round_no >= max_rounds`
  - all families are exhausted
  - judge says `stop`

## Backend Signals To Reuse

Prefer reusing existing backend signals instead of inventing extra control logic:

- completed worker-task filtering in `worker-tasks/{family}`
- `GET /agentic/session/{id}/loop-state`
- `GET /agentic/session/{id}/judge-state`

Use backend `loop-state` as a secondary safety gate:

- if backend says `should_continue == false`, Dify should stop even if it still has local family state

## What Not To Do

Do not:

- let the judge execute tools
- let the report agent decide retries
- retry the same task without a hard limit
- mix router prose with loop control state
- generate the report before the loop exits

## MVP Success Criteria

The loop design is considered implemented when:

- one BOLA task can be retried once on `needs_retry`
- the workflow can advance to the next BOLA task
- the workflow can advance from `BOLA` to `BOPLA`
- the workflow exits cleanly when no tasks remain
- the final report uses all confirmed findings accumulated during the loop
