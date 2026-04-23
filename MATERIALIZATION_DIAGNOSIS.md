# Object Materialization Diagnosis

## Latest inspected run

- `run_id`: `run-f16b1f041240`
- Run artifacts inspected:
  - `logs/dast_runs/run-f16b1f041240/events.jsonl`
  - `logs/dast_runs/run-f16b1f041240/run_summary.json`

## High-level result

Auth bootstrap is no longer the primary blocker in this run:

- OpenAPI reached auth bootstrap.
- Login succeeded for both `user_a` and `user_b`.
- Token extraction happened.
- `usable_identity_total = 2`.

Object materialization still did not start:

- `_materialization_attempts = 0`
- `_materialization_successes = 0`
- No `object_materialization_*` events were emitted.

This means materialization did not fail inside `create_test_object` or list/select execution. It never reached that execution path.

## Concrete trace evidence

### Follow-up materialization tasks were generated

The run generated materialization-style follow-ups, including variants like:

- `task_authorization_021__create_object_then_replay_1`
- `task_authorization_021__list_then_select_object_then_rep_1`
- `task_authorization_041__create_object_then_replay_1`
- `task_authorization_041__list_then_select_object_then_rep_1`
- `task_authorization_045__create_object_then_replay_1`
- `task_authorization_045__list_then_select_object_then_rep_1`

So the blocker is not absence of follow-up generation.

### A materialization-preparation task became executable but was not selected

`task_authorization_042__object_specific_auth_probe_1` was evaluated as a preparation task:

- `execution_mode = preparation`
- `readiness = needs_preparation`
- `auth_context_available = true`
- `preferred_tool = create_test_object`
- `preferred_strategy = create_object_then_replay`
- `resolved_object_id = null`
- `missing_object_id = true`

At the end of scheduling, it was still skipped while the scheduler reported:

- `reason = all_class_budgets_exhausted`
- `executable_preparation_task_count = 2`
- skipped task ids included `task_authorization_042__object_specific_auth_probe_1`

This shows one concrete stopping point: a valid materialization preparation candidate existed after auth succeeded, but class-budget exhaustion prevented it from being dispatched.

### Some materialization follow-ups were treated as direct tests without object IDs

`task_authorization_045__list_then_select_object_then_rep_1` was evaluated as:

- `execution_mode = test`
- `readiness = ready_to_test`
- `test_strategy = cross_role_replay`
- `preferred_tool = null`
- `resolved_object_id = null`

This indicates that at least one list/select materialization follow-up was normalized into a direct replay-style test before an object id existed. It then flowed through judge/rework instead of materialization execution.

Second-generation follow-ups from the same area were later suppressed for reasons including:

- `missing_object_context_for_direct_replay`
- `retry_limit_exceeded`

This is the second concrete stopping point: some object-materialization follow-up tasks lose the “must materialize object first” shape and become ordinary authorization replay tasks with no object context.

## Exact blocker

Materialization is blocked downstream of auth bootstrap by scheduler/executability handoff behavior:

1. Materialization preparation candidates can exist after auth is available, but scheduler selection can skip them when authorization class budgets are exhausted.
2. Some generated materialization follow-up tasks do not consistently retain object-id prerequisites, so they can be treated as `ready_to_test` direct replay tasks before object materialization happens.

No evidence in this run shows `create_test_object` or list/select materialization executing and failing. The absence of `object_materialization_start` confirms the execution path was never entered.

## Minimal fix direction

Keep the fix narrow:

1. Ensure materialization follow-up tasks always retain:
   - object-id prerequisite
   - object-id enrichment requirement
   - preparation readiness until an object id is actually available
   - delegated/preferred materialization tool such as `create_test_object` or list/select equivalent
2. Ensure scheduler can dispatch executable materialization-preparation tasks when auth exists and object id is missing, instead of treating them as dead pending tasks once class test budgets are exhausted.
3. Persist harvested object IDs into the existing reusable context paths once materialization execution succeeds.

