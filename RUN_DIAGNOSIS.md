# Run Diagnosis

## Latest run: run-564060d9947d

### Artifacts inspected

- `logs/dast_runs/run-564060d9947d/events.jsonl`
- `logs/dast_runs/run-564060d9947d/run_summary.json`
- `backend/services/auth_preparation_service.py`
- `backend/services/task_executability_service.py`
- `backend/services/testing_service.py`

### What the run actually did

- Wrapper path executed (`wrapper_dispatch_start=5`, `tool_execution_start=5`, `tool_subprocess_start=5`).
- Auth bootstrap executed with per-attempt logs (`auth_provision_register_attempt=20`, `auth_provision_login_attempt=30`).
- OpenAPI context reached auth preparation (`auth_openapi_context_received=5`).
- Materialization did not start (`_materialization_attempts=0`, `_materialization_successes=0`, no `object_materialization_*` events).
- Stop reason: `all_class_budgets_exhausted`.

### Exact blocker chain

1. Canonical register/login operations were selected from OpenAPI.
2. `POST /identity/api/auth/signup` returned `500` with duplicate-key DB error preview.
3. `POST /identity/api/auth/login` returned `401` (`Given Email is not registered`).
4. No `auth_provision_token_extracted` events, so `usable_identity_total=0`.
5. Object follow-up tasks stayed blocked by `missing_auth_context`.

So the downstream materialization bottleneck is still blocked by auth bootstrap failure in this run.

### Minimal fixes applied after this diagnosis

- `auth_preparation_service` now filters OpenAPI auth operations for bootstrap compatibility:
  - excludes token-only login operations for normal login bootstrap;
  - excludes register operations that require unsupported fields (e.g., `mechanic_code`) for generic identity bootstrap.
- `auth_preparation_service` now builds multiple schema-aware payload variants, including OpenAPI example-based variants (when present), not only generated identity payloads.
- `task_executability_service` now keeps materialization strategies executable in preparation mode:
  - if owner auth is missing, prefers `auto_provision`;
  - if owner auth exists but object id is missing, prefers `create_test_object`;
  - materialization strategies now explicitly surface `object_id_missing` even when task prerequisites under-specify it.

### Expected next-run signal

- Fewer `invalid_required_fields` in auth bootstrap attempts.
- If OpenAPI examples include valid credentials, `auth_provision_token_extracted` should appear.
- Even with partial auth bootstrap, object-materialization followups should be routed to an actual preparation tool instead of dead-ending as `missing_auth_context`.

---

## Schedule Next Tool Task retry: run-931f98ec82fd

### Observed symptoms

- Dify reported max retries for `POST /v1/schedule/next-task`.
- Latest run artifacts show scheduling did not hard-stop cleanly:
  - `scheduler_selection=2`
  - no `scheduler_no_task`
  - no `run_stop`
- After the second queue update, the next scheduling request emitted many `task_executability_evaluated` / `executability_resolved` events but never reached a third `scheduler_selection`.

### Important positive signal

The previous auth work did help:

- `auth_provision_token_extracted=2`
- `auth_provision_login_success=2`
- `auth_provision_finish=1`
- `blocked_by_reason={}` in `run_summary.json`

So the current failure is not the old auth-bootstrap blocker.

### Likely bottleneck

`TaskScheduler.select_next_task` selected a task, then called `order_queue()` for `remaining_tasks`. `order_queue()` repeatedly re-partitioned and re-evaluated the remaining queue, producing many diagnostic events and extra file I/O inside the HTTP request. In Dify, that made the scheduling node fragile after a few iterations.

### Fix applied

- `backend/services/task_scheduler.py`
  - replaced full `order_queue()` re-evaluation in `select_next_task` response with a lightweight deterministic sort of remaining tasks.
  - The next Dify iteration still evaluates tasks normally, so scheduling semantics are preserved.
- `backend/api/routes_scheduling.py`
  - added structured API events:
    - `schedule_next_task_start`
    - `schedule_next_task_finish`
    - `schedule_next_task_error`

### Verify after rerun

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_type=="schedule_next_task_start" or .event_type=="schedule_next_task_finish" or .event_type=="schedule_next_task_error")'
```

Expected:

- every `schedule_next_task_start` has either `schedule_next_task_finish` or `schedule_next_task_error`;
- `scheduler_selection` continues past the second iteration;
- Dify no longer hits max retries on `Schedule Next Tool Task`.

---

## Latest run: run-e63a2129e900

### Artifacts inspected

- `logs/dast_runs/run-e63a2129e900/events.jsonl`
- `logs/dast_runs/run-e63a2129e900/run_summary.json`
- `logs/dast_runs/run-e63a2129e900/wrapper_events.jsonl`
- `logs/dast_runs/run-e63a2129e900/judge_events.jsonl`
- `logs/dast_runs/run-e63a2129e900/preparation_events.jsonl`
- `backend/services/auth_preparation_service.py`
- `tests/test_auth_bootstrap_openapi.py`
- `MIGRATION_NOTES.md`

### Short answer

The numeric `number` fix did not unblock auth bootstrap in the newest run. Signup still returned HTTP `500`, login still returned HTTP `401`, no token/header/cookie was accepted as usable auth material, and object materialization still never started.

The wrapper path was still live, but confirmed findings remained absent because auth-dependent authorization tasks had no usable identities and materialization stayed blocked.

### Latest run summary

- Run ID: `run-e63a2129e900`
- Stop reason: `all_class_budgets_exhausted`
- Generated tasks: `120`
- Runnable tasks at summary time: `16`
- Blocked tasks at summary time: `6`
- Pending tasks at summary time: `22`
- `_materialization_attempts`: `0`
- `_materialization_successes`: `0`
- `object_materialization_success_rate`: `0.0`
- Top non-executable reason: `missing_auth_context`

### Auth bootstrap status

The newest run did execute the detailed auth attempt path:

- `auth_provision_start`: `4`
- `auth_provision_register_attempt`: `56`
- `auth_provision_register_result`: `56`
- `auth_provision_login_attempt`: `56`
- `auth_provision_login_result`: `56`
- `auth_provision_token_extracted`: `0`
- `auth_provision_finish`: `0`
- `auth_provision_failed`: `4`

All four auth provisioning tasks ended with:

- `identity_count`: `2`
- `register_success_total`: `0`
- `login_success_total`: `0`
- `usable_identity_total`: `0`
- failure reasons: `registration_failed`, `login_failed`

### Exact signup/login outcomes

Schema-grounded crAPI candidates were selected:

- Register:
  - endpoint: `/identity/api/auth/signup`
  - method: `POST`
  - content type: `application/json`
  - request body keys: `email`, `name`, `number`, `password`
  - observed count: `8`
  - status code: `500`
  - failure reason: `unexpected_status_code`
- Login:
  - endpoint: `/identity/api/auth/login`
  - method: `POST`
  - content type: `application/json`
  - request body keys: `email`, `password`
  - observed count: `8`
  - status code: `401`
  - failure reason: `unexpected_status_code`

Generic fallback paths were also tried and remained unavailable:

- `/api/register`, `/register`, `/signup`: mostly `404`
- `/api/login`, `/login`, `/signin`: `404`

No `auth_provision_token_extracted` event appeared. Login responses showed auth-like cookie presence in the redacted extraction summary, but because the HTTP status was `401`, the identity was not considered usable.

### Comparison with previous run

Previous run `run-80ca4001f549`:

- signup `/identity/api/auth/signup`: `500`
- login `/identity/api/auth/login`: `401`
- token extraction: `0`
- usable identities: `0`
- materialization attempts: `0`

Newest run `run-e63a2129e900`:

- signup `/identity/api/auth/signup`: still `500`
- login `/identity/api/auth/login`: still `401`
- token extraction: still `0`
- usable identities: still `0`
- materialization attempts: still `0`

So the numeric phone/number shape fix did not produce an observable improvement in this run.

### Current bottleneck

The active bottleneck is still auth bootstrap, specifically:

```text
POST /identity/api/auth/signup -> 500 unexpected_status_code
```

Because registration fails, login cannot succeed for those generated identities:

```text
POST /identity/api/auth/login -> 401 unexpected_status_code
```

Materialization remains blocked downstream of auth. There is not yet evidence of a separate object creator/list/id-harvesting bottleneck because no object materialization events fired at all.

### Minimal fix applied after latest run

The latest run proved that numeric `number` alone was insufficient. A second narrow issue was visible in code: generated identities were deterministic across runs because `_build_identity_seed` used only target URL, task ID, role, and identity index. That means rerunning against the same crAPI instance can reuse the same email/number values and trip duplicate-user behavior. crAPI often reports duplicate/invalid signup state poorly, including server-side `500`.

`backend/services/auth_preparation_service.py` now includes `execution_context.run_id` in the identity seed. This keeps identities deterministic within one run, but makes email/number unique across reruns.

Added test coverage:

- numeric phone/number is preserved
- generated email/number differs across run IDs

This is still a narrow auth bootstrap fix. It does not change graph state, scheduler, judge, wrappers, or materialization logic.

### Wrapper and judge secondary signal

The Schemathesis wrapper path still executed:

- `wrapper_dispatch_start`: `6`
- `tool_execution_start`: `6`
- `tool_subprocess_start`: `6`
- `tool_subprocess_completed`: `6`
- `evidence_build_finish`: `6`

Rate-abuse signal derivation still happened, but judge decisions remained conservative. The main blocker for authorization findings remains preparation failure, not wrapper dispatch.

Judge event status was `success` for 10 judge calls, meaning the judge node itself ran successfully. The actual `final_verdict` inside those events was `rework` for the inspected tasks. Auth task rework hints explicitly asked for valid identities and successful login attempts.

### What to check after the next run

```bash
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq -r 'select(.event_type=="auth_provision_register_result") | .artifacts'
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq -r 'select(.event_type=="auth_provision_login_result") | .artifacts'
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq -r 'select(.event_type=="auth_provision_token_extracted")'
cat logs/dast_runs/<RUN_ID>/run_summary.json | jq '{_materialization_attempts, _materialization_successes, top_non_executable_tasks}'
```

Expected result if run-scoped identity uniqueness fixes the crAPI signup failure:

- signup returns `2xx`
- login returns `2xx`
- `auth_provision_token_extracted` appears
- `usable_identity_total > 0`
- `_materialization_attempts > 0`

If signup remains `500`, the next exact bottleneck is not field shape or duplicate run identity. The next diagnostic step should be to add a secret-safe response error classification for `/identity/api/auth/signup`, because current logs intentionally avoid response bodies and cannot distinguish crAPI validation error, duplicate user, backend mail/OTP failure, or another target-side exception.

---

## Previous run: run-80ca4001f549

## Artifacts inspected

- `logs/dast_runs/run-80ca4001f549/events.jsonl`
- `logs/dast_runs/run-80ca4001f549/run_summary.json`
- `logs/dast_runs/run-80ca4001f549/wrapper_events.jsonl`
- `logs/dast_runs/run-80ca4001f549/judge_events.jsonl`
- `backend/services/auth_preparation_service.py`
- `backend/services/evidence_builder_service.py`
- `backend/services/testing_service.py`
- `MIGRATION_NOTES.md`

## Short answer

The latest run did execute the current backend code with detailed auth attempt logging. The run produced no confirmed findings primarily because auth bootstrap never produced a usable identity, so authorization and object-dependent work stayed blocked by `missing_auth_context`. Object materialization never started. Schemathesis wrapper execution did happen, but the judge kept the resulting findings in `rework` because the evidence was not clean enough for confirmation under the current strict judge rules.

## Run summary

- Run ID: `run-80ca4001f549`
- Final stop reason: `all_class_budgets_exhausted`
- Generated tasks: `120`
- Runnable tasks at summary time: `17`
- Blocked tasks at summary time: `6`
- Pending tasks at summary time: `23`
- Materialization attempts: `0`
- Materialization successes: `0`
- Top non-executable reason: `missing_auth_context`
- Confirmed findings: `0`

## Did the latest auth logging code run?

Yes. The latest run contains the new per-attempt auth events:

- `auth_provision_register_attempt`: `56`
- `auth_provision_register_result`: `56`
- `auth_provision_login_attempt`: `56`
- `auth_provision_login_result`: `56`
- `auth_provision_token_extracted`: `0`

This means the run was not using an old backend image for the auth logging path. Older sibling run directories from the same timestamp do not contain the same evidence, but `run-80ca4001f549` is the relevant run because it has `run_summary.json`, wrapper events, and judge events.

## Auth bootstrap result

Auth bootstrap started and failed four times:

- `auth_provision_start`: `4`
- `auth_provision_failed`: `4`
- `usable_identity_total`: `0`
- `register_success_total`: `0`
- `login_success_total`: `0`
- stable failure reasons: `registration_failed`, `login_failed`

The actual attempted endpoints were visible:

- Register:
  - `POST /identity/api/auth/signup`
  - content type: `application/json`
  - request body keys: `email`, `name`, `number`, `password`
  - result: HTTP `500`
- Login:
  - `POST /identity/api/auth/login`
  - content type: `application/json`
  - request body keys: `email`, `password`
  - result: HTTP `401`
- Generic fallback endpoints:
  - `/api/register`, `/register`, `/signup`, `/api/login`, `/login`, `/signin`
  - result: HTTP `404`

No token/header/cookie extraction happened because no successful auth response was received.

## Likely auth root cause

The clear narrow code issue was in identity seed generation. The signup payload included `number`, but `_build_identity_seed` previously generated it from a UUID hex substring:

```text
555 + suffix[:7]
```

Because the suffix was hexadecimal, the phone/number value could contain letters `a-f`. For crAPI-style signup payloads, this is likely invalid and can explain the observed HTTP `500` from `/identity/api/auth/signup`. Since registration failed, login correctly returned `401`, no auth artifact was captured, and `usable_identity_total` stayed at `0`.

This conclusion is inferred from the logs plus the request body keys and code. The response body was not logged, so the exact crAPI-side validation error is not visible in artifacts.

## Minimal fix applied

`backend/services/auth_preparation_service.py` now generates a deterministic numeric phone suffix:

```text
phone_suffix = int(hex_suffix, 16) -> zero-padded decimal digits
number = 555 + phone_suffix
```

This keeps the payload deterministic but avoids non-numeric characters in the `number` field.

## Materialization status

Object materialization did not start:

- `_materialization_attempts`: `0`
- `_materialization_successes`: `0`
- materialization event count: `0`

Based on the run summary and events, this is downstream of auth bootstrap failure. Object-dependent authorization tasks stayed blocked by `missing_auth_context`, so the preparation flow never reached a usable owner identity for create/list materialization.

## Wrapper execution status

The wrapper path was live:

- `wrapper_dispatch_start`: `7`
- `tool_execution_start`: `7`
- `tool_subprocess_start`: `7`
- `tool_subprocess_completed`: `7`
- `evidence_build_finish`: `7`

Schemathesis returned partial normalized results with signals such as:

- `schema_violation`
- `server_error_signal`
- `unexpected_2xx`
- `5xx`

The evidence builder also emitted rate-abuse summaries, including bounded burst counts and no-429 observations.

## Why the judge did not confirm findings

The judge produced `rework` decisions, not confirmed findings.

For authorization tasks, the blocker was preparation failure:

- no usable `user_a` / `user_b`
- no captured token/header/cookie
- no materialized owned objects

For rate-abuse/business-logic tasks, the wrapper evidence was stronger than before but still mixed:

- bounded bursts saw repeated successes without HTTP `429`
- some runs also saw `5xx`
- client/server error counts were present

Under the current strict judge rules, `5xx` and mixed failures are not enough by themselves to confirm resource abuse. The judge asked for rework to clarify whether the behavior is true missing throttling, server instability, or target-specific validation behavior.

## Code/run mismatch assessment

No code/run mismatch was found for the auth logging path:

- repository code contains the per-attempt auth events
- `run-80ca4001f549/events.jsonl` contains those events

The latest run appears to reflect the current auth diagnostics. The next run is needed to verify the numeric `number` fix because the inspected run was produced before that fix.

## Verification after next run

Inspect the next run with:

```bash
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq -r 'select(.event_name | startswith("auth_provision"))'
cat logs/dast_runs/<RUN_ID>/run_summary.json | jq '{stop_reason, _materialization_attempts, _materialization_successes, top_non_executable_tasks}'
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq -r 'select(.event_name=="auth_provision_token_extracted")'
```

Expected improvement if the numeric phone fix is sufficient:

- `auth_provision_register_result` for `/identity/api/auth/signup` becomes `2xx`
- `auth_provision_login_result` for `/identity/api/auth/login` becomes `2xx`
- `auth_provision_token_extracted` appears
- `usable_identity_total` becomes greater than `0`
- `missing_auth_context` decreases
- `_materialization_attempts` becomes greater than `0`

If signup still returns `500`, the next diagnostic step is to inspect the redacted response metadata and compare the generated body keys against crAPI's exact signup schema and validation requirements.

## Latest scheduler failure: run-40ea606e08db

The Dify node `Schedule Next Tool Task (1)` reached maximum retries because the backend returned scheduler errors, not because Dify could not reach the backend.

Evidence from `logs/dast_runs/run-40ea606e08db`:

- `schedule_next_task_start`: `4`
- `schedule_next_task_finish`: `2`
- `schedule_next_task_error`: `2`
- error type: `RecursionError`
- message: `maximum recursion depth exceeded while calling a Python object`

So the edited backend code was live, and the endpoint was receiving Dify requests. The first two scheduler calls finished quickly:

- first selected `task_authorization_021`
- second selected `task_authorization_039`

Auth bootstrap also worked in this run:

- `auth_provision_token_extracted`: `2`
- `auth_provision_login_success`: `2`
- `usable_identity_total`: `2`

The remaining failure happened after queue update generated follow-up tasks. The scheduler then hit a recursion error while preparing the next task response.

Minimal fix applied:

- `update_queue_after_verdict` no longer re-simulates the full scheduler through `order_queue()` just to return pending tasks.
- scheduler hot paths now use a lightweight deterministic ordering for remaining tasks.
- task normalization / preparation now uses a bounded mutable copy instead of recursively deep-copying arbitrary task metadata.
- `schedule_next_task_error` now includes a bounded `traceback_preview` so any future scheduler 500 points to the exact file/line.

Verification after restarting the backend/toolbox:

```bash
cat logs/dast_runs/<RUN_ID>/events.jsonl | jq 'select(.event_name | startswith("schedule_next_task_"))'
cat logs/dast_runs/<RUN_ID>/run_summary.json | jq '{schedule_errors: .event_counts.schedule_next_task_error, schedule_finishes: .event_counts.schedule_next_task_finish, last_event_type, last_status}'
```

Expected result:

- `schedule_next_task_finish` continues increasing
- `schedule_next_task_error` stays absent or `0`
- no Dify retry failure on `POST /v1/schedule/next-task`
