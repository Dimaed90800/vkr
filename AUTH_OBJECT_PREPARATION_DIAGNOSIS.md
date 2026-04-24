# Auth/Object Preparation Diagnosis (run-564060d9947d)

## Why auth/object tasks were blocked

- Auth bootstrap did run, but produced `usable_identity_total=0`.
- Canonical signup failed with HTTP `500` (`duplicate key value violates unique constraint "user_login_pkey"` in safe preview).
- Canonical login then failed with HTTP `401` (`Given Email is not registered`).
- No `auth_provision_token_extracted` events appeared.
- Scheduler therefore kept many authorization/object tasks in `missing_auth_context`.
- Object materialization never started (`_materialization_attempts=0`, `_materialization_successes=0`).

## What changed in this pass

1. `backend/services/auth_preparation_service.py`
   - Added compatibility filtering for auth operations selected from OpenAPI:
     - skips token-only login endpoints for generic login bootstrap;
     - skips register endpoints requiring unsupported required fields (for example `mechanic_code`).
   - Extended auth payload generation to include schema/example variants (OpenAPI examples) in addition to generated identity payloads.

2. `backend/services/task_executability_service.py`
   - Materialization strategies now stay executable in preparation mode:
     - if owner auth is missing: preparation prefers `auto_provision`;
     - if owner auth exists and object id is missing: preparation prefers `create_test_object`.
   - Materialization strategies now explicitly add `object_id_missing` when no resolved object exists, even if prerequisites were under-specified.

## How to verify improvement in the next run

```bash
cat logs/dast_runs/<run_id>/run_summary.json | jq '{usable: .event_counts.auth_provision_token_extracted, missing_auth: .blocked_by_reason.missing_auth_context, mat_attempts: ._materialization_attempts, mat_successes: ._materialization_successes}'
```

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq -c 'select(.event_type=="auth_provision_register_result" or .event_type=="auth_provision_login_result") | {task_id, endpoint: .artifacts.endpoint, status_code: .artifacts.status_code, failure_reason: .reason.failure_reason, request_body_keys: .artifacts.request_body_keys}'
```

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq -c 'select(.event_type=="object_materialization_start" or .event_type=="object_materialization_finish" or .event_type=="object_materialization_failed") | {event: .event_type, task_id, status, reason: .reason.failure_reason, artifacts: .artifacts}'
```
