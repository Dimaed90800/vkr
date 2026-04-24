# Auth Bootstrap Diagnosis

## Scope

Diagnosis-only pass for the latest inspected run:

- Run ID: `run-f16b1f041240`
- Evidence files:
  - `logs/dast_runs/run-f16b1f041240/events.jsonl`
  - `logs/dast_runs/run-f16b1f041240/preparation_events.jsonl`
  - `logs/dast_runs/run-f16b1f041240/run_summary.json`

No code changes were made in this pass.

## Summary

Auth bootstrap did run and did not use broad fallback guesses for the observed preparation task.

The backend selected canonical OpenAPI-derived auth operations:

- register: `POST /identity/api/auth/signup`
- login: `POST /identity/api/auth/login`
- content type: `application/json`

Signup failed for both identities, but login later succeeded for both identities and produced usable auth artifacts:

- `auth_provision_token_extracted`: `2`
- `auth_provision_login_success`: `2`
- `usable_identity_total`: `2`
- `register_success_total`: `0`
- `login_success_total`: `2`

The latest run therefore does not support "auth extraction failed" or "auth profiles stayed unusable" as the primary blocker. The observed primary auth issue is that signup attempts are failing, while login succeeds against already-existing/generated identities.

Object materialization still did not record attempts:

- `_materialization_attempts`: `0`
- `_materialization_successes`: `0`
- no `object_materialization_*` events were present in the run

Based on this run, materialization is not blocked solely because auth bootstrap failed. Auth produced two usable identities. The next blocker is downstream of auth bootstrap: materialization tasks were generated/scheduled as follow-ups, but no actual object materialization tool execution was recorded before the scheduler exhausted budgets.

## OpenAPI Propagation

OpenAPI did reach auth bootstrap.

Evidence:

```json
{
  "event_name": "auth_openapi_context_received",
  "task_id": "task_authorization_041",
  "artifacts": {
    "has_openapi_spec_text": false,
    "has_openapi_url": true,
    "has_resolved_openapi_spec_text": true,
    "source_of_openapi_context": "execution_context.openapi_url"
  }
}
```

The auth operation selection also reported `source: "openapi"` and confidence `0.95` for both register and login operations.

## Canonical Auth Operations

### Signup / Register

Selected operation:

```json
{
  "endpoint": "/identity/api/auth/signup",
  "method": "POST",
  "content_type": "application/json",
  "request_body_keys": ["email", "name", "number", "password"],
  "required_fields": ["email", "name", "number", "password"],
  "source": "openapi",
  "confidence": 0.95
}
```

Runtime attempts:

| Identity | Endpoint | Method | Content-Type | Body Keys | Status | Failure |
|---|---|---:|---|---|---:|---|
| `user_a` | `/identity/api/auth/signup` | `POST` | `application/json` | `email`, `name`, `number`, `password` | `500` | `unexpected_status_code` |
| `user_a` | `/identity/api/auth/signup` | `POST` | `application/json` | `email`, `name`, `number`, `password` | `403` | `unexpected_status_code` |
| `user_b` | `/identity/api/auth/signup` | `POST` | `application/json` | `email`, `name`, `number`, `password` | `500` | `unexpected_status_code` |
| `user_b` | `/identity/api/auth/signup` | `POST` | `application/json` | `email`, `name`, `number`, `password` | `403` | `unexpected_status_code` |

Response previews:

- `500`: `duplicate key value violates unique constraint "user_login_pkey"` with key ids `496` / `497`
- `403`: `{"message":"Number already registered! Number: 6915656974","status":403}`

Interpretation from logs:

- Endpoint, method, content type, and body key set match the OpenAPI-selected operation.
- Signup is failing at the target application/database layer.
- The repeated `Number already registered! Number: 6915656974` indicates the generated signup payloads are not using sufficiently unique phone/number values for every attempt, or a fallback payload variant is reusing a fixed number.
- The `duplicate key value violates unique constraint "user_login_pkey"` looks like target-side database state/id sequence corruption or a crAPI-specific failure mode; the logs do not show raw request values, so this cannot be fully proven from current artifacts.

## Login

Selected operation:

```json
{
  "endpoint": "/identity/api/auth/login",
  "method": "POST",
  "content_type": "application/json",
  "request_body_keys": ["email", "password"],
  "required_fields": ["email", "password"],
  "source": "openapi",
  "confidence": 0.95
}
```

Runtime attempts:

| Identity | Endpoint | Method | Content-Type | Body Keys | Status | Extraction |
|---|---|---:|---|---|---:|---|
| `user_a` | `/identity/api/auth/login` | `POST` | `application/json` | `email`, `password` | `401` | body: false, cookie: true, header: false |
| `user_a` | `/identity/api/auth/login` | `POST` | `application/json` | `email`, `password` | `200` | body: true, cookie: true, header: false |
| `user_b` | `/identity/api/auth/login` | `POST` | `application/json` | `email`, `password` | `401` | body: false, cookie: true, header: false |
| `user_b` | `/identity/api/auth/login` | `POST` | `application/json` | `email`, `password` | `200` | body: true, cookie: true, header: false |

Response previews:

- failed login: `{"token":null,"type":"","message":"Given Email is not registered! ","mfaRequired":false}`
- successful login: `{"token":"***REDACTED***","type":"Bearer","message":"Login successful","mfaRequired":false}`

Interpretation from logs:

- Login endpoint/method/content-type/body keys match the OpenAPI-selected operation.
- Token extraction from JSON body works.
- Cookie extraction also sees auth-like cookie material.
- Header extraction is false in this run, but that is not a blocker because body token extraction succeeded.

## Auth Extraction And Persistence

Token extraction happened for both identities:

```json
{
  "event_name": "auth_provision_token_extracted",
  "status": "success",
  "artifacts": {
    "auth_extraction": {
      "from_body": true,
      "from_cookie": "***REDACTED***",
      "from_header": false
    },
    "status_code": 200
  }
}
```

Auth provisioning finished successfully:

```json
{
  "event_name": "auth_provision_finish",
  "status": "success",
  "counters": {
    "identity_count": 2,
    "login_success_total": 2,
    "register_success_total": 0,
    "usable_identity_total": 2
  },
  "reason": {
    "failure_reasons": ["registration_failed"]
  }
}
```

Provisioned roles persisted in the auth preparation result:

```json
[
  {
    "name": "user_a",
    "role": "user_a",
    "aliases": ["user_a", "auto_023bfbee87_a", "auto_023bfbee87_a@example.test"],
    "auth_material": {
      "has_auth_headers": true,
      "has_cookies": "***REDACTED***",
      "has_token": "***REDACTED***"
    }
  },
  {
    "name": "user_b",
    "role": "user_b",
    "aliases": ["user_b", "auto_dc45331ad9_b", "auto_dc45331ad9_b@example.test"],
    "auth_material": {
      "has_auth_headers": true,
      "has_cookies": "***REDACTED***",
      "has_token": "***REDACTED***"
    }
  }
]
```

The service code also returns these identities as both:

- `Artifact(type="provisioned_identities", value=provisioned)`
- `Artifact(type="auth_profiles", value=provisioned)`

TestingService role lookup consumes role profiles by:

- `name`
- `role`
- `username`
- `email`
- `owner_role`
- `other_role`
- `label`
- `aliases`

Therefore, based on the latest logs and current lookup code, auth extraction and profile indexing appear to be working for `user_a` and `user_b`.

## Materialization Status

Materialization did not start in this run:

- `_materialization_attempts`: `0`
- `_materialization_successes`: `0`
- no `object_materialization_start`
- no `object_materialization_failed`
- no `object_materialization_finish`

This is not explained by auth bootstrap failure, because auth bootstrap produced usable identities.

Scheduler logs show object/materialization-related follow-up strategy keys and generated follow-up tasks, for example:

- `task_authorization_021__create_object_then_replay_1`
- `task_authorization_041__create_object_then_replay_1`
- strategy retry keys containing `object_materialization`

But the preparation tool itself did not emit object materialization events. That points to a downstream dispatch/scheduling/budget issue for materialization tasks, not to missing auth material.

## Direct Answers

1. Did auth bootstrap attempt signup and login?
   - Yes. Four signup attempts and four login attempts were logged.

2. Signup endpoint/method/content type?
   - `POST /identity/api/auth/signup`, `application/json`, selected from OpenAPI.

3. Login endpoint/method/content type?
   - `POST /identity/api/auth/login`, `application/json`, selected from OpenAPI.

4. Request body keys?
   - signup: `email`, `name`, `number`, `password`
   - login: `email`, `password`

5. Status codes?
   - signup: `500`, `403`, `500`, `403`
   - login: `401`, `200`, `401`, `200`

6. Token/header/cookie in responses?
   - token from body: yes, on both successful login responses
   - cookie-like auth material: yes, logged as redacted
   - auth header: no, but not required because body token was extracted

7. Were auth artifacts discarded or not persisted?
   - No evidence of discard in auth preparation. The finish event includes two provisioned roles with token/header/cookie material. The service returns them as `provisioned_identities` and `auth_profiles`.

8. Is OpenAPI reaching auth bootstrap?
   - Yes. `auth_openapi_context_received` says `has_openapi_url=true`, `has_resolved_openapi_spec_text=true`, source `execution_context.openapi_url`.

9. Is signup failing because of bad field mapping or required-field handling?
   - Not proven from logs. Body keys match OpenAPI required fields. However, the `403 Number already registered! Number: 6915656974` strongly suggests the generated value for `number` is being reused in at least one payload variant.

10. Is login failing because signup never succeeded, or because login payload/extraction is wrong?
   - The first login attempt for each identity failed with `Given Email is not registered`, consistent with failed signup or a bad generated identity variant. The second login attempt for each identity succeeded and token extraction worked. Login payload/extraction are therefore not globally broken.

## Current Root Cause Assessment

The strongest evidence-based conclusion:

- Auth endpoint selection is correct.
- OpenAPI propagation is working.
- Login request shape and token extraction are working.
- Auth profile persistence from the auth preparation result is working.
- Signup is unhealthy or partially malformed at the value level, not the key/method/content-type level.
- Materialization remains blocked downstream of auth bootstrap, because auth identities exist but no object materialization execution events were emitted.

Potential narrow fix candidates for a later pass, after this diagnosis:

1. Ensure every signup payload variant uses a unique `number` value, not the repeated `6915656974`.
2. Prefer login of known seeded crAPI users before attempting signup if signup returns crAPI database/id-sequence errors.
3. Trace why generated materialization follow-up tasks do not invoke `create_test_object` despite usable auth profiles.
