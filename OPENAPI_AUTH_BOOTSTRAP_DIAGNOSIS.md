# OpenAPI Auth Bootstrap Diagnosis

## Scope

This note traces why auth bootstrap (`auto_provision`) was selecting mostly fallback auth operations and producing fallback-heavy diagnostics, even when OpenAPI-derived surface existed upstream.

## Findings

1. Upstream OpenAPI existed for planning, but auth operation selection still appeared fallback-heavy.
2. In `backend/services/auth_preparation_service.py`, canonical operation discovery used:
   - `request.execution_context.openapi_spec_text` only
   - and did **not** resolve spec text via `openapi_url` in `_openapi_auth_operations` / `_openapi_auth_endpoints`.
3. The service already had `_spec_text_for_request()` that can fetch from:
   - `execution_context.openapi_spec_text`, or
   - `execution_context.openapi_url`,
   but canonical auth selection paths were not using it.
4. In Dify state update, when backend returned `updated_execution_context`, OpenAPI fields could be overwritten by an enrichment payload that omitted/emptied those fields.

## Where OpenAPI Was Lost (effective loss)

- Not at normalize input: initial `execution_context` had `openapi_url/openapi_spec_text` fields.
- Effective loss happened in auth prep selection logic:
  - canonical selection path ignored `openapi_url` resolution.
- Additional loss risk existed in loop state merge:
  - `updated_execution_context` replacement could discard existing OpenAPI fields.

## Fix Applied

1. Auth preparation now resolves canonical operations from `_spec_text_for_request()`:
   - `_openapi_auth_operations` and `_openapi_auth_endpoints` now use resolved spec text (URL or inline).
2. Canonical-first selection is bounded:
   - when OpenAPI operations are available, fallback expansion is skipped.
3. Dify state merge now preserves OpenAPI fields:
   - keeps prior `openapi_url/openapi_spec_text` if backend enrichment omits them.
4. Wrapper dispatch envelope now carries both:
   - `openapi_url`
   - `openapi_spec_text`

## New Diagnostics

- `auth_openapi_context_received` / `auth_openapi_context_missing`
- `auth_operation_selected`
- `auth_operation_selection_failed`
- `auth_provision_*_result` now includes `response_body_preview` (truncated, redacted)

## Expected Run Behavior After Fix

- Auth bootstrap should log OpenAPI context as received when URL/spec is available.
- Canonical auth operations should show `source=openapi`.
- Fallback 404 attempts should reduce when canonical register/login operations are present.
- If signup/login still fail, diagnostics should clearly show endpoint/method/content-type/status/preview.
