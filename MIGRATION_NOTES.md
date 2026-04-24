# Tool-aware Worker Migration Notes

## What Changed

- Added a normalized backend wrapper layer at `POST /v1/tools/wrappers/execute`.
- Added wrapper result and judge-ready evidence models.
- Added wrapper scaffolds for RESTler, CATS, Akto, and OWASP ASTF command names, plus real Schemathesis execution.
- Extended planner tasks with `worker_role`, `preferred_tool`, `fallback_tools`, `artifact_requirements`, `budget_profile`, and `tool_preference`.
- Updated the Dify DSL dispatcher to route wrapper commands to `/v1/tools/wrappers/execute` while preserving legacy tool endpoints.
- Updated `schema.html` to show intake, graph planner, tool-aware agents, executor tools, evidence store, judge loop, and reporter.
- Wired Schemathesis into the toolbox runtime via `backend/requirements.txt`.

## Repository Inspection Map

- Current backend tool endpoints: `backend/api/routes_tests.py`; new wrapper endpoint: `backend/api/routes_tool_wrappers.py`.
- Worker tool parsing / routing in Dify: `parse_worker_command` node in `dify/wf-multiagent-dast-multiworker.yml`.
- Backend task planning / dispatch: `backend/services/task_planner.py`, `backend/services/task_generator.py`, `backend/api/routes_planning.py`.
- Legacy evidence building in Dify: `build_evidence` node in `dify/wf-multiagent-dast-multiworker.yml`.
- Normalized wrapper evidence builder: `backend/services/evidence_builder_service.py`.
- Judge input / loop in DSL: `build_evidence`, Judge LLM, `parse_judge_verdict`, and `update_queue` nodes in `dify/wf-multiagent-dast-multiworker.yml`.
- HTML architecture schema: `schema.html`.
- Container setup: `docker-compose.yml` currently includes toolbox, ZAP, Playwright runner, mitmproxy, and demo targets.

## Legacy Logic Still In Use

- Internal task classes remain `authorization`, `injection`, and `business_logic` for compatibility.
- Legacy backend tools such as `auth_test_access`, `injection_test`, `logic_test`, `data_exposure_test`, and `resource_abuse_test` remain available.
- Existing judge loop semantics are preserved: evidence is built first, then Judge confirms, rejects, or requests rework.
- Dify keeps legacy evidence building for legacy tools, but uses `judge_ready_evidence` directly when wrapper output includes it.

## Live Schemathesis Path

The first real wrapper path is:

`planner -> preferred_tool=schemathesis_negative_test -> Dify Contract & Negative Testing Agent -> parse_worker_command -> /v1/tools/wrappers/execute -> ToolWrapperService -> Schemathesis CLI -> normalized wrapper result -> EvidenceBuilderService -> judge_ready_evidence -> Dify build_evidence -> Judge`

Wrapper-first behavior is explicit for Schemathesis tasks. If an active task has `preferred_tool` set to `schemathesis_negative_test` or `schemathesis_stateful_test`, and that tool is present in `allowed_tools`, the Dify dispatcher overrides a legacy worker selection and records a `wrapper_first_override` dispatch note. Legacy fallback is therefore no longer silent for Schemathesis-preferred tasks.

Judge compatibility is preserved because `build_evidence` checks for `judge_ready_evidence` first. If it exists, that normalized package is passed to the judge path. If it does not exist, the old evidence builder still handles legacy tool responses.

### Schemathesis Dispatch Mismatch Fix

Schemathesis was not firing because some active tasks had `preferred_tool=schemathesis_stateful_test` while `allowed_tools` still contained only legacy entries such as `logic_test`. The Dify parser validated the worker output against legacy `allowed_tools`, rejected the payload, and fell back to `noop_outcome` before the wrapper-first override could run.

Current normalization behavior:

- Backend task generation merges `preferred_tool` and `fallback_tools` into `allowed_tools`.
- Business-flow ready-to-test tasks include `schemathesis_stateful_test`, `restler_fuzz`, `akto_authz_scan`, and `logic_test`.
- Contract/negative ready-to-test tasks include `schemathesis_negative_test`, `cats_fuzz_test`, `astf_top10_suite`, and `injection_test`.
- Auth ready-to-test tasks include `akto_authz_scan`, `astf_top10_suite`, and `auth_test_access`.
- Dify `parse_worker_command` builds normalized allowed tools from `allowed_tools + preferred_tool + fallback_tools`.
- If a worker payload is invalid but the active task has `preferred_tool=schemathesis_negative_test` or `schemathesis_stateful_test`, the parser routes to the preferred wrapper instead of `noop_outcome` and records `wrapper_first_rescue`.

Verify after rerun:

```bash
jq 'select(.event_type=="wrapper_dispatch_start")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.trace_context.tool_name=="schemathesis_stateful_test" or .trace_context.tool_name=="schemathesis_negative_test")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="tool_execution_start")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="tool_subprocess_start")' logs/dast_runs/<run_id>/events.jsonl
```

## Live RESTler Wrapper Contract

The second wrapper path is:

`planner -> preferred_tool=restler_fuzz/restler_compile/restler_replay -> Dify Business Flow / Stateful Agent -> parse_worker_command -> /v1/tools/wrappers/execute -> ToolWrapperService -> RESTler scaffold artifacts -> normalized wrapper result -> EvidenceBuilderService -> judge_ready_evidence -> Dify build_evidence -> Judge`

RESTler commands currently implemented:

- `restler_compile`
- `restler_fuzz`
- `restler_replay`

Current live behavior is a deterministic scaffold, not a real RESTler subprocess. The wrapper creates RESTler-oriented artifact directories and replay metadata, then returns normalized `partial` output with `termination_reason=tool_unavailable` until a RESTler runtime is configured.

Wrapper-first behavior is explicit for RESTler tasks. If `preferred_tool` is one of `restler_compile`, `restler_fuzz`, or `restler_replay`, and that command is present in `allowed_tools`, the Dify dispatcher overrides a legacy worker selection and records a `wrapper_first_override` dispatch note.

## Tool Status

- Schemathesis: real CLI execution for `schemathesis_negative_test`; `schemathesis_stateful_test` is routed through Schemathesis with broader generation mode.
- RESTler: live normalized wrapper contract and deterministic compile/fuzz/replay scaffold; real CLI/container execution is not wired yet.
- CATS: scaffold only.
- Akto: scaffold only.
- OWASP ASTF: scaffold only.

## Missing External Dependencies

- RESTler CLI/container is not configured in `docker-compose.yml`. Expected future runtime input is either `RESTLER_BIN` or `RESTLER_DOCKER_IMAGE`.
- CATS CLI/container is not configured in `docker-compose.yml`.
- Akto service/container is not configured in `docker-compose.yml`.
- OWASP ASTF runner/container is not configured in `docker-compose.yml`.

## Schemathesis Smoke Path

After installing backend requirements locally, run:

```bash
python scripts/smoke_schemathesis_wrapper.py
```

Or run it inside the rebuilt toolbox image:

```bash
docker compose build toolbox
docker compose run --rm toolbox python scripts/smoke_schemathesis_wrapper.py
```

The script starts a local OpenAPI target, calls `POST /v1/tools/wrappers/execute` through the FastAPI app, executes `schemathesis_negative_test`, and prints the normalized wrapper result plus `judge_ready_evidence`.

Expected high-level result:

- `tool_name`: `schemathesis_negative_test`
- `schema_version`: `tool-wrapper-result/v1`
- `judge_ready_evidence.schema_version`: `judge-ready-evidence/v1`

## Schemathesis Judge Evidence Hardening

Earlier live Schemathesis runs reached `evidence_build_finish`, but the judge often saw only generic wrapper signals such as `negative_test_completed` or `partial`. That was not enough for the conservative judge rules to confirm or cleanly reject rate/resource-abuse hypotheses, so many outcomes became generic rework/partial decisions.

The evidence builder now enriches Schemathesis-derived wrapper results before they enter the judge path. It reads bounded `stdout.log` / `stderr.log` artifacts, preserves the original wrapper signals, and adds concrete normalized indicators only when supported by the wrapper output.

New Schemathesis indicators include:

- `no_rate_limit_detected`
- `rate_limit_detected`
- `repeated_success_without_throttle`
- `repeated_429_detected`
- `schema_violation`
- `server_error_signal`
- `workflow_state_bypass`
- `invalid_transition_accepted`
- `cross_role_workflow_access`
- `repeated_sensitive_action_allowed`
- `invariant_violation`

Judge-ready evidence now also includes a compact `tool_summary` block:

```json
{
  "tool_summary": {
    "tool_name": "schemathesis_stateful_test",
    "operation_count": 1,
    "success_count": 3,
    "client_error_count": 0,
    "server_error_count": 0,
    "saw_429": false,
    "saw_5xx": false,
    "rate_limit_response_count": 0,
    "bounded_burst_count": 3,
    "request_count": 3,
    "error_count": 0,
    "operations": [
      {
        "method": "POST",
        "endpoint": "/api/orders",
        "url": "http://target/api/orders"
      }
    ]
  }
}
```

For rate-abuse tasks, `no_rate_limit_detected` is emitted only when a bounded burst has repeated successful responses and no `429` signal was observed. Workflow indicators are emitted only from explicit workflow/state/invariant phrases in the tool output, not from generic `200` responses.

Structured `evidence_build_finish` logs now include:

- `derived_signals`
- `evidence_strength`
- `strong_indicators`
- `tool_summary`

Verify the judge input after a run:

```bash
jq 'select(.event_type=="evidence_build_finish") | {tool: .trace_context.tool_name, derived: .extra.derived_signals, strength: .extra.evidence_strength, summary: .extra.tool_summary}' logs/dast_runs/<run_id>/events.jsonl
```

## Final Stop Reason Resolution

The final report previously could say `timeout` while the scheduler run summary said `all_class_budgets_exhausted`. The mismatch came from two sources of truth: the dispatcher could set a local transient `timeout`, while the scheduler later selected a more specific final stop reason. The reporter consumed `state.stop_reason` directly.

The Dify dispatcher now records scheduler stop context and resolves a final stop reason before emitting the final no-task state. The reporter context consumes the resolved value, and includes `stop_reason_resolution` for inspection:

```json
{
  "stop_reason": "all_class_budgets_exhausted",
  "stop_reason_resolution": {
    "raw_state_stop_reason": "timeout",
    "scheduler_selection_reason": "all_class_budgets_exhausted",
    "transient_stop_reason": "",
    "soft_stop_fallback_used": false,
    "resolved_final_stop_reason": "all_class_budgets_exhausted"
  }
}
```

The reporter also emits a diagnostic `final_stop_reason_resolved` event so one run can show how the final value was chosen. If timeout is truly the final reason and no later scheduler reason exists, the resolved final reason remains `timeout`.

## Auth Bootstrap And Materialization Hardening

The latest bottleneck was not wrapper dispatch. Schemathesis and legacy preparation paths were reachable, but tasks still stalled because auth bootstrap did not reliably produce two reusable identities and object materialization rarely got a usable owner identity.

Auth `auto_provision` now selects register/login operations from OpenAPI first. For each auth candidate it records:

- actual HTTP method
- supported request content type
- request body keys
- required request body keys
- whether the operation came from OpenAPI, explicit input, discovered endpoints, or fallback path guessing

Fallback path guessing is still present, but OpenAPI-derived operations are ranked first.

Register/login request bodies are now schema-aware. The bootstrapper maps common auth aliases only when compatible with the operation schema:

- `email`
- `username`
- `name`
- `password`
- `firstName`
- `lastName`
- `fullName`
- `role`

If OpenAPI marks fields as required, the request body is the smallest deterministic body that satisfies those required fields. Unsupported fields are not added to schema-grounded payloads.

Auth `auto_provision` treats an identity as provisioned only when it has reusable auth material:

- bearer token
- auth headers
- session cookies

It extracts usable auth from:

- JSON body keys: `token`, `access_token`, `jwt`, `authToken`, nested `data.*`, nested `result.*`, and equivalent nested token fields.
- Response headers: `Authorization`, `X-Auth-Token`.
- Cookies from `Set-Cookie`.

It also normalizes aliases so `user_a` and `user_b` can be matched through `name`, `role`, `alias`, `username`, `email`, `owner_role`, or `other_role`. Successful identities are returned in both `provisioned_identities` and `auth_profiles`, so the existing Dify and scheduler context merge paths can reuse them across the run.

Expected auth bootstrap events:

- `auth_provision_start`
- `auth_provision_register_attempt`
- `auth_provision_register_result`
- `auth_provision_identity_created`
- `auth_provision_login_attempt`
- `auth_provision_login_result`
- `auth_provision_token_extracted`
- `auth_provision_login_success`
- `auth_provision_finish`
- `auth_provision_failed`

Stable auth failure reasons:

- `no_register_endpoint`
- `no_login_endpoint`
- `registration_failed`
- `login_failed`
- `token_missing`

Object materialization now emits explicit start/selection/success/failure events while preserving legacy preparation behavior:

- `object_materialization_start`
- `object_materialization_creator_selected`
- `object_materialization_create_success`
- `object_materialization_list_success`
- `object_materialization_id_harvested`
- `object_materialization_finish`
- `object_materialization_failed`

Stable object materialization failure reasons:

- `no_creator_candidate`
- `no_list_candidate`
- `create_failed`
- `id_not_harvested`
- `object_not_reusable`

Verify auth bootstrap happened:

```bash
jq 'select(.event_type | startswith("auth_provision_")) | {event: .event_type, status, reason, counters, artifacts}' logs/dast_runs/<run_id>/events.jsonl
```

Check that request bodies are schema-compatible without exposing secrets:

```bash
jq 'select(.event_type=="auth_provision_register_attempt" or .event_type=="auth_provision_login_attempt") | {event: .event_type, endpoint: .artifacts.endpoint, method: .artifacts.method, content_type: .artifacts.content_type, request_body_keys: .artifacts.request_body_keys}' logs/dast_runs/<run_id>/events.jsonl
```

Every attempted register/login operation now emits an `*_attempt` event before URL validation and HTTP execution, and an `*_result` event after any outcome. Non-2xx responses, request construction errors, execution errors, and token extraction errors are converted into structured result events instead of only surfacing as aggregate `auth_provision_failed`.

Useful failure details in per-attempt logs:

- `unsupported_content_type`
- `invalid_required_fields`
- `unexpected_status_code`
- `request_construction_failed`
- `request_execution_failed`
- `token_extraction_failed`

Check where auth was extracted from:

```bash
jq 'select(.event_type=="auth_provision_token_extracted" or .event_type=="auth_provision_login_result") | {event: .event_type, status, extraction: .artifacts.auth_extraction, reason: .reason}' logs/dast_runs/<run_id>/events.jsonl
```

Verify `missing_auth_context` should drop:

```bash
jq '.top_dead_end_reasons.missing_auth_context // 0' logs/dast_runs/<run_id>/summary.json
jq '.has_multi_role_auth // empty' logs/dast_runs/<run_id>/summary.json
```

Verify materialization started and succeeded:

```bash
jq '._materialization_attempts, ._materialization_successes, .object_materialization_success_rate' logs/dast_runs/<run_id>/summary.json
jq 'select(.event_type | startswith("object_materialization_")) | {event: .event_type, status, reason, counters, artifacts}' logs/dast_runs/<run_id>/events.jsonl
```

## Auth/Object Bottleneck Tightening (Current Pass)

This pass stayed scoped to auth bootstrap reliability + object-materialization start conditions.

### Why tasks were stalling

- The latest real run (`run-564060d9947d`) had OpenAPI-aware auth selection and per-attempt logs, but still no usable identities:
  - canonical signup: HTTP 500 duplicate-key error
  - canonical login: HTTP 401 not registered
  - `auth_provision_token_extracted=0`
- Object follow-up tasks then remained blocked by `missing_auth_context`.
- `_materialization_attempts` / `_materialization_successes` stayed `0`.

### What changed

1. `backend/services/auth_preparation_service.py`
   - OpenAPI auth operation selection now applies compatibility filtering:
     - generic bootstrap skips token-only login operations
     - generic bootstrap skips register operations with unsupported required fields (for example `mechanic_code`)
   - Auth payload generation now supports multiple schema-aware variants, including OpenAPI example-derived payloads when available.

2. `backend/services/task_executability_service.py`
   - Materialization strategies no longer dead-end as bare `missing_auth_context`.
   - If owner auth is missing: preparation prefers `auto_provision`.
   - If owner auth exists but object id is missing: preparation prefers `create_test_object`.
   - Materialization strategies now explicitly add `object_id_missing` when unresolved.

### Expected log signals after rerun

- Fewer `invalid_required_fields` auth failures.
- If OpenAPI includes valid login examples: `auth_provision_token_extracted > 0`.
- Object-preparation tasks should be routed into preparation tools instead of stalling:
  - `dispatch_preparation_path_selected` with `delegated_tool=auto_provision` or `create_test_object`
  - `object_materialization_start` events appearing when owner auth is available
- Run summary should move off zero materialization metrics on supported targets:
  - `_materialization_attempts > 0`
  - `_materialization_successes > 0`

## Schedule Endpoint Hardening

After auth bootstrap began producing usable identities, Dify hit max retries on `POST /v1/schedule/next-task`. The run showed that the scheduler request emitted executability diagnostics but did not reach the next `scheduler_selection`.

The schedule endpoint now emits API-level events:

- `schedule_next_task_start`
- `schedule_next_task_finish`
- `schedule_next_task_error`

`TaskScheduler.select_next_task` also no longer calls full `order_queue()` just to return `remaining_tasks`. That repeated full queue evaluation inside a single HTTP request and made the Dify scheduling node fragile. The response now uses a lightweight deterministic sort for remaining tasks; the next loop iteration still performs normal executability checks before selecting a task.

Verify:

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_type=="schedule_next_task_start" or .event_type=="schedule_next_task_finish" or .event_type=="schedule_next_task_error")'
```

Rate-abuse evidence now emits explicit structured events in addition to `evidence_build_finish`:

- `rate_abuse_signal_derivation`
- `evidence_strength_assessed`

Verify the judge receives concrete rate-abuse evidence:

```bash
jq 'select(.event_type=="rate_abuse_signal_derivation" or .event_type=="evidence_strength_assessed") | {event: .event_type, tool: .trace_context.tool_name, extra}' logs/dast_runs/<run_id>/events.jsonl
```
- signals include at least one Schemathesis-derived signal such as `5xx`, `schema_violation`, or `negative_test_completed`
- artifacts include deterministic `stdout.log`, `stderr.log`, and `replay_pack.json`

Failure-mode smoke scenarios:

```bash
python scripts/smoke_schemathesis_wrapper.py missing-openapi
python scripts/smoke_schemathesis_wrapper.py missing-cli
```

Both should return HTTP 200 from the wrapper endpoint with a normalized `partial` result and a non-empty `fallback_reason`.

Expected failure distinctions:

- `missing-openapi`: `termination_reason=missing_openapi`, signals include `openapi_missing`.
- `missing-cli`: `termination_reason=tool_unavailable`, signals include `tool_unavailable`.

## RESTler Smoke Path

Run the RESTler wrapper contract smoke path:

```bash
python scripts/smoke_restler_wrapper.py
```

Or inside the rebuilt toolbox image:

```bash
docker compose build toolbox
docker compose run --rm toolbox python scripts/smoke_restler_wrapper.py
```

Expected high-level result:

- `tool_name`: `restler_fuzz`
- `schema_version`: `tool-wrapper-result/v1`
- `status`: `partial`
- `termination_reason`: `tool_unavailable`
- signals include `wrapper_scaffold_ready` and `stateful_sequence_fuzzing_planned`
- artifacts include deterministic `stdout.log`, `stderr.log`, `replay_pack.json`, and RESTler scaffold files under `restler/`
- `judge_ready_evidence.schema_version`: `judge-ready-evidence/v1`

Sample normalized RESTler output:

```json
{
  "tool_name": "restler_fuzz",
  "status": "partial",
  "result": {
    "schema_version": "tool-wrapper-result/v1",
    "tool_name": "restler_fuzz",
    "source_task_id": "task_restler_smoke_001",
    "worker_role": "Business Flow / Stateful Agent",
    "status": "partial",
    "summary": "restler_fuzz scaffold prepared. RESTler CLI/container execution is not wired in this environment.",
    "signals": [
      "wrapper_scaffold_ready",
      "tool_unavailable",
      "restler_fuzz_scaffold_ready",
      "stateful_sequence_fuzzing_planned"
    ],
    "artifacts": {
      "stdout_path": ".../stdout.log",
      "stderr_path": ".../stderr.log",
      "raw_report_paths": [
        ".../restler/restler_wrapper_config.json",
        ".../restler/Compile/grammar.py",
        ".../restler/Compile/dict.json",
        ".../restler/Replay/replay_sequence.json"
      ],
      "replay_pack_path": ".../replay_pack.json"
    },
    "budget": {
      "max_requests": 4,
      "used_requests": 0,
      "duration_sec": 0.02,
      "max_duration_sec": 20,
      "concurrency": 1,
      "termination_reason": "tool_unavailable"
    },
    "termination_reason": "tool_unavailable",
    "fallback_reason": "restler_fuzz scaffold prepared. RESTler CLI/container execution is not wired in this environment.",
    "error": "restler_runtime_unavailable"
  }
}
```

## Direct Wrapper Request

Minimal request payload for `POST /v1/tools/wrappers/execute`:

```json
{
  "tool_name": "schemathesis_negative_test",
  "run_id": "run-schemathesis-smoke",
  "target_url": "http://127.0.0.1:8001",
  "openapi_url": "http://127.0.0.1:8001/openapi.json",
  "execution_context": {
    "target_url": "http://127.0.0.1:8001",
    "openapi_url": "http://127.0.0.1:8001/openapi.json",
    "allowed_hosts": ["127.0.0.1:8001"],
    "max_requests": 3,
    "max_duration_sec": 30
  },
  "task": {
    "id": "task_schemathesis_smoke_001",
    "class": "injection",
    "subtype": "schema_negative_test",
    "endpoint": "/items",
    "method": "POST",
    "hypothesis": "Invalid request bodies should not trigger 5xx responses.",
    "allowed_tools": ["schemathesis_negative_test", "injection_test"],
    "worker_role": "Contract & Negative Testing Agent",
    "preferred_tool": "schemathesis_negative_test"
  },
  "task_metadata": {
    "worker_role": "Contract & Negative Testing Agent"
  },
  "budgets": {
    "max_requests": 3,
    "max_duration_sec": 30,
    "concurrency": 1
  },
  "arguments": {
    "max_examples": 3
  },
  "output_dir": "/tmp/schemathesis-wrapper-smoke"
}
```

Sample normalized wrapper output shape:

```json
{
  "tool_name": "schemathesis_negative_test",
  "status": "partial",
  "result": {
    "schema_version": "tool-wrapper-result/v1",
    "tool_name": "schemathesis_negative_test",
    "source_task_id": "task_schemathesis_smoke_001",
    "worker_role": "Contract & Negative Testing Agent",
    "auth_context_name": null,
    "status": "partial",
    "summary": "Schemathesis finished with exit code 1.",
    "signals": ["5xx", "schema_violation"],
    "http_trace_refs": [],
    "artifacts": {
      "stdout_path": "/tmp/schemathesis-wrapper-smoke/run-schemathesis-smoke/schemathesis_negative_test/task_schemathesis_smoke_001/stdout.log",
      "stderr_path": "/tmp/schemathesis-wrapper-smoke/run-schemathesis-smoke/schemathesis_negative_test/task_schemathesis_smoke_001/stderr.log",
      "raw_report_paths": [],
      "replay_pack_path": "/tmp/schemathesis-wrapper-smoke/run-schemathesis-smoke/schemathesis_negative_test/task_schemathesis_smoke_001/replay_pack.json"
    },
    "candidate_findings": [],
    "reproduction": {
      "method": "POST",
      "url": "http://127.0.0.1:8001/items",
      "headers": {},
      "body": null
    },
    "budget": {
      "max_requests": 3,
      "used_requests": 3,
      "duration_sec": 1.25,
      "max_duration_sec": 30,
      "concurrency": 1,
      "termination_reason": "tool_reported_findings"
    },
    "termination_reason": "tool_reported_findings",
    "fallback_reason": null,
    "error": "schemathesis_reported_failures"
  }
}
```

Sample `judge_ready_evidence`:

```json
{
  "schema_version": "judge-ready-evidence/v1",
  "task_id": "task_schemathesis_smoke_001",
  "source_task_id": "task_schemathesis_smoke_001",
  "worker_role": "Contract & Negative Testing Agent",
  "tool_name": "schemathesis_negative_test",
  "auth_context_name": null,
  "hypothesis": "Invalid request bodies should not trigger 5xx responses.",
  "signals": ["5xx", "schema_violation"],
  "candidate_finding": {},
  "reproduction": {
    "method": "POST",
    "url": "http://127.0.0.1:8001/items",
    "headers": {},
    "body": null
  },
  "artifacts": {
    "stdout_path": ".../stdout.log",
    "stderr_path": ".../stderr.log",
    "raw_report_paths": [],
    "replay_pack_path": ".../replay_pack.json"
  },
  "budget": {
    "max_requests": 3,
    "used_requests": 3,
    "duration_sec": 1.25,
    "max_duration_sec": 30,
    "concurrency": 1,
    "termination_reason": "tool_reported_findings"
  },
  "termination_reason": "tool_reported_findings",
  "notes": ["wrapper_normalized_result"]
}
```

## Replay Pack

Artifacts are deterministic per `run_id/tool_name/task_id`:

`<output_dir>/<run_id>/<tool_name>/<task_id>/replay_pack.json`

The replay pack includes:

- `schema_version`: `replay-pack/v1`
- `tool_name`, `engine`, `run_id`, `source_task_id`, `worker_role`, `auth_context_name`
- `target_url`, `openapi_ref`, and `allowed_hosts`
- the original task payload
- sanitized reproduction metadata
- budget limits
- the Schemathesis command preview
- a `replay` block with deterministic replay strategy, CLI command, and request template
- stdout/stderr/replay artifact paths

For RESTler wrappers, the replay block uses `strategy=restler_sequence_replay` and includes sequence artifact hints:

```json
{
  "replay": {
    "strategy": "restler_sequence_replay",
    "cli_command": ["restler", "fuzz", "--grammar_file", "Compile/grammar.py", "--target_ip", "http://127.0.0.1:8001"],
    "sequence_artifacts": {
      "compile_dir": "restler/Compile",
      "results_dir": "restler/RestlerResults",
      "replay_sequence_path": "restler/Replay/replay_sequence.json"
    }
  }
}
```

Example replay block:

```json
{
  "replay": {
    "strategy": "deterministic_tool_replay",
    "cli_command": [
      "schemathesis",
      "--no-color",
      "run",
      "http://127.0.0.1:8001/openapi.json",
      "--url",
      "http://127.0.0.1:8001",
      "--mode",
      "negative",
      "--max-examples",
      "3",
      "--generation-deterministic",
      "--continue-on-failure"
    ],
    "request_template": {
      "method": "POST",
      "url": "http://127.0.0.1:8001/items",
      "headers": {},
      "body": null
    },
    "notes": [
      "Schemathesis runs with deterministic generation; rerun cli_command against the same API state to reproduce generated cases.",
      "Tool stdout/stderr may include the exact minimized failing case when Schemathesis reports one."
    ]
  }
}
```

## Troubleshooting

- Missing Schemathesis CLI: rebuild the toolbox image or install backend requirements. The wrapper should return `status=partial`, `termination_reason=tool_unavailable`, signals containing `tool_unavailable`, and a `fallback_reason`.
- Missing OpenAPI ref: include `openapi_url`, `openapi_spec_path`, or `execution_context.openapi_url`. The wrapper should return `status=partial`, `termination_reason=missing_openapi`, signals containing `openapi_missing`, and a `fallback_reason`.
- Scope rejection: make sure the target host appears in `execution_context.allowed_hosts`; otherwise the wrapper returns a normalized `error`.
- No judge evidence in Dify: confirm the execute HTTP node sends a JSON object body and `build_evidence` receives the wrapper endpoint response body.
- Unexpected legacy execution: inspect `parse_worker_command.reasoning_summary` for `wrapper_first_override`. For Schemathesis-preferred tasks, Dify should choose the preferred wrapper when it is listed in `allowed_tools`.

## Structured Wrapper Logs

Backend diagnostic events are written as JSONL under the run directory:

`logs/dast_runs/<run_id>/events.jsonl`

The toolbox Docker compose maps this to the repository `logs/` directory via `DAST_LOG_DIR=/app/logs/dast_runs`.

Key wrapper-first events:

- `wrapper_dispatch_start`: `/v1/tools/wrappers/execute` received a wrapper request.
- `wrapper_dispatch_finish`: wrapper endpoint returned normalized result and `judge_ready_evidence`.
- `tool_execution_start`: wrapper service created deterministic artifacts and began execution.
- `tool_subprocess_start`: Schemathesis CLI subprocess was actually started.
- `tool_subprocess_completed`: Schemathesis subprocess exited or timed out.
- `tool_execution_partial`: wrapper returned partial output, including missing CLI or missing OpenAPI.
- `tool_execution_finish`: wrapper produced its final normalized result.
- `tool_execution_error`: wrapper failed before producing a normal result.
- `evidence_build_start`: evidence builder received a wrapper result.
- `evidence_build_finish`: judge-ready evidence was built.
- `legacy_tool_dispatch_start`: request went to a legacy tool endpoint such as `noop_outcome`.

Useful checks:

```bash
cat logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="wrapper_dispatch_start")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.trace_context.tool_name=="schemathesis_negative_test")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="tool_subprocess_start")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="evidence_build_finish")' logs/dast_runs/<run_id>/events.jsonl
jq 'select(.event_type=="legacy_tool_dispatch_start")' logs/dast_runs/<run_id>/events.jsonl
```

How to tell what happened:

- No active task / noop path: look for `legacy_tool_dispatch_start` with `extra.noop_path=true` or `extra.current_task_missing=true`.
- Schemathesis selected by wrapper path: look for `wrapper_dispatch_start` with `trace_context.tool_name="schemathesis_negative_test"`.
- Wrapper-first override happened: inspect `extra.wrapper_first_override` on `wrapper_dispatch_start`.
- CLI unavailable: look for `tool_execution_partial` with `reason.termination_reason="tool_unavailable"`.
- OpenAPI missing: look for `tool_execution_partial` with `reason.termination_reason="missing_openapi"`.
- Schemathesis actually ran: `tool_subprocess_start` and `tool_subprocess_completed` exist for `schemathesis_negative_test`.
- Evidence reached judge-ready path: `evidence_build_finish` exists with `extra.judge_ready=true`.
- Legacy fallback happened: `legacy_tool_dispatch_start` exists for the same run/task, or wrapper dispatch is absent for a task that went through a legacy endpoint.

## Next Steps

- Add pinned container or CLI integrations for RESTler, CATS, Akto, and ASTF.
- Pin the Schemathesis version more tightly after the first crAPI experiment run if reproducibility requires it.
- Persist wrapper artifacts in a durable mounted volume for experiment exports.
- Expand the Dify worker prompts further once wrapper execution is proven against crAPI.
- Add replay-pack ingestion into the final report/export pipeline.

## Core + Desirable Tooling Integration Pass

This pass extends the project beyond wrapper-first routing and adds a broader backend contract for the requested core stack:

Core now represented in routing / execution contracts:
- Schemathesis
- RESTler
- Akto
- internal auth/materialization helpers
- wrapper layer
- evidence builder
- judge
- scheduler/planner

Desirable support now represented in routing / helper endpoints:
- CATS
- HAR / traffic import (`import_har_capture`)
- runtime inventory (`runtime_inventory`)
- replay tooling (`replay_http_sequence`)
- rate-limit / bounded burst helper (`bounded_burst_helper`)

What changed in this pass:
- Task generation and task tooling now keep the following helper tools available where appropriate:
  - `import_har_capture`
  - `runtime_inventory`
  - `replay_http_sequence`
  - `bounded_burst_helper`
- Business-flow tasks now keep richer stateful / replay / burst helper options rather than collapsing to legacy-only commands.
- New legacy helper endpoints were added:
  - `/v1/traffic/import-har`
  - `/v1/inventory/runtime`
  - `/v1/replay/http-sequence`
  - `/v1/resource/bounded-burst-helper`
- Wrapper service now supports optional external runtime handoff for RESTler / CATS / Akto / ASTF through environment-variable commands:
  - `RESTLER_WRAPPER_COMMAND`
  - `CATS_WRAPPER_COMMAND`
  - `AKTO_WRAPPER_COMMAND`
  - `ASTF_WRAPPER_COMMAND`
- If those commands are not configured, wrappers still return deterministic scaffolded output with runtime request and runtime hint artifacts.

How to wire optional external runtimes:
- Set one or more of the wrapper command environment variables on `toolbox`.
- Each command receives formatted values such as:
  - `{request_json}`
  - `{output_dir}`
  - `{target_url}`
  - `{openapi_ref}`
  - `{tool_name}`
- Example pattern:
  - `RESTLER_WRAPPER_COMMAND="python /opt/restler_adapter.py --request {request_json} --out {output_dir}"`

What is still partial:
- Schemathesis is the only wrapper with a real in-process CLI path in the default toolbox image.
- RESTler / CATS / Akto / ASTF still rely on either:
  - scaffold mode, or
  - explicitly configured external runtime commands.
- Auth materialization and object provisioning are still the biggest blocker for authorization coverage when auth contexts are absent.

## Runtime adapter pass for RESTler and Akto

This pass adds default runtime adapter entrypoints for RESTler and Akto so wrapper-first tasks can reach a real external-runtime handoff without requiring immediate full upstream installation.

### What changed
- `backend/services/tool_wrappers/service.py`
  - external runtime commands now receive both `{request_json}` and `{result_json}` placeholders;
  - if the runtime writes a normalized JSON result file, the backend parses it back into `ToolWrapperResult`;
  - stdout JSON fallback parsing was added for simple runtime adapters.
- `scripts/runtime/restler_runtime_adapter.py`
  - adapter for `restler_compile`, `restler_fuzz`, `restler_replay`;
  - uses `RESTLER_BIN` if available for compile, otherwise creates deterministic compile/fuzz/replay artifacts.
- `scripts/runtime/akto_runtime_adapter.py`
  - adapter for `akto_inventory_discovery` and `akto_authz_scan`;
  - synthesizes runtime inventory from OpenAPI and prepares authorization scan plans when upstream Akto runtime is unavailable.
- `docker-compose.yml`
  - toolbox now defaults `RESTLER_WRAPPER_COMMAND` and `AKTO_WRAPPER_COMMAND` to the adapter scripts shipped in `/app/scripts/runtime/`.
- `scripts/smoke_akto_wrapper.py`
  - minimal smoke path for Akto adapter.

### What is live now
- Schemathesis remains the most direct in-process CLI wrapper.
- RESTler now has a live external-runtime adapter path that can:
  - parse a wrapper request,
  - fetch OpenAPI,
  - optionally invoke `RESTLER_BIN` for compile,
  - otherwise generate deterministic runtime artifacts and normalized wrapper output.
- Akto now has a live external-runtime adapter path that can:
  - build runtime inventory from OpenAPI,
  - produce authorization scan plans and candidate findings for auth tasks,
  - return normalized wrapper output even without upstream Akto installed.

### Verification
- `python scripts/smoke_restler_wrapper.py`
- `python scripts/smoke_akto_wrapper.py`
- wrapper runs now persist `<engine>_runtime_request.json` and `<engine>_runtime_result.json` under the wrapper artifact directory.

### Remaining gaps
- RESTler fuzz/replay are still adapter-backed unless a real `RESTLER_BIN` is provided.
- Akto adapter currently provides runtime-backed inventory/authz planning, not a full upstream Akto engine.
- Auth/materialization remains a major blocker for some authorization findings and still needs a dedicated follow-up pass.


## Auth/materialization pass
- Auto-provisioned identities now keep deterministic role names / aliases (`user_a`, `user_b`) so downstream auth tests can resolve the correct profiles.
- Auth preparation now fetches OpenAPI from `execution_context.openapi_url` when `openapi_spec_text` is empty, which improves baseline synthesis and object materialization in black-box runs.
- TestingService now indexes role profiles by aliases, role, username, and email to reduce `missing_auth_context` caused by naming mismatches.
- Added a CATS runtime adapter and smoke path; `docker-compose.yml` now wires `CATS_WRAPPER_COMMAND` by default through `scripts/runtime/cats_runtime_adapter.py`.


## Graph-state and auth/materialization alignment pass

This pass adds a lightweight executable `graph_state` inside `ExecutionContext` and uses it to reduce task/preparation mismatches.

What changed:
- added `execution_context.graph_state`
- added `backend/services/graph_state_service.py`
- task executability now consults graph-backed auth/object/workflow state
- queue enrichment now writes provisioned identities, prepared objects, harvested IDs and workflow context into graph nodes
- authorization object-materialization tasks now keep both `auto_provision` and `create_test_object` in their preparation/allowed tool sets when auth is still missing
- owner identity selection is stricter: if an explicit owner role is requested and no matching provisioned identity exists, preparation no longer silently falls back to an arbitrary authenticated role

Why this helps:
- reduces `missing_auth_context` caused by alias / role lookup drift
- gives scheduler/executability a real dependency memory for auth/object/workflow state
- makes object-authorization tasks progress through `auto_provision -> create_test_object -> replay/test` instead of losing one half of the preparation path


## Wrapper evidence to judge handoff pass

Diagnosis from `run-086f0da40946` showed Schemathesis wrapper evidence was strong inside `evidence_build_finish`, but judge events still logged `indicators: []` and `classification: null`.

Root cause:
- `JudgeReadyEvidence` preserved `signals` and `tool_summary`, but did not expose the judge-facing fields used by the Dify judge handoff and scheduler diagnostics:
  - `strong_indicators`
  - `indicators`
  - `classification_hint`
  - `response_summary.evidence_strength`
- The Dify wrapper passthrough returned `judge_ready_evidence` as-is, so those missing fields stayed missing.

What changed:
- `backend/models/tool_wrappers.py`
  - `JudgeReadyEvidence` now includes `run_id`, `derived_signals`, `strong_indicators`, `indicators`, `classification_hint`, and `response_summary`.
- `backend/services/evidence_builder_service.py`
  - Schemathesis rate-abuse evidence now serializes the same strong indicators and tool summary that were already logged.
  - Rate-abuse wrapper evidence gets `classification_hint=unrestricted_resource_consumption`.
- `dify/wf-multiagent-dast-multiworker.yml`
  - wrapper passthrough backfills judge-facing fields if an older backend response lacks them.
- `backend/services/task_scheduler.py`
  - queue update now emits judge handoff diagnostics:
    - `judge_input_source_selected`
    - `judge_input_built`
    - `judge_input_wrapper_fields_present`
    - `judge_input_wrapper_fields_missing`
- `JUDGE_HANDOFF_DIAGNOSIS.md`
  - captures the traced field loss and fix.

This does not auto-confirm findings or weaken judge policy. It only makes wrapper-derived evidence visible to the existing judge.

Verification after a Dify run:
```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_type | startswith("judge_input_"))'
cat logs/dast_runs/<run_id>/judge_events.jsonl | jq 'select(.task_id=="task_business_logic_006")'
```


## Schedule endpoint hardening

Diagnosis from `run-40ea606e08db` showed the current Dify failure was a backend scheduler error:

- Dify reached `/v1/schedule/next-task`.
- The backend emitted `schedule_next_task_start`.
- The first two scheduling calls emitted `schedule_next_task_finish`.
- The third and retried calls emitted `schedule_next_task_error` with `RecursionError`.

What changed:

- `backend/services/task_scheduler.py`
  - `select_next_task` keeps the lightweight remaining-task ordering introduced for the Dify HTTP path.
  - `update_queue_after_verdict` now also uses lightweight ordering instead of calling `order_queue()` and re-simulating the full scheduler after every verdict.
  - scheduler task enrichment and replay construction use bounded mutable task copies.
- `backend/services/task_tooling_service.py`
  - added `mutable_task_copy()` to copy only scheduler-mutated fields and avoid recursive deep-copy of arbitrary metadata.
- `backend/services/task_executability_service.py`
  - task preparation now uses the bounded mutable copy.
- `backend/services/followup_task_generation_service.py`
  - follow-up task cloning now uses the bounded mutable copy.
- `backend/api/routes_scheduling.py`
  - `schedule_next_task_error` now includes a secret-safe, bounded `traceback_preview`.

How to verify after restarting/rebuilding toolbox:

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_name=="schedule_next_task_error")'
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_name=="schedule_next_task_finish")'
```

If `schedule_next_task_error` appears again, inspect `artifacts.traceback_preview` in that event.


## Object materialization scheduler pass

Diagnosis is captured in `MATERIALIZATION_DIAGNOSIS.md` from run `run-f16b1f041240`.

What the run showed:

- Auth bootstrap worked and produced two usable identities.
- Materialization follow-up tasks were generated.
- `_materialization_attempts` and `_materialization_successes` stayed at `0`.
- No `object_materialization_*` events appeared, so `create_test_object` / list-select execution never started.

Root causes:

- Some materialization follow-ups could lose the hard object-id prerequisite and be treated as direct replay tests before an object id existed.
- Valid materialization preparation candidates could be skipped after the authorization class test budget was exhausted, even though they were preparation work rather than another authorization test.

What changed:

- `backend/services/followup_task_generation_service.py`
  - object materialization follow-ups now always keep `requires_object_id_enrichment=true`, `prerequisites.requires_object_id=true`, `readiness=needs_preparation`, and `create_test_object` as the delegated preparation tool.
- `backend/services/task_executability_service.py`
  - materialization tasks keep their requested strategy (`create_object_then_replay` vs `list_then_select_object_then_replay`).
  - if a prepared object id already exists, the task converts to replay-ready auth testing instead of staying in preparation.
- `backend/services/task_scheduler.py`
  - executable `create_test_object` materialization preparation can be selected even when the class test budget is exhausted.
  - that materialization preparation selection does not increment the authorization class test budget.

How to verify after a Dify run:

```bash
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.event_name=="object_materialization_start" or .event_type=="object_materialization_start")'
cat logs/dast_runs/<run_id>/run_summary.json | jq '{attempts: ._materialization_attempts, successes: ._materialization_successes, stop_reason}'
cat logs/dast_runs/<run_id>/events.jsonl | jq 'select(.reason.selection_reason=="selected_materialization_preparation_despite_class_budget")'
```

Expected improvement:

- `object_materialization_start` should appear once a materialization follow-up is selected.
- `_materialization_attempts` should become non-zero.
- `_materialization_successes` should become non-zero when the target exposes a usable create or list/select path.

## Object materialization dispatch alignment

- Materialization follow-ups now keep `requires_object_id`, `requires_object_id_enrichment`, `preferred_tool=create_test_object`, and `strategy_family=object_materialization` consistently.
- Scheduler now prioritizes executable materialization preparation tasks before ordinary direct tests once they are runnable.
- Added regression tests to ensure object-specific authorization follow-ups stay in preparation mode and scheduler selects materialization tasks when auth already exists but object id is missing.


## Object replay endpoint propagation

- Materialization now derives a `replay_endpoint_template` from the OpenAPI family when the original authorization target is a collection endpoint without path placeholders.
- Queue enrichment propagates `replay_endpoint_template` / `replay_path_params` into downstream object-dependent replay tasks so prepared replays can hit object-specific endpoints instead of reusing the original collection path.
- Verification after a run:
  - check `object_materialization_*` events exist
  - inspect `queue_enrichment_applied` and `worker_request_prepared` for enriched replay tasks
  - confirm `endpoint_before_substitution` is object-specific when `selected_object_id` exists

## Object replay endpoint application hardening

- Queue enrichment and post-preparation replay building now apply an object-specific replay endpoint not only to tasks with explicit placeholder/object-id prerequisites, but also to object-authorization replay tasks (`bola`, `object_authorization`, `create_object_then_replay`, `list_then_select_object_then_replay`).
- This prevents prepared replay tasks from keeping the original collection endpoint after a successful materialization.
- `prepared_object` and `workflow_context` now preserve `replay_endpoint_template` in addition to `replay_ready_endpoint` / `replay_path_params` so downstream enrichment has both the template and the concrete path context.
- Verification after a run:
  - inspect `queue_enrichment_applied`
  - inspect `worker_request_prepared` for `__prepared_replay` tasks
  - confirm `endpoint_before_substitution` is object-specific (contains a placeholder template or resolved object path), not the original collection endpoint


## Materialization fallback and budget increase

- Increased default scheduler fairness budgets to allow more authorization and business-logic work per run.
- Increased Dify normalize-input defaults for `max_requests`, `max_duration_sec`, `max_retries_per_task`, and `discovery_max_duration_sec`.
- Materialization can now fall back to list harvesting after create failures such as duplicate/conflict responses, which reduces dead-end `create_failed` outcomes when the object already exists but is still listable.
- Judge handoff logging now reads wrapper-derived `signals`, `strong_indicators`, and `tool_summary` from both top-level evidence and `response_summary`, reducing false `judge_input_wrapper_fields_missing` diagnostics.


## 2026-04-23 — Materialization payload variants + judge handoff hygiene

- create/list materialization now tries multiple bounded body variants for create candidates:
  - schema baseline body
  - baseline body merged with endpoint-specific inferred fields
  - endpoint-specific inferred body
  - generic inferred body
- video create candidates now receive video-shaped payloads for `/identity/api/v2/user/videos` instead of generic `name/title/description` payloads.
- create attempts now emit `object_materialization_attempted` with status code and request body keys for easier diagnosis of `create_failed` / `unexpected_status_code`.
- judge handoff no longer counts legacy evidence as `judge_input_wrapper_fields_missing`; non-wrapper cases are emitted as `judge_input_wrapper_fields_not_applicable`.
- generic wrapper enrichment now emits minimal `tool_summary` and derived authz indicators for authz/runtime wrapper results, improving wrapper-field preservation into judge input.

## Baseline synthesis hardening
- OpenAPI request-body examples are now merged into synthesized baseline payloads before required-field validation.
- Vendor JSON media types such as `application/*+json` are now supported when selecting request schemas.
- Required fields from composed schemas are merged and backfilled with heuristic/example values instead of failing early when the schema is partially sparse.
