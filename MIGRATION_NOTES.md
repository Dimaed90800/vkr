# Tool-aware Worker Migration Notes

## What Changed

- Added a normalized backend wrapper layer at `POST /v1/tools/wrappers/execute`.
- Added wrapper result and judge-ready evidence models.
- Added wrapper scaffolds for RESTler, Schemathesis, CATS, Akto, and OWASP ASTF command names.
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

## Tool Status

- Schemathesis: real CLI execution for `schemathesis_negative_test`; `schemathesis_stateful_test` is routed through Schemathesis with broader generation mode.
- RESTler: scaffold only.
- CATS: scaffold only.
- Akto: scaffold only.
- OWASP ASTF: scaffold only.

## Missing External Dependencies

- RESTler CLI/container is not configured in `docker-compose.yml`.
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
