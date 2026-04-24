# Judge Handoff Diagnosis

## Run Traced

- Run ID: `run-086f0da40946`
- Concrete task traced: `task_business_logic_006`
- Tool: `schemathesis_stateful_test`

## What Was Present Before Judge Handoff

`wrapper_events.jsonl` showed the wrapper path and evidence builder were working:

- `wrapper_dispatch_start`: present
- `tool_subprocess_completed`: present
- `rate_abuse_signal_derivation`: present
- `evidence_strength_assessed`: present
- `evidence_build_finish`: present

For `task_business_logic_006`, `evidence_build_finish` contained:

- `derived_signals`:
  - `schema_violation`
  - `server_error_signal`
  - `repeated_success_without_throttle`
  - `no_rate_limit_detected`
- `strong_indicators`:
  - `schema_violation`
  - `server_error_signal`
  - `repeated_success_without_throttle`
  - `no_rate_limit_detected`
- `tool_summary`:
  - `bounded_burst_count`: `20`
  - `success_count`: `18`
  - `client_error_count`: `63`
  - `server_error_count`: `12`
  - `saw_429`: `false`
  - `saw_5xx`: `true`
- `evidence_strength`: `sufficient_indicators`
- `judge_ready`: `true`

## What The Judge Actually Saw

`judge_events.jsonl` for the same task showed:

- `classification`: `null`
- `signal_strength`: `null`
- `artifacts.indicators`: `[]`
- `final_verdict`: `rework`

So the judge node ran, but the wrapper-derived security indicators were not visible in the fields the judge handoff and scheduler diagnostics were reading.

## Where Evidence Was Lost

The loss happened at the judge input contract boundary:

1. `backend/services/evidence_builder_service.py` built rich wrapper evidence, but the serialized `JudgeReadyEvidence` model did not include `strong_indicators`, `indicators`, `classification_hint`, or `response_summary.evidence_strength`.
2. `dify/wf-multiagent-dast-multiworker.yml` passed wrapper evidence through when `judge_ready_evidence` existed, but did not backfill those judge-facing fields.
3. The judge parser and backend scheduler diagnostics read `classification_hint`, `response_summary`, and `indicators`, so they logged empty/null values even though `signals` and `tool_summary` existed elsewhere.

## Fix

The wrapper evidence contract now preserves judge-facing fields:

- `signals`
- `derived_signals`
- `strong_indicators`
- `indicators`
- `classification_hint`
- `response_summary`
- `tool_summary`
- `reproduction`
- `artifacts`
- `task_id`
- `worker_role`
- `tool_name`

Dify wrapper passthrough also backfills these fields when an older backend response lacks them.

Backend queue update diagnostics now emit:

- `judge_input_source_selected`
- `judge_input_built`
- `judge_input_wrapper_fields_present`
- `judge_input_wrapper_fields_missing`

This does not auto-confirm findings and does not weaken judge policy. It only ensures the judge receives the same normalized evidence the wrapper/evidence builder already produced.
