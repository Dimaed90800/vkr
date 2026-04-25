# TESTING_STRATEGY.md

## Purpose

This document defines the tests required to safely refactor the project.

## Baseline command

Use the current working test command:

```bash
python -m pytest tests
```

If pytest is unavailable or the project expects unittest discovery:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Critical tests to preserve

Prioritize these tests during refactor:

```text
tests/test_dify_workflow_dispatch_contract.py
tests/test_graph_state_integration.py
tests/test_task_tooling_integration.py
tests/test_routes_scheduling_diagnostics.py
tests/test_task_contract_alignment.py
tests/test_replay_service.py
tests/test_judge_service.py
tests/test_unified_judge_service.py
tests/test_judge_handoff_preservation.py
tests/test_agentic_judge_service.py
tests/test_bopla_finding_dedup.py
tests/test_dify_bola_normalization.py
tests/test_auth_materialization_pipeline.py
tests/test_auth_bootstrap_openapi.py
tests/test_final_stop_reason_service.py
tests/test_traffic_capture_service.py
```

## Required new tests

### 1. Campaign compatibility

```text
test_campaign_create_returns_campaign_id
test_campaign_summary_contains_budget_and_counts
test_legacy_run_id_maps_to_campaign_id
```

### 2. Request corpus

```text
test_corpus_stores_successful_2xx_request
test_corpus_stores_403_as_auth_baseline
test_corpus_redacts_authorization_header
test_corpus_extracts_object_ids
test_corpus_finds_cross_role_candidates
```

### 3. API graph

```text
test_openapi_ingest_creates_operation_nodes
test_response_enrichment_adds_returned_fields
test_dependency_graph_links_producer_consumer
```

### 4. Worker command

```text
test_worker_command_validates_allowed_tool
test_worker_command_rejects_out_of_scope_host
test_worker_command_uses_seed_request
```

### 5. Tool result

```text
test_schemathesis_wrapper_returns_tool_result_v1
test_restler_degraded_scaffold_returns_tool_result_v1
test_tool_result_contains_artifact_refs
```

### 6. Evidence builder

```text
test_evidence_pack_contains_baseline_and_attack
test_bola_missing_ownership_proof_sets_missing_evidence
test_evidence_pack_contains_replay_steps
```

### 7. Judge apply

```text
test_confirmed_verdict_creates_finding
test_rework_verdict_creates_followup_task
test_rejected_verdict_records_reason
test_duplicate_verdict_does_not_create_new_finding
```

### 8. Dify loop contract

```text
test_loop_iteration_executes_single_task
test_dify_state_does_not_contain_full_corpus
test_backend_stop_reason_is_final_source
```

## Golden path integration test

Create one end-to-end test against demo target:

```text
create campaign
ingest OpenAPI
bootstrap corpus
plan access control task
execute role swap
build evidence
judge confirms
report contains one confirmed finding
```

## Regression rule

Before removing or rewriting any service, add tests around its current externally visible behavior.
