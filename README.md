# Adaptive REST API Pentest Platform

## Abstract

This project implements an adaptive platform for automated REST API security testing as part of a bachelor's thesis.

The system combines:
- hypothesis generation
- specialized multi-agent roles
- strategy arbitration
- adaptive campaign execution
- observation analysis
- findings extraction
- experiment comparison

The current practical focus is comparison of two judge modes:
- `rule_based`
- `dify`

The main security targets are:
- BOLA
- BOPLA / excessive data exposure

## Architecture

The implementation is split into three layers.

### 1. FastAPI backend

The backend is the central system component and is responsible for:
- `TestSession` lifecycle
- agent registry and per-session enabled agent configuration
- campaign execution
- hypothesis generation and prioritization
- observations and findings
- BOLA and BOPLA analysis
- metrics and reporting
- experiment execution and export

### 2. Dify

Dify is used as:
- an optional LLM-based judge mode
- an optional specialized `dify_bola_agent` workflow for additional BOLA hypothesis generation

It selects the next hypothesis candidate and works as an intelligent arbitration layer.

The system preserves fallback behavior so that `rule_based` selection remains available when Dify is unavailable or returns an invalid result.

### 3. n8n

`n8n` is used as an orchestration layer above the backend.

It is used for:
- campaign automation
- experiment automation
- workflow-based execution
- demonstration-ready orchestration flows

Business logic is intentionally kept in the backend rather than moved into `n8n`.

## Workflow

The core adaptive workflow is:

`hypothesis -> judge -> execution -> observation -> analysis -> findings`

In the current implementation this is expressed as a multi-agent pipeline:

`agent -> hypothesis -> judge -> execution -> observation -> finding`

Agents do not execute HTTP actions directly. They generate structured hypotheses, the judge selects the next action, and the backend executor performs the request and stores the resulting observations/findings.

## Current Capabilities

Implemented practical features include:
- stable `rule_based` baseline
- working `dify` judge mode with fallback
- working `dify_bola_agent` integration
- explicit agent catalog and session-level enabled agent configuration
- BOLA detection and verification flow
- BOPLA / excessive data exposure detection
- experiment runner and comparison
- diploma-oriented experiment comparison summary
- final JSON and Markdown session reports
- agent activity summary
- JSON and CSV export
- `n8n` campaign and experiment workflows

## Agent Roles

The current practical agent set is:
- `rule_based_auth_agent`
- `rule_based_discovery_agent`
- `rule_based_probe_agent`
- `rule_based_analysis_agent`
- `rule_based_bola_agent`
- `rule_based_bopla_agent`
- `rule_based_verifier_agent`
- `dify_bola_agent`

This agent split is sufficient to represent a multi-agent pentest workflow for thesis experiments without overcomplicating orchestration.

## Key Endpoints

### Session and campaign

- `POST /session/create`
- `GET /session/{session_id}`
- `POST /campaign/step`
- `POST /campaign/run`

### Agent configuration

- `GET /agents/catalog`
- `GET /agents/session/{session_id}/plan`

### Reporting and metrics

- `GET /metrics/session/{session_id}`
- `GET /report/session/{session_id}`
- `GET /report/session/{session_id}/summary-text`
- `GET /report/session/{session_id}/executive-summary`
- `GET /report/session/{session_id}/final`
- `GET /report/session/{session_id}/markdown`
- `GET /report/session/{session_id}/agent-summary`

### Experiments

- `POST /experiments/run`
- `POST /experiments/run-summary`
- `GET /experiments/comparison`
- `GET /experiments/export`
- `GET /experiments/export.csv`
- `GET /experiments/diploma-summary`
- `GET /experiments/diploma-summary/markdown`

## Example Requests

### Run one full campaign

```bash
curl -X POST http://localhost:8000/campaign/run \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "crapi",
    "target_url": "http://host.docker.internal:8888",
    "judge_mode": "rule_based",
    "max_rounds": 15,
    "allowed_test_classes": ["discovery", "bola", "bopla", "auth"],
    "enabled_agents": [
      "rule_based_auth_agent",
      "rule_based_discovery_agent",
      "rule_based_probe_agent",
      "rule_based_analysis_agent",
      "rule_based_bola_agent",
      "rule_based_bopla_agent",
      "rule_based_verifier_agent",
      "dify_bola_agent"
    ]
  }'
```

### Run one experiment

```bash
curl -X POST http://localhost:8000/experiments/run \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "crapi",
    "target_url": "http://host.docker.internal:8888",
    "judge_mode": "rule_based",
    "max_rounds": 15,
    "profile": "mixed"
  }'
```

### Inspect the active agent plan for a session

```bash
curl "http://localhost:8000/agents/session/1/plan"
```

### Get diploma-oriented comparison summary

```bash
curl "http://localhost:8000/experiments/diploma-summary?target_name=crapi"
curl "http://localhost:8000/experiments/diploma-summary/markdown?target_name=crapi"
```

### Export recent experiment summary as CSV

```bash
curl "http://localhost:8000/experiments/export.csv?last_n_runs=5&view=summary"
```

## Metrics

The platform currently tracks:
- observations
- generated hypotheses
- judge decisions
- findings total
- BOLA findings
- BOPLA findings
- confirmed findings
- Dify direct matches
- Dify recoveries
- Dify fallbacks
- Dify issue breakdown
- agent activity summary
- confirmation rate
- stability index
- efficiency index

## `n8n` Workflows

The following orchestration workflows are currently supported:

### Campaign runners

- `Rule-Based Campaign Runner (Detailed)`
- `Dify Campaign Runner (Detailed)`
- `Rule-Based Campaign Runner (Simple)`
- `Dify Campaign Runner (Simple)`

### Experiment runners

- `Rule-Based Experiment Runner`
- `Dify Experiment Runner`
- `Batch Experiments With Reports`

The repository also includes an importable workflow template:

- [`n8n/workflows/run_batch_with_reports.json`](/Users/vanya/PycharmProjects/vkr/n8n/workflows/run_batch_with_reports.json)

This workflow is designed as an outer orchestration layer above the backend:

1. prepares a batch configuration
2. calls `POST /experiments/run-batch-with-reports`
3. receives experiment results together with generated LLM Markdown reports
4. exposes saved report paths for quick review in `n8n`

## Project Structure

```text
backend/
  app/
    core/
    routers/
    services/
    models.py
    schemas.py
    db.py
tests/
sql/
docker-compose.yml
zap/
```

## Run

Start the stack:

```bash
docker compose up -d
```

Start `n8n` separately if needed:

```bash
docker compose up -d n8n
```

Run a fully automated batch with report generation from the backend:

```bash
curl -X POST http://localhost:8000/experiments/run-batch-with-reports \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "crapi",
    "target_url": "http://host.docker.internal:8888",
    "profile": "mixed",
    "max_rounds": 15,
    "judge_modes": ["rule_based", "dify", "unified"]
  }'
```

The response includes:

- experiment batch metadata
- per-run results
- comparison report
- `session_reports` with:
  - `session_id`
  - `judge_mode`
  - `provider`
  - `used_fallback`
  - `saved_report_path`
  - `report_preview`

Generated Markdown reports are saved to:

- [`backend/exports/reports`](/Users/vanya/PycharmProjects/vkr/backend/exports/reports)

Run basic tests:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

## Current Limitations

- BOPLA detection is still heuristic
- Dify quality depends on external provider stability and token availability
- `dify` runs are less stable than `rule_based`
- local Python 3.9 environments may emit an `urllib3` / `LibreSSL` warning
- no reinforcement learning layer is implemented yet

## Next Practical Steps

- strengthen experiment datasets and evaluation
- polish thesis-facing comparison tables and narrative conclusions
- continue refining BOPLA precision
- extend orchestration scenarios in `n8n` only as an outer automation layer

## Thesis Context

The project supports a bachelor's thesis on adaptive vulnerability detection in REST APIs using strategy arbitration and automated orchestration.

## Author

Student: Vanya  
Academic year: 2025-2026
