# Adaptive REST API Pentest Platform

## Abstract

This project implements an adaptive platform for automated REST API security testing as part of a bachelor's thesis.

The system combines:
- specialized multi-agent roles
- prompt-driven routing
- adaptive campaign execution
- observation analysis
- findings extraction
- experiment comparison

The current practical focus is an agentic execution loop:
- user prompt as the campaign goal
- router that distributes tasks to specialized logical agents
- worker agents that execute search and exploitation actions
- judge that validates only execution results
- report generation from confirmed vulnerabilities

Legacy-compatible experiment modes are still available for comparison:
- `agentic`
- `dify`
- `rule_based`
- `unified`

The main security targets are:
- BOLA
- BOPLA / excessive data exposure

## Architecture

The implementation is split into three layers.

### 1. FastAPI backend

The backend is the central system component and is responsible for:
- `TestSession` lifecycle
- agent registry and per-session enabled agent configuration
- prompt-aware router and judge state
- campaign execution
- hypothesis generation and prioritization
- observations and findings
- BOLA and BOPLA analysis
- metrics and reporting
- experiment execution and export

### 2. Dify

Dify is used as:
- an optional provider for specialized worker agents
- an optional legacy judge mode for experiment comparison
- an optional report-generation provider

In the main `agentic` flow, Dify is not required to arbitrate every step. It can be used by worker agents and by the final report generator.

The system preserves fallback behavior so that legacy `rule_based` selection remains available when Dify is unavailable or returns an invalid result in comparison modes.

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

`user_prompt -> router -> agent task -> execution -> judge -> retry_or_next -> confirmed finding -> report`

In the current implementation this is expressed as a multi-agent pipeline:

`logical_agent -> hypothesis -> execution -> judge verdict -> follow-up verification -> finding`

Agents do not execute HTTP actions directly. They generate structured hypotheses, the backend executor performs the request, and the judge evaluates only the produced result and whether exploitation was actually confirmed.

## Current Capabilities

Implemented practical features include:
- prompt-driven `agentic` orchestration mode
- router over logical agents
- judge loop with bounded retries
- confirmed-finding-first reporting flow
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
    "user_prompt": "Найди подтвержденные BOLA и BOPLA уязвимости и дойди до верификации эксплуатации",
    "judge_mode": "agentic",
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
    "judge_mode": "agentic",
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
- router and judge decisions
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

- `Agentic Campaign Runner (Detailed)`
- `Dify Campaign Runner (Detailed)`
- `Agentic Campaign Runner (Simple)`
- `Dify Campaign Runner (Simple)`

### Experiment runners

- `Agentic Experiment Runner`
- `Dify Experiment Runner`
- `Batch Experiments With Reports`
- `Batch Job Runner (Polling)`

The repository also includes an importable workflow template:

- [`n8n/workflows/run_batch_with_reports.json`](/Users/vanya/PycharmProjects/vkr/n8n/workflows/run_batch_with_reports.json)
- [`n8n/workflows/run_batch_job_polling.json`](/Users/vanya/PycharmProjects/vkr/n8n/workflows/run_batch_job_polling.json)

Two orchestration styles are supported:

### Direct batch execution

This flow is useful for direct backend calls and short local runs:

1. prepares a batch configuration
2. calls `POST /experiments/run-batch-with-reports`
3. receives experiment results together with generated LLM Markdown reports
4. exposes saved report paths for quick review in `n8n`

### Recommended job-based orchestration

For `n8n`, the preferred production-like flow is job-based polling:

1. call `POST /automation/run-batch-job`
2. receive `job_id` with status `queued`
3. wait for a short interval
4. poll `GET /automation/jobs/{job_id}`
5. continue polling while status is `queued` or `running`
6. when status becomes `finished`, display artifact paths and report summary

This avoids long-running blocking HTTP requests in `n8n` and makes the workflow more stable.
The polling workflow is available as an importable template in:

- [`n8n/workflows/run_batch_job_polling.json`](/Users/vanya/PycharmProjects/vkr/n8n/workflows/run_batch_job_polling.json)

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
    "judge_modes": ["agentic", "dify"]
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

Start a background automation job:

```bash
curl -X POST http://localhost:8000/automation/run-batch-job \
  -H "Content-Type: application/json" \
  -d '{
    "target_name": "crapi",
    "target_url": "http://host.docker.internal:8888",
    "profile": "mixed",
    "max_rounds": 5,
    "judge_modes": ["agentic"]
  }'
```

Then poll job status:

```bash
curl http://localhost:8000/automation/jobs/<job_id>
```

When the job finishes, the response includes:

- `job_id`
- `status`
- `artifact_dir`
- `result`
- `result.artifact_paths.summary_markdown`
- `result.session_reports`

Automation job artifacts are saved to:

- [`backend/exports/jobs`](/Users/vanya/PycharmProjects/vkr/backend/exports/jobs)

Advanced experiment-design options are also supported in batch and automation payloads:

- `enabled_logical_agents`
  - enable only selected logical agents such as `authentication_agent`, `authorization_agent`, `exposure_agent`
- `disabled_logical_agents`
  - run agent ablations without editing backend code
- `strategy_config.agentic_max_retries_per_candidate`
  - bound judge-triggered retries for the same task candidate
- `strategy_config.agentic_max_tasks_per_logical_agent`
  - prevent infinite cycling on one logical agent
- `strategy_config.agentic_max_judge_history_items`
  - cap stored judge-history state in the session strategy payload
- `strategy_config.unified_weights`
  - override unified arbitration blend weights for legacy ablation experiments
- `bootstrap_probes`
  - attach target-specific seed requests for API portability experiments
- `targets`
  - run the same judge-mode matrix across multiple API targets in one batch
- `zap_baseline`
  - run a classical OWASP ZAP baseline scan and attach normalized results automatically to `external_baselines`
- `external_baselines`
  - attach normalized results from external tools such as Schemathesis, RESTler, EvoMaster or RESTSpecIT for side-by-side comparison in the generated comparison report

Example payload for an ablation and portability-oriented automation run:

```bash
curl -X POST http://localhost:8000/automation/run-batch-job \
  -H "Content-Type: application/json" \
  -d '{
    "judge_modes": ["agentic", "dify", "unified"],
    "max_rounds": 12,
    "enabled_logical_agents": ["authorization_agent", "exposure_agent"],
    "strategy_config": {
      "agentic_max_retries_per_candidate": 2,
      "agentic_max_tasks_per_logical_agent": 4,
      "unified_weights": {
        "rule_weight": 0.55,
        "dify_weight": 0.45
      }
    },
    "targets": [
      {
        "target_name": "crapi",
        "target_url": "http://host.docker.internal:8888",
        "profile": "mixed"
      }
    ],
    "zap_baseline": {
      "enabled": true,
      "import_openapi": true,
      "use_ajax_spider": false,
      "max_spider_sec": 120,
      "max_active_sec": 300
    },
    "external_baselines": [
      {
        "tool": "schemathesis",
        "profile": "mixed",
        "target_name": "crapi",
        "findings_total": 3,
        "confirmed_findings": 2,
        "requests_used": 60,
        "time_used": 120
      }
    ]
  }'
```

Each job directory contains:

- `batch_result.json`
- `comparison_report.json`
- `session_reports.json`
- `summary.md`
- `reports/` with generated session Markdown reports

Generated exports under [`backend/exports/jobs`](/Users/vanya/PycharmProjects/vkr/backend/exports/jobs) and runtime Markdown reports under [`backend/exports/reports`](/Users/vanya/PycharmProjects/vkr/backend/exports/reports) are treated as runtime artifacts and should not be committed to git.

Run basic tests:

```bash
.venv/bin/python -m unittest discover -s tests -p 'test_*.py'
```

## Current Limitations

- BOPLA detection is still heuristic
- Dify quality depends on external provider stability and token availability
- legacy `dify` and `unified` comparison runs are less stable than the default `agentic` flow
- local Python 3.9 environments may emit an `urllib3` / `LibreSSL` warning
- no reinforcement learning layer is implemented yet

## Next Practical Steps

- strengthen experiment datasets and evaluation
- polish thesis-facing comparison tables and narrative conclusions
- continue refining BOPLA precision
- extend orchestration scenarios in `n8n` only as an outer automation layer

## Thesis Context

The project supports a bachelor's thesis on adaptive vulnerability detection in REST APIs using strategy arbitration and automated orchestration.

For current implementation work, treat `agentic` as the primary orchestration mode and `rule_based` / `unified` as legacy-compatible experiment modes.

## Author

Student: Vanya  
Academic year: 2025-2026
