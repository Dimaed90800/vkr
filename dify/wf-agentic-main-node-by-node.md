# wf-agentic-main Node-by-Node

This is the current practical Dify build plan for the main workflow.

Use this file as the source of truth while the importable YAML is still catching up with the backend.

For the finite retry/advance/stop logic, use
[wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md)
as the canonical loop reference.

## Goal

Build one workflow that executes this path:

1. start agentic session
2. prepare auth
3. prepare probe seeds
4. fetch BOLA worker tasks
5. execute one BOLA task
6. ingest worker result
7. fetch judge package
8. run LLM judge
9. save judge verdict
10. fetch BOPLA worker tasks
11. execute one bounded BOPLA loop
12. fetch report package
13. run final report LLM

This file still documents the practical node chain.

The bounded retry and family-transition logic is specified separately in
[wf-agentic-loop-design.md](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-loop-design.md).

The current importable baseline is
[wf-agentic-main-v10.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-main-v10.yml).

For the current working path, prefer `v10` over `v4-v9`.

If you want the same path but with the new logical-agent orchestration layer in front,
start from
[wf-agentic-orchestrated-v2.yml](/Users/vanya/PycharmProjects/vkr/dify/wf-agentic-orchestrated-v2.yml).

`orchestrated-v2` extends the same working access-control path with two deterministic
scanner loops:

- `Discovery Agent loop`
- `DAST Agent loop`

For the current retry behavior, do not rely on unsaved retry-memory fields.
Use the bounded loops themselves:

- `should_exit_bola_loop`
- `should_exit_bopla_loop`
- `loop_count = 2`

This gives one initial attempt and at most one retry per family.

## Inputs

Create these `Start` inputs:

- `backend_base_url`
- `target_name`
- `target_url`
- `user_prompt`
- `allowed_test_classes_csv`
- `max_rounds`
- `budget_requests_total`
- `budget_time_total`

Recommended defaults:

- `allowed_test_classes_csv`: `discovery,bola,bopla,auth`
- `max_rounds`: `10`
- `budget_requests_total`: `200`
- `budget_time_total`: `1800`

## Node 1. `Code` — Normalize Input

Responsibilities:

- trim URLs
- parse CSV test classes
- cast budgets and rounds to integers

Outputs:

- `backend_base_url`
- `target_name`
- `target_url`
- `user_prompt`
- `allowed_test_classes_json`
- `max_rounds_value`
- `budget_requests_total_value`
- `budget_time_total_value`

## Node 2. `HTTP Request` — Start Session

Method:

- `POST`

URL:

- `{{#normalize_input.backend_base_url#}}/agentic/start`

Body:

```json
{
  "target_name": "{{#normalize_input.target_name#}}",
  "target_url": "{{#normalize_input.target_url#}}",
  "user_prompt": "{{#normalize_input.user_prompt#}}",
  "allowed_test_classes": {{#normalize_input.allowed_test_classes_json#}},
  "max_rounds": {{#normalize_input.max_rounds_value#}},
  "budget_requests_total": {{#normalize_input.budget_requests_total_value#}},
  "budget_time_total": {{#normalize_input.budget_time_total_value#}}
}
```

## Node 3. `Code` — Parse Session

Extract:

- `session_id`
- `session_context_url`
- `judge_state_url`
- `report_package_url`
- `bola_worker_tasks_url`
- `tool_execute_url`

Build these additional URLs:

- `prepare_auth_url`: `{{backend_base_url}}/agentic/session/{{session_id}}/prepare-auth`
- `prepare_probe_url`: `{{backend_base_url}}/agentic/session/{{session_id}}/prepare-probe-seeds`
- `bopla_worker_tasks_url`: `{{backend_base_url}}/agentic/session/{{session_id}}/worker-tasks/bopla`
- `worker_result_url`: `{{backend_base_url}}/agentic/session/{{session_id}}/worker-result`

## Node 4. `HTTP Request` — Prepare Auth

Method:

- `POST`

URL:

- `{{#parse_session.prepare_auth_url#}}`

Body:

```json
{
  "max_steps": 6
}
```

## Node 5. `HTTP Request` — Prepare Probe Seeds

Method:

- `POST`

URL:

- `{{#parse_session.prepare_probe_url#}}`

Body:

```json
{
  "max_steps": 4
}
```

## Node 6. `HTTP Request` — Get BOLA Worker Tasks

Method:

- `GET`

URL:

- `{{#parse_session.bola_worker_tasks_url#}}`

## Node 7. `Code` — Pick First BOLA Task

Responsibilities:

- read `tasks`
- pick first item if present
- expose:
  - `has_bola_task`
  - `task_id`
  - `worker_type`
  - `vulnerability_class`
  - `endpoint`
  - `method`
  - `owner_role`
  - `other_role`

## Node 8. `If-Else` — Has BOLA Task

Condition:

- `has_bola_task == true`

If false:

- skip directly to BOPLA branch or report branch

## Node 9. `LLM` — BOLA Worker Agent

Use the prompt from [bola_worker_system_prompt.md](/Users/vanya/PycharmProjects/vkr/dify/prompts/bola_worker_system_prompt.md).

Input:

- one BOLA worker task
- instruction to prepare one tool command

Expected output:

- strict JSON in `tool_command` mode

## Node 10. `Code` — Parse BOLA Tool Command

Responsibilities:

- parse the worker agent JSON
- expose:
  - `tool_name`
  - `arguments`

## Node 11. `HTTP Request` — Execute BOLA Tool

Method:

- `POST`

URL:

- `{{#parse_session.tool_execute_url#}}`

Body:

```json
{
  "tool_name": "{{#parse_bola_tool_command.tool_name#}}",
  "arguments": {{#parse_bola_tool_command.arguments_json#}}
}
```

## Node 12. `Code` — Build BOLA Worker Result

In the current working baseline, do not use an LLM to summarize the BOLA tool result.

Instead, build the worker result deterministically from the HTTP tool-execution payload.

Reason:

- Dify HTTP nodes return an outer envelope like:
  - `tool_name`
  - `status`
  - `result`
- backend `worker-result` ingestion expects the inner `result`
- passing the outer envelope caused `candidate_finding = null`

The code node should:

- parse `Execute BOLA Tool.body`
- extract `payload["result"]` when present
- preserve:
  - `worker_type`
  - `tool_name`
  - `task_id`
  - `vulnerability_class`
- expose:
  - `result_json`

## Node 13. `HTTP Request` — Save BOLA Worker Result

Method:

- `POST`

URL:

- `{{#parse_session.worker_result_url#}}`

Body:

```json
{
  "worker_type": "{{#build_bola_worker_result.worker_type#}}",
  "tool_name": "{{#build_bola_worker_result.tool_name#}}",
  "task_id": "{{#build_bola_worker_result.task_id#}}",
  "vulnerability_class": "{{#build_bola_worker_result.vulnerability_class#}}",
  "result": {{#build_bola_worker_result.result_json#}}
}
```

## Node 14. `Code` — Extract Candidate Finding

Responsibilities:

- parse `Save BOLA Worker Result.body`
- extract:
  - `finding_id`
  - serialized `candidate_finding`

If `candidate_finding` is `null`, the next `Get Judge Package` call will fail with `404`,
so this is the first node to inspect when debugging the looped BOLA branch.

## Node 15. `Code` — Extract Candidate Finding

Outputs:

- `has_candidate_finding`
- `finding_id`

## Node 16. `If-Else` — Has Candidate Finding

If false:

- continue to BOPLA branch

## Node 17. `HTTP Request` — Get Judge Package

Method:

- `GET`

URL:

- `{{#normalize_input.backend_base_url#}}/agentic/session/{{#parse_session.session_id#}}/judge-package/{{#extract_candidate.finding_id#}}`

## Node 18. `LLM` — Judge Agent

Use the prompt from [judge_system_prompt.md](/Users/vanya/PycharmProjects/vkr/dify/prompts/judge_system_prompt.md).

Input:

- full judge package JSON

Output:

- strict JSON only:
  - `status`
  - `finding_type`
  - `reason`
  - `next_action`

## Node 19. `HTTP Request` — Save Judge Verdict

Method:

- `POST`

URL:

- `{{#normalize_input.backend_base_url#}}/agentic/session/{{#parse_session.session_id#}}/judge-verdict`

Body:

```json
{
  "finding_id": {{#extract_candidate.finding_id#}},
  "status": {{#judge_agent.text#}}["status"],
  "reason": {{#judge_agent.text#}}["reason"],
  "finding_type": {{#judge_agent.text#}}["finding_type"],
  "next_action": {{#judge_agent.text#}}["next_action"]
}
```

In practice, if your Dify version cannot index JSON directly from the LLM output, insert one more `Code` node to parse the judge JSON first.

## Node 20. `HTTP Request` — Get BOPLA Worker Tasks

Method:

- `GET`

URL:

- `{{#parse_session.bopla_worker_tasks_url#}}`

## Node 21. `Code` — Pick First BOPLA Task

Responsibilities:

- read first `bopla` task
- expose:
  - `has_bopla_task`
  - `task_id`
  - `worker_type`
  - `vulnerability_class`
  - `observation_id`
  - `suspected_fields`

## Node 22. `If-Else` — Has BOPLA Task

Condition:

- `has_bopla_task == true`

## Node 23. `LLM` — BOPLA Worker Agent

Use the prompt from [bopla_worker_system_prompt.md](/Users/vanya/PycharmProjects/vkr/dify/prompts/bopla_worker_system_prompt.md).

Input:

- one BOPLA worker task
- instruction to prepare one tool command

Expected output:

- strict JSON in `tool_command` mode

## Node 24. `Code` — Parse BOPLA Tool Command

Responsibilities:

- parse the worker agent JSON
- expose:
  - `tool_name`
  - `arguments`

## Node 25. `HTTP Request` — Execute BOPLA Tool

For `bopla_probe`, use:

```json
{
  "tool_name": "{{#parse_bopla_tool_command.tool_name#}}",
  "arguments": {{#parse_bopla_tool_command.arguments_json#}}
}
```

## Node 26. `LLM` — BOPLA Worker Agent Result Summary

Use the same [bopla_worker_system_prompt.md](/Users/vanya/PycharmProjects/vkr/dify/prompts/bopla_worker_system_prompt.md).

Input:

- original BOPLA worker task
- tool result JSON
- instruction to summarize the tool result in `worker_result` mode

Expected output:

- strict JSON in `worker_result` mode

## Node 27. `Code` — Parse BOPLA Worker Result

Responsibilities:

- parse the worker result JSON
- expose:
  - `worker_type`
  - `tool_name`
  - `task_id`
  - `vulnerability_class`
  - `result`

## Node 28. `HTTP Request` — Save BOPLA Worker Result

Method:

- `POST`

URL:

- `{{#parse_session.worker_result_url#}}`

Body:

```json
{
  "worker_type": "{{#parse_bopla_worker_result.worker_type#}}",
  "tool_name": "{{#parse_bopla_worker_result.tool_name#}}",
  "task_id": "{{#parse_bopla_worker_result.task_id#}}",
  "vulnerability_class": "{{#parse_bopla_worker_result.vulnerability_class#}}",
  "result": {{#parse_bopla_worker_result.result_json#}}
}
```

After this, reuse the same `judge-package -> judge-agent -> judge-verdict` chain as for BOLA.

## Node 29. `HTTP Request` — Get Judge State

Method:

- `GET`

URL:

- `{{#parse_session.judge_state_url#}}`

Use:

- show confirmed findings count
- expose current candidate/confirmed state before report

## Node 30. `HTTP Request` — Get Report Package

Method:

- `GET`

URL:

- `{{#parse_session.report_package_url#}}`

## Node 31. `LLM` — Final Report

Use the prompt from [report_system_prompt.md](/Users/vanya/PycharmProjects/vkr/dify/prompts/report_system_prompt.md).

Input:

- report package JSON

## Node 32. `Output`

Return:

- `session_id`
- `confirmed_findings_total`
- `report_markdown`

## Practical Note

Do not try to build the full retry loop in the first pass.

First make this linear version work:

- one BOLA task
- one judge pass
- one BOPLA task
- one judge pass
- final report

When that is stable, add:

- loop over remaining BOLA tasks
- loop over remaining BOPLA tasks
- retry on `needs_retry`
