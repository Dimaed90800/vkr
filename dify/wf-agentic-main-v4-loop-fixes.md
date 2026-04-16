# wf-agentic-main-v4 Loop Fixes

These are the exact fixes for the looped `BOLA` branch from the edited Dify export.

Use them when your exported DSL already contains the `BOLA loop` node and the nested node ids shown below.

## 1. `Pick First BOLA Task (1)` input binding

The loop-local task picker must read from `Get BOLA Worker Tasks (1)`, not from `prepare_probe`.

Correct block:

```yaml
- data:
    code: "import json\ndef main(body: str) -> dict:\n    payload = json.loads(body)\n    tasks = payload.get(\"tasks\", []) or []\n    first = tasks[0] if tasks else {}\n    inputs = first.get(\"inputs\", {}) or {}\n    return {\n        \"task_id\": first.get(\"task_id\", \"\"),\n        \"worker_type\": first.get(\"worker_type\", \"\"),\n        \"vulnerability_class\": first.get(\"vulnerability_class\", \"\"),\n        \"endpoint\": inputs.get(\"endpoint\", \"\"),\n        \"method\": inputs.get(\"method\", \"GET\"),\n        \"owner_role\": inputs.get(\"owner_role\", \"\"),\n        \"other_role\": inputs.get(\"other_role\", \"\"),\n        \"tasks_total\": payload.get(\"tasks_total\", 0),\n    }\n"
    code_language: python3
    dependencies: []
    desc: Pick the first available BOLA task.
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    outputs:
      endpoint: {children: null, type: string}
      method: {children: null, type: string}
      other_role: {children: null, type: string}
      owner_role: {children: null, type: string}
      task_id: {children: null, type: string}
      tasks_total: {children: null, type: number}
      vulnerability_class: {children: null, type: string}
      worker_type: {children: null, type: string}
    title: Pick First BOLA Task (1)
    type: code
    variables:
    - value_selector: ['17761116119590', body]
      value_type: string
      variable: body
  id: '17761116343250'
```

## 2. `BOLA Worker Result Agent (1)` prompt

Your current node contains a `tool_command` prompt. It must return `worker_result`.

Correct block:

```yaml
- data:
    context: {enabled: false, variable_selector: []}
    desc: LLM worker summarizes one executed BOLA tool result.
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    model:
      completion_params: {temperature: 0.1}
      mode: chat
      name: gpt-4.1
      provider: langgenius/openai/openai
    prompt_template:
    - id: sys
      role: system
      text: "You are a BOLA worker result agent in an adaptive REST API pentest system.\n\nYou receive:\n- one structured BOLA worker task\n- one executed tool result\n\nYou do not invent new tasks.\nYou do not confirm vulnerabilities finally.\nYou do not output prose outside JSON.\nYou only summarize the executed tool result into one strict worker result JSON.\n\nPreserve these fields exactly:\n- task_id\n- worker_type\n- tool_name\n- vulnerability_class\n\nUse the executed tool result as the source of truth.\nDo not drop nested fields from the tool result unless they are clearly missing.\nDo not invent observations or analysis.\n\nReturn strict JSON only in this format:\n{\n  \"mode\": \"worker_result\",\n  \"worker_type\": \"replay_agent\",\n  \"tool_name\": \"probe_same_object_across_roles\",\n  \"vulnerability_class\": \"BOLA\",\n  \"task_id\": \"bola_probe::example\",\n  \"summary\": \"short factual summary\",\n  \"result\": {}\n}"
    - id: user
      role: user
      text: "Summarize this executed BOLA tool result as a strict worker result JSON.\n\nOriginal worker task:\n{\n  \"task_id\": \"{{#17761116343250.task_id#}}\",\n  \"worker_type\": \"{{#17761116343250.worker_type#}}\",\n  \"vulnerability_class\": \"{{#17761116343250.vulnerability_class#}}\",\n  \"inputs\": {\n    \"endpoint\": \"{{#17761116343250.endpoint#}}\",\n    \"method\": \"{{#17761116343250.method#}}\",\n    \"owner_role\": \"{{#17761116343250.owner_role#}}\",\n    \"other_role\": \"{{#17761116343250.other_role#}}\"\n  }\n}\n\nExecuted tool result:\n{{#17761140495430.body#}}\n\nReturn JSON only in this format:\n{\n  \"mode\": \"worker_result\",\n  \"worker_type\": \"{{#17761116343250.worker_type#}}\",\n  \"tool_name\": \"probe_same_object_across_roles\",\n  \"vulnerability_class\": \"{{#17761116343250.vulnerability_class#}}\",\n  \"task_id\": \"{{#17761116343250.task_id#}}\",\n  \"summary\": \"short factual summary\",\n  \"result\": <copy the executed tool result as structured JSON>\n}"
    title: BOLA Worker Result Agent (1)
    type: llm
    variables: []
    vision: {enabled: false}
  id: '17761140198680'
```

## 3. `Save Worker Result (1)` body

The loop-local worker-result persistence must read from `Parse BOLA Worker Result (1)`.

Correct block:

```yaml
- data:
    authorization: {config: null, type: no-auth}
    body:
      data:
      - type: text
        value: "{\n  \"worker_type\": \"{{#17761140277870.worker_type#}}\",\n  \"tool_name\": \"{{#17761140277870.tool_name#}}\",\n  \"task_id\": \"{{#17761140277870.task_id#}}\",\n  \"vulnerability_class\": \"{{#17761140277870.vulnerability_class#}}\",\n  \"result\": {{#17761140277870.result_json#}}\n}\n"
      type: json
    desc: Persist normalized worker result and create candidate finding.
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    headers: Content-Type:application/json
    method: post
    params: ''
    retry_config: {max_retries: 1, retry_enabled: true, retry_interval: 200}
    ssl_verify: false
    timeout: {max_connect_timeout: 0, max_read_timeout: 0, max_write_timeout: 0}
    title: Save Worker Result (1)
    type: http-request
    url: '{{#parse_session.worker_result_url#}}'
    variables: []
  id: '17761117095280'
```

## 4. `Extract Candidate Finding (1)` input binding

It must read from `Save Worker Result (1)`, not `prepare_auth`.

Correct block:

```yaml
- data:
    code: "import json\ndef main(body: str) -> dict:\n    payload = json.loads(body)\n    finding = payload.get(\"candidate_finding\", {}) or {}\n    return {\n        \"finding_id\": finding.get(\"id\"),\n        \"candidate_finding_json\": json.dumps(finding, ensure_ascii=False),\n    }\n"
    code_language: python3
    dependencies: []
    desc: Extract candidate finding identifier.
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    outputs:
      candidate_finding_json: {children: null, type: string}
      finding_id: {children: null, type: number}
    title: Extract Candidate Finding (1)
    type: code
    variables:
    - value_selector: ['17761117095280', body]
      value_type: string
      variable: body
  id: '17761117276370'
```

## 5. `Get Judge Package (1)` URL

It needs a `/` before the `finding_id`.

Correct URL:

```yaml
url: '{{#parse_session.judge_package_base_url#}}/{{#17761117276370.finding_id#}}'
```

## 6. `Judge Agent (1)` input

It must evaluate the actual loop-local judge package, not `prepare_probe.body`.

Correct block:

```yaml
- data:
    context: {enabled: false, variable_selector: []}
    desc: Evidence-based LLM judge. It must return strict JSON only.
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    model:
      completion_params: {temperature: 0.1}
      mode: chat
      name: gpt-4.1
      provider: langgenius/openai/openai
    prompt_template:
    - id: sys
      role: system
      text: "You are a security judge for an adaptive REST API pentest system.\n\nYou must evaluate only the structured evidence package.\nDo not trust agent intentions, plans, or claims.\nA vulnerability is confirmed only if the evidence directly proves exploitation.\n\nReturn strict JSON:\n{\n  \"status\": \"confirmed\",\n  \"finding_type\": \"BOLA\",\n  \"reason\": \"short explanation\",\n  \"next_action\": \"save_finding\"\n}"
    - id: user
      role: user
      text: "Evaluate this judge package and return strict JSON only:\n\n{{#17761117377640.body#}}"
    title: Judge Agent (1)
    type: llm
    variables: []
    vision: {enabled: false}
  id: '17761117804050'
```

## 7. `Update BOLA Retry State (1)` should drive loop stop

Add `should_exit_bola_loop`, and keep retry bounded.

Correct block:

```yaml
- data:
    code: "def main(\n    status: str,\n    next_action: str,\n    previous_retry_count: str = \"\",\n) -> dict:\n    try:\n        retry_count = int(str(previous_retry_count or \"0\").strip())\n    except Exception:\n        retry_count = 0\n\n    status = str(status or \"\").strip().lower()\n    next_action = str(next_action or \"\").strip().lower()\n\n    wants_retry = (\n        status == \"needs_retry\"\n        and next_action in {\"retry_same_class\", \"verify_candidate\"}\n    )\n\n    should_retry = wants_retry and retry_count < 1\n    new_retry_count = retry_count + 1 if should_retry else retry_count\n    should_exit_bola_loop = not should_retry\n\n    return {\n        \"should_retry_bola\": should_retry,\n        \"should_exit_bola_loop\": should_exit_bola_loop,\n        \"bola_retry_count\": new_retry_count,\n        \"judge_status\": status,\n        \"judge_next_action\": next_action,\n    }\n"
    code_language: python3
    isInIteration: false
    isInLoop: true
    loop_id: '1776111585046'
    outputs:
      bola_retry_count: {children: null, type: number}
      judge_next_action: {children: null, type: string}
      judge_status: {children: null, type: string}
      should_exit_bola_loop: {children: null, type: boolean}
      should_retry_bola: {children: null, type: boolean}
    title: Update BOLA Retry State (1)
    type: code
    variables:
    - value_selector: ['17761118144330', status]
      value_type: string
      variable: status
    - value_selector: ['17761118144330', next_action]
      value_type: string
      variable: next_action
    - value_selector: ['1776111585046', bola_retry_count]
      value_type: number
      variable: previous_retry_count
  id: '17761118704040'
```

## 8. `Should Retry BOLA (1)` selector

It must read from `Update BOLA Retry State (1)`.

Correct block:

```yaml
- data:
    cases:
    - case_id: 'true'
      conditions:
      - comparison_operator: is
        value: true
        varType: boolean
        variable_selector: ['17761118704040', should_retry_bola]
      id: 'true'
      logical_operator: and
    title: Should Retry BOLA (1)
    type: if-else
  id: '17761133507190'
```

## 9. Loop stop condition

For the `BOLA loop` node:

- `loop_count: 2`
- break condition should use:

```yaml
- comparison_operator: is
  value: true
  varType: boolean
  variable_selector: ['17761118704040', should_exit_bola_loop]
```

Do not use `should_retry_bola == false` directly as the break condition.

## 10. Wiring reminder

Inside the loop, keep this order:

1. `Get BOLA Worker Tasks (1)`
2. `Pick First BOLA Task (1)`
3. `BOLA Worker Agent (1)`
4. `Parse BOLA Tool Command (1)`
5. `Execute BOLA Tool (1)`
6. `BOLA Worker Result Agent (1)`
7. `Parse BOLA Worker Result (1)`
8. `Save Worker Result (1)`
9. `Extract Candidate Finding (1)`
10. `Get Judge Package (1)`
11. `Judge Agent (1)`
12. `Parse Judge Verdict (1)`
13. `Save Judge Verdict (1)`
14. `Update BOLA Retry State (1)`

Then:

- if `should_retry_bola == true`, go to the next loop iteration
- otherwise, let the loop stop and continue to `Get BOPLA Worker Tasks`
