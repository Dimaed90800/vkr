# Worker Agent Contracts

These are the strict JSON contracts for LLM worker agents in Dify.

Use them when replacing procedural `Code + HTTP` sequences with actual worker agents.

## BOLA Worker Agent

### Input

The agent should receive:

- one `worker task` JSON
- one short instruction:
  - `prepare tool command`
  - or `summarize tool result`

### Output Mode 1. `tool_command`

```json
{
  "mode": "tool_command",
  "tool_name": "probe_same_object_across_roles",
  "arguments": {
    "session_id": 159,
    "owner_role": "user_a",
    "other_role": "user_b",
    "endpoint": "http://host.docker.internal:8888/identity/api/v2/vehicle/abc/location",
    "method": "GET"
  }
}
```

### Output Mode 2. `worker_result`

```json
{
  "mode": "worker_result",
  "worker_type": "replay_agent",
  "tool_name": "probe_same_object_across_roles",
  "vulnerability_class": "BOLA",
  "task_id": "bola_probe::vehicle::abc::user_a::user_b",
  "summary": "Both roles received successful responses for the same object endpoint.",
  "result": {
    "session_id": 159,
    "owner_observation": {"id": 3134, "status_code": 200},
    "other_observation": {"id": 3135, "status_code": 200},
    "analysis": {"inference": "possible_bola"}
  }
}
```

### Output Mode 3. `error`

```json
{
  "mode": "error",
  "reason": "short explanation"
}
```

## Practical Embedding In Dify

Inside `wf-agentic-main`, replace the direct BOLA execution chain with:

1. `Get BOLA Worker Tasks`
2. `Pick First BOLA Task`
3. `LLM` — `BOLA Worker Agent`
4. `Code` — parse worker tool command JSON
5. `HTTP Request` — `POST /agentic/tools/execute`
6. `LLM` — `BOLA Worker Agent` again, now in `summarize tool result` mode
7. `Code` — parse worker result JSON
8. `HTTP Request` — `POST /agentic/session/{session_id}/worker-result`
9. `Judge Agent`

This keeps:

- backend as execution environment
- LLM as real attacking worker
- judge as evidence-based verifier

## BOPLA Worker Agent

### Input

The agent should receive:

- one `worker task` JSON
- one short instruction:
  - `prepare tool command`
  - or `summarize tool result`

### Output Mode 1. `tool_command`

```json
{
  "mode": "tool_command",
  "tool_name": "infer_bopla",
  "arguments": {
    "observation_id": 101,
    "suspected_fields": ["email", "role", "available_credit"]
  }
}
```

### Output Mode 2. `worker_result`

```json
{
  "mode": "worker_result",
  "worker_type": "exposure_agent",
  "tool_name": "infer_bopla",
  "vulnerability_class": "BOPLA",
  "task_id": "bopla_probe::101",
  "summary": "The response exposes sensitive fields including email and role.",
  "result": {
    "observation": {"id": 101, "status_code": 200},
    "analysis": {"inference": "possible_bopla", "exposed_fields": ["email", "role"]}
  }
}
```

### Output Mode 3. `error`

```json
{
  "mode": "error",
  "reason": "short explanation"
}
```

## Practical Embedding For BOPLA

Inside `wf-agentic-main`, add the BOPLA branch after the BOLA branch:

1. `Get BOPLA Worker Tasks`
2. `Pick First BOPLA Task`
3. `LLM` — `BOPLA Worker Agent`
4. `Code` — parse worker tool command JSON
5. `HTTP Request` — `POST /agentic/tools/execute`
6. `LLM` — `BOPLA Worker Agent` again, now in `summarize tool result` mode
7. `Code` — parse worker result JSON
8. `HTTP Request` — `POST /agentic/session/{session_id}/worker-result`
9. `Judge Agent`
