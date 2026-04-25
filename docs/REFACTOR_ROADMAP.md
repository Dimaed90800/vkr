# REFACTOR_ROADMAP.md

## Purpose

This roadmap tells an AI coding agent how to migrate the current backend to the target architecture without breaking the existing working pipeline.

## Target end state

```text
Input:
  target_url
  toolbox_url
  openapi_url/swagger_url
  roles/auth profiles
  limits/profile

Flow:
  create campaign
  ingest OpenAPI
  discover additional endpoints
  import traffic/browser traces
  build API graph
  build dependency graph
  bootstrap request corpus
  plan high-value tasks
  execute one task per loop iteration
  build evidence pack
  judge verdict
  update queue/corpus/graph/findings
  generate report from confirmed findings
```

## Phase 0 — Documentation and guardrails

Add these files to the repository root or `docs/`:

```text
CLAUDE.md
docs/BACKEND_CURRENT_STATE.md
docs/REFACTOR_ROADMAP.md
docs/ARCHITECTURE_DATA_CONTRACTS.md
docs/DIFY_BACKEND_CONTRACT.md
docs/TESTING_STRATEGY.md
```

Acceptance criteria:

```text
- Claude/Codex can understand what not to delete.
- Existing test commands are documented.
- Target architecture is clear.
```

## Phase 1 — Campaign compatibility layer

Goal: introduce a campaign-centered model without removing current `run_id` / session logic.

Add or normalize:

```text
Campaign
CampaignState
CampaignSummary
```

Minimum campaign fields:

```json
{
  "campaign_id": "cmp_...",
  "run_id": "optional legacy run id",
  "target_url": "http://target",
  "openapi_url": "http://target/openapi.json",
  "allowed_hosts": ["target"],
  "profile": "safe",
  "limits": {
    "max_requests": 1000,
    "max_duration_sec": 1800,
    "max_iterations": 50
  },
  "created_at": "...",
  "status": "running"
}
```

Acceptance criteria:

```text
- Dify can call create_campaign and receive campaign_id.
- Existing run_id still works.
- Health endpoint still works.
- No existing tests broken.
```

## Phase 2 — Request corpus service

Goal: make successful requests reusable.

Create service:

```text
backend/services/request_corpus_service.py
```

Data model:

```text
RequestCorpusItem
ResourceInstance
AuthProfileRef
```

Minimum operations:

```text
add_from_tool_result
add_from_manual_request
find_successful_by_operation
find_ids_by_resource_type
find_cross_role_candidates
find_replay_seed
```

Acceptance criteria:

```text
- Every useful request/response can be stored.
- 2xx/3xx are stored as successful seeds.
- 401/403 are stored as authorization baseline.
- 5xx are stored as bug/security candidates, not confirmed findings.
- Sensitive data is redacted.
```

## Phase 3 — API graph and dependency graph as source of planning

Goal: planner should use graph/corpus instead of only raw OpenAPI paths.

Extend existing graph service or create:

```text
api_graph_service.py
dependency_graph_service.py
```

Graph nodes:

```text
Operation
ResourceType
Parameter
AuthProfile
RequestExample
ResponseExample
ResourceInstance
FindingCandidate
```

Edges:

```text
HAS_PARAM
RETURNS_FIELD
PRODUCES
CONSUMES
REQUIRES_AUTH
OWNED_BY
MAY_TRIGGER_OWASP
HAS_EVIDENCE
```

Acceptance criteria:

```text
- OpenAPI ingest creates operation nodes.
- Runtime responses enrich operation nodes.
- IDs from responses create resource instances.
- Producer-consumer links are inferred.
```

## Phase 4 — Worker command normalization

Goal: workers do not call tools directly. Workers produce commands.

Add schema:

```text
WorkerCommand
```

Example:

```json
{
  "command_id": "cmd_...",
  "campaign_id": "cmp_...",
  "task_id": "task_...",
  "worker_class": "access_control",
  "strategy": "role_swap_object_access",
  "tool_name": "custom_request_executor",
  "operation_id": "op_...",
  "seed_request_id": "req_...",
  "inputs": {
    "owner_role": "user_a",
    "attacker_role": "user_b",
    "object_id": "123"
  },
  "budget": {
    "max_requests": 4,
    "timeout_sec": 30
  }
}
```

Acceptance criteria:

```text
- Dify can pass one command to backend.
- Backend validates command against tool capabilities.
- Invalid commands return structured error.
```

## Phase 5 — Tool result normalization

Goal: all tool wrappers return the same outer shape.

Schema:

```text
ToolResult
```

Required fields:

```text
tool_run_id
campaign_id
task_id
tool_name
status
summary
requests
responses
observations
artifacts
errors
metrics
```

Acceptance criteria:

```text
- Schemathesis wrapper returns ToolResult.
- RESTler/CATS/ASTF scaffolds return ToolResult even when degraded.
- ZAP/nuclei/httpx/ffuf wrappers can be added using same shape.
```

## Phase 6 — Backend-owned evidence builder

Goal: Dify should not build canonical evidence.

Create or harden:

```text
backend/services/evidence_builder_service.py
```

Evidence pack must include:

```text
baseline requests
attack requests
negative controls
diffs
role context
object ownership proof
raw artifact references
derived signals
missing evidence
replay instructions
```

Acceptance criteria:

```text
- EvidenceBuilder can produce judge-ready evidence from ToolResult.
- Existing judge node can consume this evidence.
- If evidence is incomplete, missing evidence is explicit.
```

## Phase 7 — Judge apply endpoint

Goal: queue updates should happen in backend.

Add or normalize:

```text
POST /v1/judge/apply
```

Input:

```text
campaign_id
task_id
evidence_pack
judge_verdict
```

Output:

```text
updated campaign summary
new pending tasks
confirmed finding id if any
rework task id if any
```

Acceptance criteria:

```text
- confirmed -> writes confirmed finding.
- rework -> creates bounded follow-up task.
- rejected -> records rejection reason.
- duplicate -> links candidate to existing finding.
```

## Phase 8 — Dify loop simplification

Target Dify loop:

```text
get_next_task
worker_command_selector
execute_worker_command
build_evidence_backend
judge
apply_judge_verdict
should_continue
```

Acceptance criteria:

```text
- Dify variables are compact.
- Full state is fetched by campaign_id when needed.
- One iteration executes one bounded command.
```

## Phase 9 — Report from backend context

Reporter should call:

```text
GET /v1/report/{campaign_id}/context
```

Context includes:

```text
target summary
tested surface
confirmed findings
replay packs
tool runs
coverage summary
limitations
```

Acceptance criteria:

```text
- Report does not include rejected/inconclusive candidates as vulnerabilities.
- Each finding has reproduction steps and remediation.
```

## Phase 10 — Cleanup and deprecation

Only after tests pass:

```text
- mark legacy endpoints as compatibility.
- remove duplicate logic gradually.
- keep experiment endpoints if needed for diploma comparison.
```
