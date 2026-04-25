# TOOL_EXECUTION_ARCHITECTURE.md

## 1. Назначение документа

Этот документ описывает, как в проекте должна работать подсистема запуска инструментов для многоагентного REST API DAST.

Цель: сделать запуск инструментов управляемым, воспроизводимым и безопасным, чтобы LLM-агенты не вызывали инструменты напрямую, а формировали ограниченные команды, которые backend валидирует, исполняет, нормализует и передаёт в Judge.

Целевая цепочка:

```text
Dify / Worker Agent
    ↓
WorkerCommand
    ↓
Backend validation
    ↓
ToolRegistry
    ↓
ToolExecutor
    ↓
ToolWrapper
    ↓
ToolResult
    ↓
Request Corpus update
    ↓
API Graph / Dependency Graph update
    ↓
EvidencePack
    ↓
Judge
    ↓
JudgeApply
    ↓
Confirmed finding / rework task / rejection
```

Главное правило:

```text
Инструменты не создают confirmed findings напрямую.
Инструменты создают observations, requests, responses и artifacts.
Уязвимость подтверждает только Judge на основе EvidencePack.
```

---

## 2. Архитектурные роли

## 2.1 Dify

Dify отвечает за orchestration и LLM-решения верхнего уровня.

Dify может:

```text
- принять входные параметры пользователя;
- вызвать создание campaign;
- вызвать OpenAPI ingest;
- вызвать discovery/surface acquisition;
- получить next task;
- вызвать worker/LLM для выбора bounded command;
- отправить command в backend;
- вызвать Judge LLM;
- вызвать apply verdict;
- вызвать report context;
- сформировать финальный README report.
```

Dify не должен:

```text
- хранить весь API graph;
- хранить весь request corpus;
- хранить raw tool logs;
- самостоятельно запускать shell-команды;
- самостоятельно решать, что finding confirmed;
- хранить всю очередь задач;
- хранить все evidence artifacts;
- обходить backend validation.
```

Dify должен передавать между узлами только компактное состояние:

```json
{
  "campaign_id": "cmp_...",
  "active_task_id": "task_...",
  "active_command_id": "cmd_...",
  "latest_tool_run_id": "toolrun_...",
  "latest_evidence_id": "ev_...",
  "latest_verdict": "rework",
  "compact_summary": {
    "pending_tasks": 12,
    "confirmed_findings": 2,
    "budget_left": 640
  }
}
```

---

## 2.2 Backend

Backend является source of truth.

Backend отвечает за:

```text
- campaign state;
- scope validation;
- OpenAPI parsing;
- surface normalization;
- API graph;
- dependency graph;
- request corpus;
- resource instances;
- task queue;
- tool registry;
- tool execution;
- raw artifact storage;
- ToolResult normalization;
- corpus update;
- graph update;
- EvidencePack construction;
- Judge verdict application;
- confirmed findings storage;
- report context aggregation.
```

Backend не должен доверять LLM-командам без проверки.

Любая команда от Dify/агента должна проходить:

```text
schema validation
scope validation
budget validation
tool capability validation
task compatibility validation
auth profile validation
seed request validation
```

---

## 2.3 Worker Agent

Worker Agent — это не инструмент и не Judge.

Worker Agent получает task и compact context, затем возвращает один bounded `WorkerCommand`.

Worker Agent может выбирать:

```text
- стратегию;
- подходящий tool_name из allowed_tools;
- seed_request_id;
- роли;
- object_id;
- ограниченный набор параметров;
- success criteria;
- budget внутри разрешённого лимита.
```

Worker Agent не должен:

```text
- запускать инструмент напрямую;
- создавать finding;
- подтверждать уязвимость;
- менять request corpus;
- менять graph;
- менять task queue напрямую;
- выходить за allowed_hosts;
- поднимать budget выше разрешённого.
```

---

## 2.4 ToolWrapper

ToolWrapper — backend-адаптер над конкретным инструментом.

Примеры:

```text
custom_request_executor
openapi_parser
zap
schemathesis
restler
cats
playwright_capture
mitmproxy_import
nuclei
httpx
ffuf
kiterunner
arjun
jwt_tool
```

Каждый wrapper обязан:

```text
- принимать нормализованный WorkerCommand;
- проверять минимальные входные данные;
- выполнять только разрешённое действие;
- сохранять raw artifacts;
- возвращать ToolResult v1;
- не создавать confirmed finding напрямую;
- не обновлять Judge verdict напрямую.
```

---

## 2.5 EvidenceBuilder

EvidenceBuilder превращает ToolResult и данные из corpus/graph в judge-ready EvidencePack.

EvidenceBuilder должен отвечать на вопрос:

```text
Какие доказательства есть?
Каких доказательств не хватает?
Можно ли воспроизвести наблюдение?
Какие baseline/attack/control requests относятся к гипотезе?
```

---

## 2.6 Judge

Judge принимает решение только на основе EvidencePack.

Вердикты:

```text
confirmed
rework
rejected
duplicate
out_of_scope
inconclusive
```

MVP может поддерживать только:

```text
confirmed
rework
rejected
```

но схема должна быть расширяемой.

---

## 2.7 JudgeApply

JudgeApply — backend-сервис, который применяет verdict.

Он делает:

```text
confirmed  -> создать confirmed finding;
rework     -> создать bounded follow-up task;
rejected   -> сохранить rejected decision;
duplicate  -> связать с существующим finding;
out_of_scope -> пометить задачу вне scope;
inconclusive -> закрыть или отложить задачу.
```

---

## 3. Главный алгоритм запуска инструмента

Одна итерация loop должна выглядеть так:

```text
1. Backend отдаёт next_task.
2. Dify/Worker Agent строит WorkerCommand.
3. Backend валидирует WorkerCommand.
4. Backend выбирает ToolWrapper через ToolRegistry.
5. ToolWrapper выполняет инструмент.
6. Backend сохраняет raw artifacts.
7. Backend нормализует результат в ToolResult.
8. Backend обновляет request corpus.
9. Backend обновляет API graph / dependency graph.
10. Backend строит EvidencePack.
11. Judge оценивает EvidencePack.
12. Backend применяет Judge verdict.
13. Backend обновляет queue/campaign summary.
```

Фундаментальное ограничение:

```text
Одна loop iteration = одна bounded command = один ToolResult = один EvidencePack = один Judge verdict.
```

Это предотвращает хаотичный параллельный запуск инструментов и упрощает отладку.

---

## 4. Campaign context

Любой запуск инструмента происходит внутри campaign.

Минимальный Campaign:

```json
{
  "campaign_id": "cmp_20260425_001",
  "legacy_run_id": "run-5037de94e560",
  "target_url": "http://host.docker.internal:8888",
  "openapi_url": "http://host.docker.internal:8888/openapi.json",
  "allowed_hosts": [
    "host.docker.internal",
    "localhost",
    "127.0.0.1"
  ],
  "profile": "safe",
  "status": "running",
  "limits": {
    "max_requests": 1500,
    "max_duration_sec": 1800,
    "max_iterations": 60,
    "max_retries_per_task": 2
  },
  "created_at": "2026-04-25T00:00:00Z"
}
```

`legacy_run_id` нужен для совместимости со старым pipeline. Новая архитектура должна использовать `campaign_id`.

---

## 5. Task model

Task — это гипотеза или техническая задача, которую нужно выполнить.

Пример access-control task:

```json
{
  "task_id": "task_bola_001",
  "campaign_id": "cmp_20260425_001",
  "class": "access_control",
  "owasp_category": "API1_BOLA",
  "strategy": "role_swap_object_access",
  "operation_id": "op_get_vehicle_by_id",
  "seed_request_id": "req_user_a_vehicle_123",
  "hypothesis": "Endpoint may miss object-level authorization checks.",
  "required_evidence": [
    "baseline_owner_access",
    "attacker_access_same_object",
    "ownership_proof",
    "negative_control"
  ],
  "preferred_tool": "custom_request_executor",
  "allowed_tools": [
    "custom_request_executor"
  ],
  "fallback_tools": [],
  "budget": {
    "max_requests": 4,
    "timeout_sec": 30
  },
  "retry_count": 0,
  "max_retries": 2,
  "status": "pending",
  "priority": 95
}
```

---

## 6. Worker classes

Не нужно делать отдельного агента на каждый OWASP API Top 10 класс.

Нужно использовать strategy worker classes:

```text
access_control
contract_fuzzing
stateful_flow
discovery_inventory
misconfiguration
ssrf_external
```

## 6.1 access_control

Покрывает:

```text
API1 BOLA
API2 Broken Authentication
API3 BOPLA
API5 BFLA
```

Типовые стратегии:

```text
role_swap_object_access
anonymous_access
expired_token_access
malformed_token_access
low_privilege_admin_endpoint_access
mass_assignment
forbidden_field_update
excessive_data_exposure
horizontal_access_matrix
vertical_access_matrix
```

Основной инструмент:

```text
custom_request_executor
```

Fallback:

```text
zap
astf
jwt_tool
```

---

## 6.2 contract_fuzzing

Покрывает:

```text
API3 BOPLA частично
API4 Unrestricted Resource Consumption частично
schema validation
unexpected 5xx
type confusion
boundary values
```

Типовые стратегии:

```text
missing_required_field
wrong_type
boundary_value
unexpected_field_injection
large_payload_safe
invalid_enum
invalid_header
invalid_query_param
```

Основные инструменты:

```text
schemathesis
cats
custom_request_executor
```

---

## 6.3 stateful_flow

Покрывает:

```text
stateful sequences
resource lifecycle
API6 sensitive business flows
invalid transitions
idempotency issues
replay abuse
```

Типовые стратегии:

```text
create_read_update_delete_sequence
replay_same_action
invalid_state_transition
double_submit
business_flow_replay
sequence_from_dependency_graph
```

Основные инструменты:

```text
restler
custom_sequence_executor
playwright_capture
```

---

## 6.4 discovery_inventory

Покрывает:

```text
API9 Improper Inventory Management
hidden endpoints
undocumented endpoints
old API versions
swagger exposure
admin/debug paths
```

Типовые стратегии:

```text
openapi_common_paths
api_wordlist_discovery
traffic_endpoint_import
browser_xhr_capture
hidden_parameter_discovery
versioned_api_discovery
```

Основные инструменты:

```text
httpx
ffuf
kiterunner
arjun
zap_spider
playwright_capture
mitmproxy_import
```

---

## 6.5 misconfiguration

Покрывает:

```text
API8 Security Misconfiguration
CORS
security headers
debug exposure
verbose errors
default panels
known exposed components
```

Основные инструменты:

```text
zap
nuclei
httpx
custom_header_checker
```

---

## 6.6 ssrf_external

Покрывает:

```text
API7 SSRF
API10 Unsafe Consumption of APIs частично
webhook/callback/fetch/import endpoints
```

Типовые стратегии:

```text
url_parameter_probe
callback_url_probe
webhook_registration_probe
external_fetch_probe
redirect_url_probe
```

Основные инструменты:

```text
custom_ssrf_checker
nuclei
custom_request_executor
```

---

## 7. WorkerCommand contract

WorkerCommand — единственный способ, которым агент просит backend запустить инструмент.

Пример:

```json
{
  "schema_version": "worker-command/v1",
  "command_id": "cmd_bola_001",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "worker_class": "access_control",
  "strategy": "role_swap_object_access",
  "tool_name": "custom_request_executor",
  "inputs": {
    "seed_request_id": "req_user_a_vehicle_123",
    "owner_role": "user_a",
    "attacker_role": "user_b",
    "object_id": "123"
  },
  "success_criteria": [
    "attacker receives 200",
    "response contains same object_id",
    "response contains sensitive fields"
  ],
  "budget": {
    "max_requests": 4,
    "timeout_sec": 30
  }
}
```

Обязательные поля:

```text
schema_version
command_id
campaign_id
task_id
worker_class
strategy
tool_name
inputs
budget
```

---

## 8. Command validation

Backend должен валидировать WorkerCommand до запуска инструмента.

Проверки:

```text
1. campaign_id существует;
2. campaign status позволяет запуск;
3. task_id существует;
4. task status == pending или running;
5. worker_class совпадает с task.class;
6. strategy разрешена для task.class;
7. tool_name входит в task.allowed_tools;
8. tool_name зарегистрирован в ToolRegistry;
9. tool capability подходит под command;
10. budget не превышает task.budget;
11. target host входит в allowed_hosts;
12. seed_request_id существует, если требуется;
13. auth profiles существуют, если требуются;
14. object_id получен из corpus/graph или явно разрешён;
15. command не дублирует уже выполненный fingerprint.
```

Пример invalid response:

```json
{
  "status": "invalid_command",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "reason": "tool_name is not allowed for this task",
  "details": {
    "tool_name": "nuclei",
    "allowed_tools": [
      "custom_request_executor"
    ]
  }
}
```

---

## 9. ToolRegistry

ToolRegistry хранит информацию о доступных инструментах.

Пример записи:

```json
{
  "tool_name": "schemathesis",
  "enabled": true,
  "capabilities": [
    "openapi_contract_testing",
    "negative_testing",
    "schema_validation",
    "unexpected_5xx_detection"
  ],
  "supported_worker_classes": [
    "contract_fuzzing"
  ],
  "requires": [
    "openapi_url"
  ],
  "max_safe_duration_sec": 300,
  "output_format": "tool-result/v1"
}
```

ToolRegistry должен уметь:

```text
- list_tools;
- get_tool_capabilities;
- check_preflight;
- validate_command;
- choose_fallback_tool;
```

---

## 10. ToolExecutor

ToolExecutor — общий backend-компонент, который запускает конкретный wrapper.

Псевдокод:

```python
class ToolExecutor:
    def execute(self, command: WorkerCommand) -> ToolResult:
        campaign = campaign_service.get(command.campaign_id)
        task = task_service.get(command.task_id)

        command_validator.validate(command, campaign, task)

        wrapper = tool_registry.get(command.tool_name)

        tool_run = tool_run_service.create(command)

        try:
            raw_result = wrapper.run(command, campaign)
            artifacts = artifact_store.save_raw(tool_run.id, raw_result)
            tool_result = wrapper.normalize(raw_result, artifacts, command)
            tool_run_service.mark_finished(tool_run.id, tool_result)
            return tool_result

        except ToolTimeout as exc:
            return tool_run_service.mark_failed(
                tool_run.id,
                error_type="timeout",
                message=str(exc)
            )

        except Exception as exc:
            return tool_run_service.mark_failed(
                tool_run.id,
                error_type="internal_error",
                message=str(exc)
            )
```

---

## 11. ToolResult contract

Все инструменты должны возвращать единый внешний формат.

```json
{
  "schema_version": "tool-result/v1",
  "tool_run_id": "toolrun_001",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "command_id": "cmd_bola_001",
  "tool_name": "custom_request_executor",
  "status": "finished",
  "summary": {
    "request_count": 3,
    "success_count": 2,
    "client_error_count": 1,
    "server_error_count": 0,
    "duration_ms": 1532
  },
  "requests": [
    {
      "request_id": "req_baseline_001",
      "role": "user_a",
      "method": "GET",
      "url": "/identity/api/v2/vehicle/123",
      "path_template": "/identity/api/v2/vehicle/{vehicleId}",
      "headers_ref": "artifact://toolrun_001/req_baseline_headers.json",
      "body_ref": null
    }
  ],
  "responses": [
    {
      "request_id": "req_baseline_001",
      "status_code": 200,
      "headers_ref": "artifact://toolrun_001/res_baseline_headers.json",
      "body_ref": "artifact://toolrun_001/res_baseline_body.json",
      "response_schema_hash": "sha256:..."
    }
  ],
  "observations": [
    {
      "type": "cross_role_same_object_access",
      "operation_id": "op_get_vehicle_by_id",
      "object_id": "123",
      "owner_role": "user_a",
      "attacker_role": "user_b",
      "confidence": 0.8
    }
  ],
  "artifacts": [
    {
      "artifact_id": "art_http_jsonl_001",
      "type": "http_exchange_jsonl",
      "path": "storage/campaigns/cmp_20260425_001/artifacts/toolrun_001/http.jsonl"
    }
  ],
  "errors": []
}
```

Статусы:

```text
finished
partial
failed
timeout
skipped
invalid_command
```

---

## 12. Raw artifacts

Нельзя терять сырые данные инструментов. Но их нельзя тащить целиком через Dify.

Хранение:

```text
storage/
  campaigns/
    cmp_20260425_001/
      tool_runs/
        toolrun_001.json
      artifacts/
        toolrun_001/
          http.jsonl
          raw_stdout.txt
          raw_stderr.txt
          zap_alerts.json
          schemathesis_cases.jsonl
          restler_bug_buckets/
          nuclei.jsonl
```

В ToolResult передаются ссылки:

```json
{
  "artifact_id": "art_zap_alerts_001",
  "type": "zap_alerts",
  "path": "storage/campaigns/cmp_20260425_001/artifacts/toolrun_001/zap_alerts.json"
}
```

---

## 13. Request Corpus update

После ToolResult backend должен извлечь полезные HTTP exchanges и сохранить их в request corpus.

RequestCorpusItem:

```json
{
  "request_id": "req_attack_001",
  "campaign_id": "cmp_20260425_001",
  "operation_id": "op_get_vehicle_by_id",
  "source_tool_run_id": "toolrun_001",
  "source": "custom_request_executor",
  "method": "GET",
  "url": "/identity/api/v2/vehicle/123",
  "path_template": "/identity/api/v2/vehicle/{vehicleId}",
  "auth_profile": "user_b",
  "headers_redacted": {
    "Authorization": "<redacted>"
  },
  "body_redacted": null,
  "status_code": 200,
  "response_body_redacted": {
    "id": "123",
    "ownerId": "user_a"
  },
  "response_schema_hash": "sha256:...",
  "extracted_ids": {
    "vehicleId": [
      "123"
    ],
    "ownerId": [
      "user_a"
    ]
  },
  "sensitive_fields": [
    "ownerId"
  ],
  "created_at": "2026-04-25T00:00:00Z"
}
```

Что сохранять:

```text
2xx/3xx -> successful request seed;
401/403 -> authorization baseline;
404 -> negative response / invalid object candidate;
409/422 -> validation/constraint signal;
429 -> rate limit signal;
5xx -> robustness/security candidate observation, но не confirmed finding.
```

Redaction обязателен для:

```text
Authorization
Cookie
Set-Cookie
X-API-Key
api_key
access_token
refresh_token
password
secret
client_secret
```

---

## 14. ResourceInstance extraction

Из request/response нужно извлекать конкретные объекты.

Пример:

```json
{
  "resource_instance_id": "res_vehicle_123",
  "campaign_id": "cmp_20260425_001",
  "resource_type": "Vehicle",
  "object_id": "123",
  "owner_role": "user_a",
  "owner_confidence": 0.85,
  "source_request_id": "req_user_a_vehicle_123",
  "source_operation_id": "op_get_vehicle_by_id",
  "observed_by_roles": [
    "user_a",
    "user_b"
  ]
}
```

Источники ownership:

```text
- object appeared in user_a collection;
- response contains ownerId == user_a;
- object was created by user_a;
- traffic/session context says user_a owns it;
- OpenAPI/semantic hints.
```

Если ownership не доказан, EvidenceBuilder должен указать `missing_evidence`.

---

## 15. API Graph update

ToolResult и corpus должны обновлять API graph.

Operation node:

```json
{
  "operation_id": "op_get_vehicle_by_id",
  "method": "GET",
  "path_template": "/identity/api/v2/vehicle/{vehicleId}",
  "sources": [
    "openapi",
    "runtime"
  ],
  "auth_required": true,
  "observed_status_codes": [
    200,
    403,
    404
  ],
  "observed_roles": [
    "user_a",
    "user_b"
  ],
  "risk_hints": [
    "object_id_in_path",
    "cross_role_access_signal"
  ],
  "owasp_candidates": [
    "API1_BOLA",
    "API3_BOPLA"
  ]
}
```

Dependency edge:

```json
{
  "edge_id": "edge_vehicle_create_get",
  "campaign_id": "cmp_20260425_001",
  "from_operation_id": "op_create_vehicle",
  "to_operation_id": "op_get_vehicle_by_id",
  "edge_type": "PRODUCES_CONSUMES",
  "producer_field": "$.id",
  "consumer_location": "path",
  "consumer_name": "vehicleId",
  "confidence": 0.9,
  "sources": [
    "openapi_schema",
    "runtime_response"
  ]
}
```

Graph update не означает finding. Это только knowledge base.

---

## 16. EvidencePack construction

EvidencePack должен быть компактным и judge-ready.

Пример BOLA EvidencePack:

```json
{
  "schema_version": "evidence-pack/v1",
  "evidence_id": "ev_bola_001",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "tool_run_ids": [
    "toolrun_001"
  ],
  "owasp_category": "API1_BOLA",
  "hypothesis": "Object-level authorization may be missing.",
  "baseline": {
    "role": "user_a",
    "request_id": "req_baseline_001",
    "status_code": 200,
    "object_id": "123",
    "operation_id": "op_get_vehicle_by_id"
  },
  "attack": {
    "role": "user_b",
    "request_id": "req_attack_001",
    "status_code": 200,
    "object_id": "123",
    "operation_id": "op_get_vehicle_by_id"
  },
  "controls": [
    {
      "type": "attacker_collection_check",
      "role": "user_b",
      "result": "object_not_listed",
      "request_id": "req_control_001"
    }
  ],
  "diff": {
    "same_object": true,
    "same_sensitive_fields": [
      "id",
      "ownerId"
    ],
    "status_code_changed": false
  },
  "derived_signals": [
    "cross_role_same_object_access",
    "sensitive_object_data_exposed"
  ],
  "missing_evidence": [],
  "replay": {
    "steps": [
      {
        "role": "user_a",
        "method": "GET",
        "url": "/identity/api/v2/vehicle/123"
      },
      {
        "role": "user_b",
        "method": "GET",
        "url": "/identity/api/v2/vehicle/123"
      }
    ]
  },
  "artifact_refs": [
    "artifact://toolrun_001/http.jsonl"
  ]
}
```

EvidenceBuilder обязан явно указывать недостающие доказательства:

```json
{
  "missing_evidence": [
    "ownership_proof",
    "negative_control"
  ]
}
```

---

## 17. Judge requirements by category

## 17.1 API1 BOLA

Confirmed только если есть:

```text
- baseline owner access;
- attacker access same object;
- proof or strong evidence of ownership;
- same object id in response;
- sensitive data or unauthorized action;
- negative control желательно;
- replay steps.
```

Если нет ownership proof:

```text
verdict = rework
```

---

## 17.2 API2 Broken Authentication

Confirmed только если есть:

```text
- endpoint должен требовать auth;
- missing/expired/malformed/tampered token accepted;
- response/action demonstrates access;
- control with valid/invalid token;
- replay steps.
```

---

## 17.3 API3 BOPLA

Excessive data exposure confirmed если:

```text
- user получил поля, которые не должны быть доступны;
- поля чувствительные;
- это подтверждено spec/role policy/semantic expectation;
- есть baseline/control.
```

Mass assignment confirmed если:

```text
- forbidden field отправлен в request;
- API принял field;
- subsequent GET показывает изменение;
- изменение влияет на privilege/ownership/business state.
```

---

## 17.4 API5 BFLA

Confirmed если:

```text
- endpoint privileged/admin/management;
- low-privileged role успешно вызвала endpoint;
- response/action имеет административный impact;
- есть role/control comparison.
```

---

## 17.5 API8 Misconfiguration

Confirmed если:

```text
- есть конкретная misconfiguration;
- она воспроизводима;
- понятен impact;
- есть affected host/endpoint;
- есть tool evidence или custom check evidence.
```

---

## 17.6 API9 Inventory

Confirmed если:

```text
- endpoint доступен runtime;
- endpoint отсутствует в OpenAPI или относится к старой версии;
- endpoint несёт security relevance;
- есть source discovery evidence.
```

---

## 18. Judge verdict contract

```json
{
  "schema_version": "judge-verdict/v1",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "evidence_id": "ev_bola_001",
  "verdict": "confirmed",
  "confidence": 0.92,
  "severity": "high",
  "reason": "The attacker role accessed the same user-owned object and received sensitive fields.",
  "missing_evidence": [],
  "rework_actions": [],
  "finding_candidate": {
    "title": "Broken Object Level Authorization on GET /vehicle/{vehicleId}",
    "owasp_category": "API1_BOLA",
    "endpoint": "/identity/api/v2/vehicle/{vehicleId}",
    "method": "GET",
    "evidence_summary": "user_b received 200 OK for vehicleId owned by user_a",
    "reproduction_steps": [
      "Authenticate as user_a and obtain vehicle id 123.",
      "Authenticate as user_b.",
      "Request GET /identity/api/v2/vehicle/123 with user_b token.",
      "Observe 200 OK and same vehicle data."
    ],
    "remediation": "Enforce object-level authorization on every access to user-owned resources."
  }
}
```

Rework example:

```json
{
  "schema_version": "judge-verdict/v1",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "evidence_id": "ev_bola_001",
  "verdict": "rework",
  "confidence": 0.61,
  "reason": "The attacker received 200, but ownership of object_id=123 is not proven.",
  "missing_evidence": [
    "ownership_proof"
  ],
  "rework_actions": [
    {
      "strategy": "prove_ownership",
      "worker_class": "access_control",
      "tool_name": "custom_request_executor",
      "inputs": {
        "owner_role": "user_a",
        "attacker_role": "user_b",
        "object_id": "123",
        "goal": "show object appears in owner collection and not in attacker collection"
      },
      "budget": {
        "max_requests": 3,
        "timeout_sec": 30
      }
    }
  ]
}
```

---

## 19. JudgeApply

JudgeApply должен быть backend endpoint/service.

Input:

```json
{
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "evidence_id": "ev_bola_001",
  "verdict": {
    "schema_version": "judge-verdict/v1",
    "verdict": "confirmed",
    "confidence": 0.92,
    "severity": "high",
    "reason": "...",
    "finding_candidate": {}
  }
}
```

Output:

```json
{
  "status": "applied",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_bola_001",
  "task_status": "confirmed",
  "created_finding_id": "finding_001",
  "created_rework_task_id": null,
  "campaign_summary": {
    "pending_tasks": 11,
    "confirmed_findings": 3,
    "budget_left": 620,
    "should_stop": false
  }
}
```

Rules:

```text
confirmed:
  - create confirmed finding;
  - mark task confirmed;
  - deduplicate similar tasks;
  - update graph finding edge.

rework:
  - create follow-up task;
  - increment retry_count;
  - enforce max_retries;
  - preserve parent_task_id.

rejected:
  - mark task rejected;
  - store reason;
  - do not report as vulnerability.

duplicate:
  - link candidate to existing finding;
  - do not create new finding.

out_of_scope:
  - mark task out_of_scope;
  - optionally suppress similar tasks.
```

---

## 20. Tool-specific execution details

## 20.1 custom_request_executor

Purpose:

```text
Precise replay, role swap, auth mutation, object id substitution, field injection, negative controls.
```

Used by:

```text
access_control
ssrf_external
stateful_flow
contract_fuzzing small targeted mutations
```

Example command:

```json
{
  "tool_name": "custom_request_executor",
  "strategy": "role_swap_object_access",
  "inputs": {
    "seed_request_id": "req_user_a_vehicle_123",
    "owner_role": "user_a",
    "attacker_role": "user_b",
    "object_id": "123"
  }
}
```

Expected behavior:

```text
1. Load seed request from corpus.
2. Reconstruct URL/body/headers.
3. Replace auth with owner_role.
4. Execute baseline request.
5. Replace auth with attacker_role.
6. Execute attack request.
7. Optionally execute collection/control requests.
8. Save all HTTP exchanges.
9. Return ToolResult.
```

---

## 20.2 Schemathesis

Purpose:

```text
OpenAPI-based property/contract testing.
```

Used by:

```text
contract_fuzzing
stateful_flow частично
```

Example command:

```json
{
  "tool_name": "schemathesis",
  "inputs": {
    "openapi_url": "http://target/openapi.json",
    "operation_id": "op_create_order",
    "auth_profile": "user_a",
    "checks": [
      "not_a_server_error",
      "status_code_conformance",
      "response_schema_conformance"
    ],
    "max_examples": 30
  },
  "budget": {
    "timeout_sec": 60
  }
}
```

Normalization:

```text
Schemathesis case -> request/response exchange
failure -> observation
unexpected 5xx -> observation
schema mismatch -> observation
```

Do not confirm finding directly.

---

## 20.3 RESTler

Purpose:

```text
Stateful REST API fuzzing and producer-consumer dependency exploration.
```

Used by:

```text
stateful_flow
contract_fuzzing limited
dependency graph enrichment
```

Example command:

```json
{
  "tool_name": "restler",
  "inputs": {
    "openapi_url": "http://target/openapi.json",
    "operation_subset": [
      "op_create_vehicle",
      "op_get_vehicle_by_id",
      "op_update_vehicle"
    ],
    "mode": "fuzz-lean"
  },
  "budget": {
    "max_duration_sec": 180,
    "max_requests": 200
  }
}
```

Normalization:

```text
RESTler sequence -> multiple RequestCorpusItems
producer-consumer discovery -> dependency edges
bug bucket -> observation
```

---

## 20.4 CATS

Purpose:

```text
Negative OpenAPI testing and fuzzing malformed inputs.
```

Used by:

```text
contract_fuzzing
```

Example command:

```json
{
  "tool_name": "cats",
  "inputs": {
    "openapi_url": "http://target/openapi.json",
    "operation_id": "op_patch_profile",
    "fuzzer_groups": [
      "body",
      "headers",
      "query"
    ]
  },
  "budget": {
    "max_requests": 100,
    "timeout_sec": 120
  }
}
```

Normalization:

```text
failed case -> observation
HTTP exchange -> corpus candidate
unexpected server error -> observation
```

---

## 20.5 OWASP ZAP

Purpose:

```text
DAST API scan, passive scan, active scan, spidering, misconfiguration hints.
```

Used by:

```text
misconfiguration
discovery_inventory
access_control fallback
```

Example command:

```json
{
  "tool_name": "zap",
  "inputs": {
    "target_url": "http://target",
    "openapi_url": "http://target/openapi.json",
    "scan_type": "api_scan",
    "policy": "safe"
  },
  "budget": {
    "max_duration_sec": 300
  }
}
```

Normalization:

```text
ZAP alert -> observation
ZAP URL -> surface endpoint candidate
ZAP request/response -> corpus candidate if useful
```

---

## 20.6 nuclei

Purpose:

```text
Known vulnerabilities, exposures, misconfiguration templates.
```

Used by:

```text
misconfiguration
ssrf_external limited
discovery_inventory limited
```

Example command:

```json
{
  "tool_name": "nuclei",
  "inputs": {
    "targets": [
      "http://target"
    ],
    "tags": [
      "exposure",
      "misconfig",
      "api"
    ],
    "severity": [
      "low",
      "medium",
      "high",
      "critical"
    ]
  },
  "budget": {
    "max_templates": 200,
    "timeout_sec": 180
  }
}
```

Normalization:

```text
template match -> observation
matched request -> artifact
matched response -> artifact
```

---

## 20.7 httpx

Purpose:

```text
Fast probing: alive, status, headers, title, redirects, tech.
```

Used by:

```text
discovery_inventory
misconfiguration
```

Example command:

```json
{
  "tool_name": "httpx",
  "inputs": {
    "urls": [
      "http://target",
      "http://target/api",
      "http://target/swagger"
    ],
    "collect": [
      "status_code",
      "headers",
      "title",
      "tech"
    ]
  },
  "budget": {
    "timeout_sec": 60,
    "max_requests": 100
  }
}
```

Normalization:

```text
alive URL -> surface candidate
headers -> misconfiguration observations
tech -> planner hints
```

---

## 20.8 ffuf / Kiterunner

Purpose:

```text
Endpoint discovery and API route discovery.
```

Used by:

```text
discovery_inventory
```

Example command:

```json
{
  "tool_name": "ffuf",
  "inputs": {
    "base_url": "http://target/api/FUZZ",
    "wordlist_profile": "api_common",
    "allowed_statuses": [
      200,
      204,
      301,
      302,
      401,
      403
    ]
  },
  "budget": {
    "max_requests": 500,
    "timeout_sec": 120
  }
}
```

Normalization:

```text
discovered path -> surface candidate
status/auth hints -> graph hints
```

---

## 20.9 Arjun

Purpose:

```text
Hidden parameter discovery.
```

Used by:

```text
discovery_inventory
contract_fuzzing
access_control limited
```

Example command:

```json
{
  "tool_name": "arjun",
  "inputs": {
    "url": "http://target/api/users",
    "method": "GET",
    "parameter_profiles": [
      "api_common",
      "authz"
    ]
  },
  "budget": {
    "max_requests": 300,
    "timeout_sec": 120
  }
}
```

Normalization:

```text
hidden param -> parameter node
hidden param -> task generation candidate
```

---

## 20.10 jwt_tool

Purpose:

```text
JWT inspection and controlled token tampering tests.
```

Used by:

```text
access_control
```

Example command:

```json
{
  "tool_name": "jwt_tool",
  "inputs": {
    "auth_profile": "user_a",
    "tests": [
      "decode_claims",
      "alg_none_probe",
      "claim_tamper_role",
      "claim_tamper_user_id"
    ]
  },
  "budget": {
    "max_requests": 20,
    "timeout_sec": 60
  }
}
```

Normalization:

```text
tampered token accepted -> observation
claim structure -> auth model hints
```

Sensitive tokens must be redacted in artifacts.

---

## 20.11 Playwright capture

Purpose:

```text
Browser-based auth flow, XHR/fetch capture, business flow discovery.
```

Used by:

```text
discovery_inventory
stateful_flow
business_flow
```

Example command:

```json
{
  "tool_name": "playwright_capture",
  "inputs": {
    "target_url": "http://target",
    "role": "user_a",
    "scenario": "login_and_click_main_flows",
    "capture_network": true
  },
  "budget": {
    "timeout_sec": 120,
    "max_actions": 30
  }
}
```

Normalization:

```text
XHR/fetch request -> RequestCorpusItem
browser flow -> sequence hint
token/cookie -> auth profile update
```

---

## 20.12 mitmproxy import

Purpose:

```text
Import captured traffic from proxy flows.
```

Used by:

```text
discovery_inventory
stateful_flow
corpus bootstrap
```

Example command:

```json
{
  "tool_name": "mitmproxy_import",
  "inputs": {
    "flow_file_ref": "artifact://traffic/user_a.flows",
    "role": "user_a"
  }
}
```

Normalization:

```text
flow -> RequestCorpusItem
flow sequence -> dependency hints
observed endpoints -> surface candidates
```

---

## 21. Tool selection matrix

| Worker class | Preferred tools | Fallback tools |
|---|---|---|
| `access_control` | `custom_request_executor` | `jwt_tool`, `zap`, `astf` |
| `contract_fuzzing` | `schemathesis`, `cats` | `custom_request_executor` |
| `stateful_flow` | `restler`, `custom_sequence_executor` | `playwright_capture` |
| `discovery_inventory` | `httpx`, `ffuf`, `kiterunner`, `arjun` | `zap_spider`, `playwright_capture`, `mitmproxy_import` |
| `misconfiguration` | `nuclei`, `zap`, `httpx` | `custom_header_checker` |
| `ssrf_external` | `custom_ssrf_checker` | `nuclei`, `custom_request_executor` |

Tool choice must be constrained by task.allowed_tools.

---

## 22. Budget control

Budget must exist at multiple levels:

```text
campaign budget
worker class budget
task budget
tool command budget
retry budget
```

Example:

```json
{
  "campaign_budget": {
    "max_requests": 1500,
    "max_duration_sec": 1800,
    "max_iterations": 60
  },
  "task_budget": {
    "max_requests": 4,
    "timeout_sec": 30
  },
  "retry_policy": {
    "max_retries_per_task": 2,
    "max_rework_depth": 2
  }
}
```

ToolExecutor must stop if:

```text
- command exceeds max_requests;
- command exceeds timeout;
- campaign budget exhausted;
- task retry limit reached;
- tool preflight failed;
- scope validation failed.
```

---

## 23. Scope and safety validation

Every tool command must be checked against scope.

Rules:

```text
1. Only allowed_hosts can be targeted.
2. Redirects outside allowed_hosts must be blocked or recorded and stopped.
3. SSRF tests must use controlled callback/canary endpoints only.
4. Resource consumption tests must respect safe profile limits.
5. ffuf/kiterunner/arjun must have request limits.
6. Active scans must respect profile: safe/balanced/aggressive.
7. Tokens and cookies must never be printed in final report.
8. Raw artifacts must be access-controlled or local-only.
```

Out-of-scope response:

```json
{
  "status": "blocked",
  "reason": "target host is outside allowed_hosts",
  "target": "http://external.example.com"
}
```

---

## 24. Deduplication

Before scheduling or executing a command, compute fingerprint:

```text
fingerprint =
  campaign_id
  task.class
  strategy
  tool_name
  operation_id
  normalized_path
  auth_profile(s)
  payload_class
  object_id if applicable
```

If the same fingerprint was already executed and produced no useful novelty, skip or lower priority.

Novelty signals:

```text
new endpoint
new role
new object_id
new status code
new response schema
new sensitive field
new dependency edge
new OWASP category
new evidence gap resolved
```

---

## 25. Dify integration pattern

Target Dify loop:

```text
Get Next Task
    ↓
Worker Command Selector
    ↓
Execute Worker Command
    ↓
Build Evidence Pack
    ↓
Judge
    ↓
Apply Judge Verdict
    ↓
Should Continue
```

Dify should call backend endpoints like:

```text
POST /v1/tasks/next
POST /v1/workers/command/validate
POST /v1/tools/execute
POST /v1/evidence/build
POST /v1/judge/apply
GET  /v1/campaigns/{campaign_id}/summary
```

Dify variables should be compact:

```text
campaign_id
task_json
worker_command_json
tool_result_summary_json
evidence_pack_json
judge_verdict_json
campaign_summary_json
```

Do not pass raw artifacts through Dify.

---

## 26. Recommended backend endpoints

MVP endpoints:

```text
POST /v1/campaigns
GET  /v1/campaigns/{campaign_id}
GET  /v1/campaigns/{campaign_id}/summary

POST /v1/ingest/openapi
POST /v1/surface/discover
POST /v1/surface/import-traffic
POST /v1/graph/build
GET  /v1/graph/{campaign_id}/summary

POST /v1/corpus/bootstrap
GET  /v1/corpus/{campaign_id}/seeds

POST /v1/tasks/plan
POST /v1/tasks/next
POST /v1/tasks/{task_id}/status

POST /v1/workers/command
POST /v1/workers/command/validate

POST /v1/tools/execute
GET  /v1/tools/registry
GET  /v1/tools/preflight

POST /v1/evidence/build
GET  /v1/evidence/{evidence_id}

POST /v1/judge/apply

GET  /v1/findings/{campaign_id}
GET  /v1/report/{campaign_id}/context
```

Compatibility endpoints can remain.

---

## 27. Storage layout for MVP

If not using PostgreSQL yet:

```text
storage/
  campaigns/
    cmp_20260425_001/
      campaign.json
      summary.json
      api_graph.json
      dependency_graph.json
      request_corpus.jsonl
      resource_instances.jsonl
      task_queue.json
      tool_runs/
        toolrun_001.json
      artifacts/
        toolrun_001/
          http.jsonl
          raw_stdout.txt
          raw_stderr.txt
      evidence/
        ev_bola_001.json
      judge_decisions.jsonl
      findings.json
      report_context.json
```

Later this can be migrated to tables:

```text
campaigns
api_operations
api_parameters
api_schema_fields
api_resource_types
api_resource_instances
api_graph_edges
request_corpus
task_queue
tool_runs
tool_artifacts
evidence_packs
judge_decisions
confirmed_findings
```

---

## 28. Error handling

All tool errors should be structured.

Example:

```json
{
  "schema_version": "tool-result/v1",
  "tool_run_id": "toolrun_002",
  "campaign_id": "cmp_20260425_001",
  "task_id": "task_contract_001",
  "tool_name": "schemathesis",
  "status": "failed",
  "summary": {
    "request_count": 0,
    "duration_ms": 1200
  },
  "requests": [],
  "responses": [],
  "observations": [],
  "artifacts": [
    {
      "type": "stderr",
      "path": "storage/campaigns/cmp_20260425_001/artifacts/toolrun_002/raw_stderr.txt"
    }
  ],
  "errors": [
    {
      "error_type": "tool_preflight_failed",
      "message": "schemathesis binary not found",
      "recoverable": true
    }
  ]
}
```

Recoverable errors can create fallback task/tool execution.

Non-recoverable errors should mark task failed with reason.

---

## 29. Observability

Every tool run should log:

```text
campaign_id
task_id
command_id
tool_run_id
tool_name
strategy
start_time
end_time
duration
status
request_count
artifact_paths
error_type
final_stop_reason
```

A diagnostics endpoint should expose:

```text
recent tool runs
failed wrappers
preflight status
budget status
queue status
last judge decisions
```

---

## 30. Implementation phases

## Phase 1 — Contracts only

Add:

```text
WorkerCommand schema
ToolResult schema
EvidencePack schema
ToolRegistry model
```

Do not rewrite all wrappers yet.

Acceptance:

```text
schemas validate examples
existing tests still pass
```

---

## Phase 2 — ToolExecutor skeleton

Add:

```text
ToolRegistry
ToolExecutor
CommandValidator
ArtifactStore
```

Wrap existing tool calls through ToolExecutor where possible.

Acceptance:

```text
one existing wrapper can run through ToolExecutor
ToolResult v1 returned
```

---

## Phase 3 — custom_request_executor

Implement the most important wrapper first.

Required strategies:

```text
replay_seed_request
role_swap_object_access
anonymous_access
forbidden_field_injection
prove_ownership
negative_control_collection_check
```

Acceptance:

```text
BOLA task can produce ToolResult
request corpus updates
EvidencePack can be built
```

---

## Phase 4 — Corpus and graph integration

After every ToolResult:

```text
update request corpus
extract resource instances
update operation observed status codes
update graph hints
```

Acceptance:

```text
successful requests are reusable as seeds
resource IDs are extracted
cross-role candidates can be found
```

---

## Phase 5 — EvidenceBuilder backend ownership

Move evidence construction to backend.

Acceptance:

```text
Dify no longer assembles canonical evidence manually
EvidencePack has missing_evidence list
```

---

## Phase 6 — JudgeApply

Add endpoint/service to apply verdicts.

Acceptance:

```text
confirmed creates finding
rework creates follow-up task
rejected stores reason
```

---

## Phase 7 — Add wrappers gradually

Add wrappers one by one:

```text
httpx
ffuf/kiterunner
nuclei
schemathesis
cats
restler
zap
playwright_capture
mitmproxy_import
arjun
jwt_tool
```

Each wrapper must return ToolResult v1.

---

## Phase 8 — Dify loop simplification

Target loop:

```text
next_task -> command -> execute -> evidence -> judge -> apply
```

Acceptance:

```text
Dify carries compact state only
backend owns source of truth
```

---

## 31. Required tests

## 31.1 Command validation tests

```text
test_command_rejects_unknown_tool
test_command_rejects_tool_not_allowed_for_task
test_command_rejects_out_of_scope_host
test_command_rejects_budget_excess
test_command_accepts_valid_access_control_command
```

---

## 31.2 ToolResult tests

```text
test_custom_executor_returns_tool_result_v1
test_failed_tool_returns_structured_error
test_tool_result_artifacts_are_saved
test_tool_result_requests_are_redacted
```

---

## 31.3 Corpus update tests

```text
test_2xx_response_saved_as_seed
test_403_response_saved_as_auth_baseline
test_authorization_header_redacted
test_object_id_extracted_from_path
test_object_id_extracted_from_response
```

---

## 31.4 Graph update tests

```text
test_operation_observed_status_codes_updated
test_cross_role_signal_added_to_operation
test_resource_instance_created_from_response
test_dependency_edge_created_from_producer_consumer
```

---

## 31.5 EvidenceBuilder tests

```text
test_bola_evidence_contains_baseline_and_attack
test_missing_ownership_proof_marked_as_missing_evidence
test_negative_control_included_when_available
test_evidence_pack_contains_replay_steps
```

---

## 31.6 JudgeApply tests

```text
test_confirmed_verdict_creates_finding
test_rework_verdict_creates_followup_task
test_rejected_verdict_does_not_create_finding
test_duplicate_verdict_links_existing_finding
```

---

## 32. Prompt guidance for Claude/Codex

When asking Claude/Codex to implement this subsystem, use phased prompts.

Good prompt:

```text
Read:
- CLAUDE.md
- docs/TOOL_EXECUTION_ARCHITECTURE.md
- docs/ARCHITECTURE_DATA_CONTRACTS.md
- docs/DIFY_BACKEND_CONTRACT.md

Implement only Phase 2:
- ToolRegistry
- ToolExecutor skeleton
- CommandValidator
- ArtifactStore
- one adapter for existing custom request execution path if available

Do not:
- rewrite Dify workflow
- remove legacy endpoints
- create confirmed findings directly from tools
- change Judge contract

Add tests:
- command validation
- ToolResult v1 shape
- artifact storage

Stop after this phase and summarize changed files.
```

Bad prompt:

```text
Переделай backend под новую архитектуру.
```

This is too broad and may cause destructive rewrites.

---

## 33. Summary

The target tool execution architecture is:

```text
Agent does not execute tools.
Agent emits WorkerCommand.
Backend validates WorkerCommand.
ToolExecutor runs a ToolWrapper.
ToolWrapper returns ToolResult.
Backend stores artifacts, updates corpus and graph.
EvidenceBuilder builds EvidencePack.
Judge confirms/reworks/rejects.
JudgeApply updates findings and queue.
Reporter reads confirmed findings only.
```

This structure allows the system to:

```text
- reuse successful requests;
- reduce useless scans;
- avoid false positives;
- preserve evidence;
- support many tools through one interface;
- keep Dify lightweight;
- make the backend the source of truth;
- generate reliable reports.
```

---

## 34. Long-running tools and fuzzing jobs

Some tools must not be treated as immediate request/response tools.

Long-running tools:

```text
RESTler
Schemathesis with many examples
CATS
OWASP ZAP active scan
nuclei with many templates
ffuf / Kiterunner with large wordlists
Playwright crawl
```

These tools run as `ToolRun` jobs.

### 34.1 Why this is needed

Fuzzers and scanners can produce many requests and a lot of noise:

```text
ordinary 400/422 responses
expected 401/403 responses
single 500 errors
schema mismatches
scanner alerts
partial sequences
timeouts
```

Most of this must not go directly to Judge.

Correct flow:

```text
Agent emits WorkerCommand
  ↓
Backend starts ToolRun
  ↓
Backend returns tool_run_id
  ↓
Tool runs with budget
  ↓
Backend saves raw artifacts
  ↓
Backend normalizes ToolResult
  ↓
Backend creates Observations
  ↓
Corpus / Graph are updated
  ↓
Agent triages signals and plans verification
  ↓
EvidenceBuilder creates EvidencePack only for judge-worthy candidates
  ↓
Judge evaluates EvidencePack
```

### 34.2 ToolRun start response

```json
{
  "status": "accepted",
  "execution_mode": "async",
  "tool_run_id": "toolrun_schemathesis_001",
  "campaign_id": "cmp_001",
  "task_id": "task_contract_001",
  "tool_name": "schemathesis",
  "state": "running",
  "poll_after_sec": 5
}
```

### 34.3 ToolRun status response

```json
{
  "tool_run_id": "toolrun_schemathesis_001",
  "status": "running",
  "progress": {
    "requests_sent": 42,
    "max_requests": 100,
    "elapsed_sec": 27
  },
  "partial_summary": {
    "observations_count": 2,
    "server_errors": 1,
    "schema_mismatches": 1
  }
}
```

### 34.4 Finished ToolRun response

```json
{
  "tool_run_id": "toolrun_schemathesis_001",
  "status": "finished",
  "result_ready": true,
  "summary": {
    "requests_sent": 100,
    "observations_count": 4,
    "server_errors": 1,
    "schema_mismatches": 2,
    "auth_anomalies": 1
  }
}
```

### 34.5 Collecting result

```http
POST /v1/tools/runs/{tool_run_id}/collect
```

The collect endpoint returns or creates `ToolResult v1`.

### 34.6 Fuzzing does not directly create findings

Examples:

```text
Schemathesis found one 500
  -> Observation: unexpected_500
  -> usually VerificationPlan: replay_minimized_payload
  -> not confirmed finding yet

ZAP found CORS alert
  -> Observation: zap_alert
  -> VerificationPlan: cors_replay_validation
  -> not confirmed finding yet

RESTler found sequence
  -> Corpus seed + dependency edge
  -> maybe Observation
  -> not confirmed finding by itself
```

### 34.7 Recommended fuzzing modes

```text
smoke:
  10-20 requests, checks that tool works

targeted:
  one endpoint or small endpoint group, 30-100 requests

bounded:
  high-risk operations only, strict time/request budget

deep:
  long run, should be explicit and not part of normal loop iteration
```

Agents should usually choose `smoke`, `targeted`, or `bounded`. `deep` runs should be explicit.

---

## 35. Tool signals vs agent verification

Agents are not just tool launchers.

Tools produce signals:

```text
successful request
unexpected 500
schema mismatch
auth anomaly
ZAP alert
nuclei match
discovered endpoint
hidden parameter
cross-role access signal
state changed after invalid request
```

Agents convert signals into verification/exploitation plans.

Correct model:

```text
Tool signal
  ↓
Observation
  ↓
Agent interpretation
  ↓
VerificationPlan
  ↓
Backend executes bounded commands
  ↓
EvidenceBuilder creates proof
  ↓
Judge decides
```

### 35.1 BOLA example

```text
Signal:
  user_a successfully accessed /vehicle/123

Agent hypothesis:
  endpoint may have BOLA

Verification:
  replay same object as user_b

Judge says rework:
  ownership proof missing

Agent follow-up:
  get user_a collection
  get user_b collection
  prove object is in owner collection but not attacker collection

Evidence:
  baseline + attack + ownership proof + negative control

Judge:
  confirmed
```

### 35.2 Schemathesis 500 example

```text
Signal:
  POST /orders with negative quantity returns 500

Agent interpretation:
  single 500 is not enough

Verification:
  replay minimized payload
  check reproducibility
  check sensitive error/state change/resource impact

Judge:
  confirmed only if security impact is shown,
  otherwise rejected or inconclusive
```

### 35.3 ZAP CORS example

```text
Signal:
  ZAP CORS alert

Agent verification:
  replay with controlled Origin
  check Access-Control-Allow-Origin
  check Access-Control-Allow-Credentials
  check whether sensitive endpoint is affected

Judge:
  confirms only if misconfiguration is exploitable or security-relevant
```

### 35.4 Updated loop rules

For synchronous tools:

```text
one WorkerCommand -> one ToolResult -> observations -> optional EvidencePack -> Judge
```

For asynchronous tools:

```text
one WorkerCommand -> one ToolRun -> poll/collect -> ToolResult -> observations -> optional EvidencePack -> Judge
```

For both:

```text
ToolResult is never a confirmed finding by itself.
```
