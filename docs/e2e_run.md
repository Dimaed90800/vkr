# E2E demo run

Этот сценарий проверяет минимальный end-to-end путь:

`Dify -> Router -> Authorization Worker -> Execute Tool -> Judge -> Reporter`

## 1. Запустить backend toolbox

```bash
cd /Users/vanya/PycharmProjects/vkr/backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Toolbox должен быть доступен по `http://127.0.0.1:8000`.

## 1.1 Запуск через Docker Compose

Из корня проекта:

```bash
cd /Users/vanya/PycharmProjects/vkr
docker compose up --build
```

После старта будут доступны:

- toolbox: `http://127.0.0.1:8000`
- zap: `http://127.0.0.1:8080`
- vulnerable demo target: `http://127.0.0.1:8001`
- secure demo target: `http://127.0.0.1:8002`

Проверка health:

```bash
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8080/JSON/core/view/version/
curl http://127.0.0.1:8001/health
curl http://127.0.0.1:8002/health
```

Проверка доступности discovery endpoint:

```bash
curl -X POST http://127.0.0.1:8000/v1/recon/discovery \
  -H 'Content-Type: application/json' \
  -d '{
    "target_url": "http://demo_target_vulnerable:8001",
    "allowed_hosts": ["demo_target_vulnerable:8001"],
    "discovery_mode": "zap",
    "zap_base_url": "http://zap:8080",
    "use_spider": true,
    "use_ajax_spider": false,
    "max_depth": 2,
    "max_children": 50,
    "max_duration_sec": 120
  }'
```

## 2. Запустить demo target

Vulnerable mode:

```bash
cd /Users/vanya/PycharmProjects/vkr
uvicorn demo_target.main:app --host 0.0.0.0 --port 8001 --reload
```

Secure mode:

```bash
cd /Users/vanya/PycharmProjects/vkr
DEMO_TARGET_MODE=secure uvicorn demo_target.main:app --host 0.0.0.0 --port 8001 --reload
```

Demo target endpoint:

`GET http://127.0.0.1:8001/identity/api/v2/vehicle/veh-123/location`

Поддерживаются роли:
- `user_a`
- `user_b`

Роль может передаваться через:
- `Authorization: Bearer token-a|token-b`
- `X-Debug-Role: user_a|user_b`

## 3. Данные для Start node в Dify

Используй файлы:

- `/Users/vanya/PycharmProjects/vkr/examples/dify_inputs/start_payload.json`
- `/Users/vanya/PycharmProjects/vkr/examples/dify_inputs/roles.json`
- `/Users/vanya/PycharmProjects/vkr/examples/dify_inputs/allowed_hosts.json`
- `/Users/vanya/PycharmProjects/vkr/examples/dify_inputs/openapi_spec.json`

Минимальные значения для Start node:

- `toolbox_url`: `http://127.0.0.1:8000`
- `target_url`: `http://demo_target_vulnerable:8001`
- `openapi_url`: оставить пустым
- `openapi_spec_text`: вставить содержимое `openapi_spec.json` как текст
- `roles_json`: вставить содержимое `roles.json`
- `allowed_hosts_json`: вставить содержимое `allowed_hosts.json`
- `max_requests`: `20`
- `max_duration_sec`: `300`
- `max_retries_per_task`: `1`
- `enable_discovery`: `true`
- `discovery_mode`: `zap`
- `zap_base_url`: `http://zap:8080`
- `discovery_max_depth`: `2`
- `discovery_max_children`: `50`
- `discovery_max_duration_sec`: `120`
- `use_ajax_spider`: `false`
- `user_prompt`: `Проверь authorization/BOLA для demo target и сфокусируйся на endpoint location.`

## 4. Что должно произойти

1. `Router Agent` должен построить authorization task для vehicle location endpoint.
2. `Authorization Worker` должен выбрать `auth_test_access`.
3. Dify вызовет:

```text
POST http://127.0.0.1:8000/v1/auth/test-access
```

4. Toolbox выполнит два запроса к demo target:
- owner role: `user_a`
- other role: `user_b`

Для dockerized сценария важно:

- Dify обращается к toolbox по опубликованному адресу хоста: `http://127.0.0.1:8000`
- сам toolbox внутри Docker-сети ходит к target по service name:
  - vulnerable: `http://demo_target_vulnerable:8001`
  - secure: `http://demo_target_secure:8001`
- discovery через ZAP внутри Docker-сети ходит к ZAP по service name:
  - `http://zap:8080`

## 5. Ожидаемый результат в vulnerable mode

Ожидается:
- `owner.status_code = 200`
- `other.status_code = 200`
- `similarity >= 0.9`
- indicators содержат:
  - `same_status_code`
  - `similar_response`
  - `potential_bola`

Ориентиры:
- пример evidence: `/Users/vanya/PycharmProjects/vkr/examples/expected/evidence_success.json`
- пример verdict: `/Users/vanya/PycharmProjects/vkr/examples/expected/judge_verdict_confirmed.json`

## 6. Ожидаемый результат в secure mode

Ожидается:
- owner получает `200`
- other получает `403`
- `potential_bola` отсутствует
- Judge не должен подтверждать finding

Для secure run в Dify просто замени `target_url` на:

`http://demo_target_secure:8001`

## 7. Как понять, что сценарий сработал

Признаки успешного vulnerable run:
- в логах toolbox виден `task_id`
- в логах видно endpoint и обе роли
- в логах видны `owner_status=200` и `other_status=200`
- в логах есть `indicators=['same_status_code', 'similar_response', 'potential_bola']`
- Reporter формирует итоговый отчет с confirmed finding

Признаки успешного secure run:
- в логах видно `owner_status=200` и `other_status=403`
- `potential_bola` не появляется
- подтвержденного finding нет

## 8. Быстрый direct check без Dify

```bash
curl -X POST http://127.0.0.1:8000/v1/auth/test-access \
  -H 'Content-Type: application/json' \
  -d @/Users/vanya/PycharmProjects/vkr/examples/tasks/auth_task_request_vulnerable.json
```

## 9. Discovery-enabled run

Если OpenAPI пустой или неполный, workflow все равно может продолжить работу на discovery surface.

Минимальный discovery-enabled payload для Start node:

- `toolbox_url`: `http://127.0.0.1:8000`
- `target_url`: `http://demo_target_vulnerable:8001`
- `openapi_url`: оставить пустым
- `openapi_spec_text`: можно оставить пустым
- `roles_json`: вставить содержимое `roles.json`
- `allowed_hosts_json`: `["demo_target_vulnerable:8001"]`
- `enable_discovery`: `true`
- `discovery_mode`: `zap`
- `zap_base_url`: `http://zap:8080`
- `discovery_max_depth`: `2`
- `discovery_max_children`: `50`
- `discovery_max_duration_sec`: `120`
- `use_ajax_spider`: `false`
- `max_requests`: `20`
- `max_duration_sec`: `300`
- `max_retries_per_task`: `1`

Минимальная ручная проверка:

1. Поднять `docker compose up --build`.
2. Проверить `curl http://127.0.0.1:8080/JSON/core/view/version/`.
3. Проверить `POST /v1/recon/discovery`.
4. Запустить workflow в Dify с `enable_discovery=true`.
5. Убедиться, что `Discover Endpoints` вернул `normalized_surface`.
6. Убедиться, что `Merge Surfaces` отдал merged surface even if OpenAPI empty.
7. Убедиться, что `Plan Tasks` вернул задачи и дальше пайплайн дошел до `Judge` и `Reporter`.
