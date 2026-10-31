# lab_codex: Codex CLI + OTLP-приёмник + OpenSearch

Минимальная лаба: реальный `codex exec` против мока OpenAI Responses API,
Altprobe с OTLP-приёмником и OpenSearch. Без Falco/Suricata/Prempti.

## Запуск

```bash
docker compose -f labs/lab_codex/docker-compose.yaml up -d --build
```

Остановить:

```bash
docker compose -f labs/lab_codex/docker-compose.yaml down
```

## Что внутри

| Сервис | Роль |
|---|---|
| `agent` | Node 22 + `@openai/codex`; `codex exec`, провайдер — мок Responses API на `mock:4010`, `[otel]` настроен на `http://altprobe:4318/v1/logs` |
| `mock` | OpenAI Responses API (SSE + `function_call` exec), `labs/lab_codex/mock/mock_codex.py` |
| `altprobe` | пакет 1.0.2 из release; `TRACE_MODE=external`, принимает `/v1/traces` и `/v1/logs` |
| `opensearch` | OCSF + `otel-logs-*`/`otel-v1-traces-*`, `127.0.0.1:19200` |
| `opensearch-dashboards` | UI, `127.0.0.1:5601` |

## Статус проверки (31.10.2026)

- Codex CLI **работает**: `codex exec` получает от мока `function_call`,
  выполняет реальный `exec_command` (`curl ...` succeeded), возвращает финальный
  ответ; в логе агента видно `exec ... succeeded`.
- Codex генерирует OTel-события (`codex.conversation_starts`,
  `codex.api_request`, `codex.sse_event`, `codex.tool_decision`,
  `codex.tool_result`), но в `codex exec` 0.166 они пишутся только в stderr
  (`codex_otel.log_only`), а экспортёр по `[otel]` не отправляет их на
  `/v1/logs`: проверены `protocol = "binary"` и `"json"`, endpoint с `/v1/logs`
  и без — `otel-logs-*` остаётся пустым. Конфиг валиден (`--strict-config`
  проходит), значит это ограничение текущего `codex exec`, а не схемы.
- В лабе при необходимости можно смотреть события в `docker logs lab-codex-agent`.

## Конфиг

`agent/config.toml`:

```toml
model = "gpt-5-codex"
model_provider = "mock"

[model_providers.mock]
name = "mock"
base_url = "http://mock:4010/v1"
env_key = "OPENAI_API_KEY"
wire_api = "responses"

[otel]
environment = "dev"
log_user_prompt = false
exporter = { otlp-http = { endpoint = "http://altprobe:4318/v1/logs", protocol = "binary" } }
```

Мок отдаёт `function_call` с аргументом `cmd` (Codex 0.166) и финальный
`output_text` после `function_call_output`.
