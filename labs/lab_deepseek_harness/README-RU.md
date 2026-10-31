# lab_deepseek_harness: DeepSeek Harness + OTel traces + OpenSearch

Минимальная лаба: реальный `dsh --profile headless` с плагином
[`@loongsuite/dsh-plugin`](https://www.npmjs.com/package/@loongsuite/dsh-plugin),
OTLP-приёмник Altprobe и OpenSearch. Без Falco/Suricata/Prempti.

```
dsh 0.1.7 (headless) ── @loongsuite/dsh-plugin ── OTLP/HTTP ──► altprobe /v1/traces
        │                                                        │
        └── Anthropic-совместимый мок (DEEPSEEK_BASE_URL)        ▼
                                                         otel-v1-traces-*
```

## Запуск

```bash
docker compose -f labs/lab_deepseek_harness/docker-compose.yaml up -d --build
```

Остановить:

```bash
docker compose -f labs/lab_deepseek_harness/docker-compose.yaml down
```

## Что внутри

| Сервис | Роль |
|---|---|
| `agent` | Node 22 + `@deepseek-ai/dsh` 0.1.7-rc.2; профиль `headless`, плагин `@loongsuite/dsh-plugin`; провайдер — мок на `mock:4010` |
| `mock` | Anthropic Messages API (SSE + `tool_use` Bash), `labs/lab_deepseek_harness/mock/mock_anthropic.py` |
| `altprobe` | пакет 1.0.2 из GitHub release; `TRACE_MODE=external`, принимает `/v1/traces` и `/v1/logs` |
| `opensearch` | `otel-v1-traces-*` + OCSF, `127.0.0.1:19200` |
| `opensearch-dashboards` | UI, `127.0.0.1:5601` |

## OTel

Плагин LoongSuite строит GenAI-трейсы по OTel semconv и отправляет OTLP/HTTP:

- `OTEL_SERVICE_NAME=deepseek-harness`
- `OTEL_EXPORTER_OTLP_ENDPOINT=http://altprobe:4318`
- иерархия спанов: `ENTRY` → `AGENT` → `STEP` → `LLM`/`TOOL`
- метрики `gen_ai.client.token.usage`/`operation.duration` плагин тоже шлёт на
  `/v1/metrics`; Altprobe их не принимает, это ожидаемые ошибки экспортёра.

Проверка:

```bash
curl -s 'http://127.0.0.1:19200/otel-v1-traces-*/_count'
curl -s 'http://127.0.0.1:19200/otel-v1-traces-*/_search?size=3&pretty'
```

Ожидаемо: документы со спанами `invoke_agent deepseek-harness`,
`chat deepseek-flash`, `react step`.

## Почему LoongSuite, а не официальный плагин

`@deepseek-ai/dsh-session-telemetry-otel` 0.0.1-rc.1 требует peer-пакет
`@deepseek-ai/dsh-user-id`, которого нет в DSH 0.1.7/0.2.1 (переименован в
`dsh-anonymous-user-id`), поэтому плагин не активируется. LoongSuite ставится
штатно через `dsh plugin add` и даёт полноценные трейсы.
