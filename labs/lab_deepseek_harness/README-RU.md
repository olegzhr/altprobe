# lab_deepseek_harness: DeepSeek Harness + OTLP + OpenSearch

Минимальная лаба: реальный `dsh --profile headless` и OTLP-приёмник Altprobe.
Никаких Falco/Suricata/Prempti/shipper — только агент, мок-провайдер, Altprobe
и OpenSearch.

```
dsh headless --json ──► otel_push.js ──► altprobe /v1/logs ──► otel-logs-*
        │
        └── Anthropic-совместимый мок (DEEPSEEK_BASE_URL)
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
| `agent` | Node 22 + `@deepseek-ai/dsh`; `dsh --profile headless --json`, провайдер — мок на `mock:4010` (`DEEPSEEK_BASE_URL`) |
| `mock` | Anthropic Messages API (SSE + `tool_use` Bash), `labs/lab_deepseek_harness/mock/mock_anthropic.py` |
| `altprobe` | пакет 1.0.2 из GitHub release; `TRACE_MODE=external`, принимает `/v1/traces` и `/v1/logs` |
| `opensearch` | OCSF + `otel-logs-*`, `127.0.0.1:19200` |
| `opensearch-dashboards` | UI, `127.0.0.1:5601` |

## OTel

`dsh` не экспортирует OTel сам, поэтому `agent/run.sh` сохраняет поток
`dsh --json` в `dsh-events.jsonl`, а stderr — в `dsh-run.log`.
`agent/otel_push.js` превращает **оба** источника в OTLP-logs и отправляет на
`http://altprobe:4318/v1/logs`:

- события harness (`session`, `status`, `tool_call`, `tool_result`) —
  `event.name` = тип события, JSON в `body`;
- диагностика запуска — `event.name=dsh.log`.

В результате в `otel-logs-*` видны и события, и лог прогона.

Проверка:

```bash
curl -s 'http://127.0.0.1:19200/otel-logs-*/_count'
curl -s 'http://127.0.0.1:19200/otel-logs-*/_search?size=1&pretty'
```

Ожидаемо: `[lab] OTLP logs: 200` в логе агента и документы в `otel-logs-*`.
