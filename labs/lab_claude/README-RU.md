# lab_claude: Claude Code + Prempti + Falco + Suricata + OTel logs

Полный стек вокруг Claude Code: реальные Falco, Suricata и Prempti, приёмник
OTLP на Altprobe и OpenSearch. В отличие от `lab_outbound`, здесь включена
телеметрия Claude Code: логи (`/v1/logs`) попадают в `otel-logs-*`, а спаны
(`/v1/traces`) — в `otel-v1-traces-*`.

```
Claude Code ── OTLP logs ──────────────► altprobe /v1/logs ──► otel-logs-*
   │ hook                                        ▲
Prempti ── log_agent ────────────────────────────┤
   │                                             │
   └─ curl → TLS (SNI api.openai.com)            │
Falco ── log_falco ──────────────────────────────┤
Suricata ── log_suri ────────────────────────────┘
                                             OCSF → OpenSearch
```

## Запуск

Из корня репозитория `altprobe`:

```bash
docker compose -f labs/lab_claude/docker-compose.yaml up -d --build
```

Образ `altprobe` собирается из GitHub release `v1.0.2` с проверкой по
`SHA256SUMS`. Если релиз обновился, а Docker закешировал слой установки пакета,
пересоберите приёмник:

```bash
docker compose -f labs/lab_claude/docker-compose.yaml build --no-cache altprobe
docker compose -f labs/lab_claude/docker-compose.yaml up -d altprobe
```

Порты: OpenSearch `127.0.0.1:19200`, Dashboards `127.0.0.1:5601`.

Остановить, сохранив данные:

```bash
docker compose -f labs/lab_claude/docker-compose.yaml down
```

## Что внутри

| Сервис | Роль |
|---|---|
| `claude` | Claude Code 2.1.316 + Prempti 0.2.1 (`pid: host`), провайдер — мок Anthropic API; экспортирует OTLP-логи |
| `mock` | Anthropic Messages API (SSE + `tool_use` Bash), `labs/lab_claude/mock/mock_anthropic.py` |
| `tls` | локальный TLS с сертификатом `api.openai.com` |
| `falco` | Falco 0.38.2, modern eBPF, JSON в `/var/log/falco/events.json` |
| `suricata` | Suricata 7.0 в netns агента, EVE JSON |
| `shipper` | раскладывает Falco/Suricata/Prempti в Redis (`log_falco`, `log_suri`, `log_agent`) |
| `altprobe` | пакет 1.0.2 из release + конфиг лабы; принимает `/v1/traces` и `/v1/logs` |
| `opensearch` | OCSF + `otel-logs-*` + `otel-v1-traces-*` |

## Проверка

```bash
# сервисы
docker compose -f labs/lab_claude/docker-compose.yaml ps

# логи Claude дошли до приёмника
curl -s 'http://127.0.0.1:19200/otel-logs-*/_count'

# пример записи
curl -s 'http://127.0.0.1:19200/otel-logs-*/_search?size=1&pretty'

# приёмник жив
docker exec lab-claude-agent curl -s -o /dev/null -w '%{http_code}\n' \
  -X POST http://altprobe:4318/v1/logs -H 'Content-Type: application/json' \
  -d '{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"timeUnixNano":"1793470000000000000","body":{"stringValue":"probe"}}]}]}]}'
```

Ожидаемо: `200` на `/v1/logs` (раньше был `404`), в `otel-logs-*` появляются
записи `claude_code.*` со `scope.name=com.anthropic.claude_code.events`,
`session.id`, моделью и токенами.

## OTel-логи и что они дают

- `POST /v1/logs` принимает OTLP/JSON и protobuf, gzip, общий лимит тела;
- документы пишутся **как логи** в `otel-logs-*` (шаблон
  `opensearch/templates/otel_logs_template.json`), без синтетических спанов и
  без trace-триггеров;
- Alertflex sink для логов не нужен — достаточно OpenSearch;
- Prempti по-прежнему нужен для `tool.input_command`, `agent_decision` и
  привязки к PID; OTel-логи дают сессии, модель, токены и факты вызовов
  инструментов без hook'ов.

## Заметки

- `CLAUDE_CODE_ENABLE_TELEMETRY=1`, `OTEL_LOGS_EXPORTER=otlp`,
  `OTEL_EXPORTER_OTLP_LOGS_ENDPOINT=http://altprobe:4318/v1/logs`; метрики
  отключены (`OTEL_METRICS_EXPORTER=none`).
- Шаблон `otel-logs` регистрируется `opensearch-init`.
- Для локальной проверки приёмника без агента можно отправить лог из контейнера
  `claude` (команда выше).
