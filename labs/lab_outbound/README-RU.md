# lab_outbound: Falco + Suricata + Prempti + OpenSearch + Altprobe

Docker Compose-лаб с настоящими компонентами (без WSL-процессов и без
эмуляторов сенсоров):

```
Claude Code (реальный, провайдер — мок Anthropic API)
   │ hook
Prempti (falco-плагин + interceptor + правила)  ── log_agent ─┐
   │                                                          │
   └─ curl → локальный TLS-сервер (SNI api.openai.com)        │
        │                                                     │
Falco (modern eBPF, host) ── log_falco ───────────────────────┤
Suricata (AF_PACKET, netns claude) ── log_suri ───────────────┤
                                                              ▼
                                                   altprobe (OutboundCorrelator)
                                                              │ OCSF
                                                              ▼
                                                      OpenSearch (:19200)
```

## Запуск

Из корня репозитория `altprobe`:

```bash
docker compose -f labs/lab_outbound/docker-compose.yaml up -d --build
```

Образ `altprobe` собирается **из пакета GitHub release** `olegzhr/altprobe`
тега `v1.0.2`: Dockerfile скачивает `altprobe_1.0.2_amd64.deb` и проверяет его
по `SHA256SUMS` из того же релиза, затем накладывает конфиг лабы из
`labs/lab_outbound/altprobe/etc/`. Локально собранный бинарник больше не нужен.

Требования: Docker Desktop с Linux-контейнерами; BTF в ядре (в WSL2 есть:
`/sys/kernel/btf/vmlinux`). Первая сборка качает образы Falco, Suricata,
OpenSearch и собирает `claude` (Claude Code + Prempti).

Остановить, сохранив данные:

```bash
docker compose -f labs/lab_outbound/docker-compose.yaml down
```

## Что внутри

| Сервис | Роль |
|---|---|
| `claude` | Claude Code + Prempti в одном контейнере (`pid: host`), hook и interceptor видят PID агента; провайдер — мок Anthropic API на `mock:4010` |
| `mock` | Anthropic Messages API (SSE + `tool_use` Bash) из `labs/lab_outbound/mock/mock_anthropic.py` |
| `tls` | локальный TLS-сервер с сертификатом `api.openai.com` — стабильная замена внешнему egress |
| `falco` | настоящий Falco 0.38.2, modern eBPF, JSON в `/var/log/falco/events.json` |
| `suricata` | настоящая Suricata 7.0, `network_mode: service:claude`, EVE JSON |
| `shipper` | читает три файла и раскладывает события в Redis (`log_falco`, `log_suri`, `log_agent`) |
| `altprobe` | пакет 1.0.2 из GitHub release + конфиг лабы: `sources.agent_*`, `correlator.inbound/outbound`, trace-приёмник |
| `opensearch` | OCSF-документы, порт `127.0.0.1:19200` |

## Проверка

```bash
# статус
docker compose -f labs/lab_outbound/docker-compose.yaml ps

# Falco поймал connect
docker run --rm -v af-prempti-real_falco-logs:/logs alpine:3.20 sh -c "grep -c 'lab connect' /logs/events.json"

# Suricata увидела TLS SNI
docker run --rm -v af-prempti-real_suricata-logs:/suri alpine:3.20 sh -c "grep -o '\"sni\":\"[^\"]*\"' /suri/eve.json | sort | uniq -c"

# Prempti пишет coding_agent-события
docker exec lab-real-claude sh -c "tail -1 /home/lab/.prempti/log/falco.log"

# OCSF в OpenSearch
docker run --rm --network af-prempti-real_default python:3.12-slim python -c "import urllib.request;print(urllib.request.urlopen('http://opensearch:9200/_cat/indices?h=index,docs.count').read().decode())"
```

## Текущий статус (31.10.2026)

Работает и проверено:

- все сервисы поднимаются; OpenSearch healthy, индексы OCSF создаются;
- `altprobe` в образе — из GitHub release (`dpkg -s altprobe` → 1.0.2);
- настоящий Falco пишет `connect`-события (`fd.sip`, `fd.sport`, `proc.pid/ppid`, `container.name=lab-real-claude`);
- настоящая Suricata логирует TLS с `sni=api.openai.com`;
- настоящий Prempti установлен в контейнере с Claude, hook зарегистрирован, события `source: coding_agent` пишутся в `~/.prempti/log/falco.log` и уходят в `log_agent`;
- **OTEL-приёмник оставлен только для traces** (`POST /v1/traces`); OTLP logs и
  metrics не поддерживаются. Для трейсов используется `POST /api/v1/traces/{asset}`
  в Alertflex (см. `sql/triggers-claude.sql` в `rain-alertflex`);
- реальные findings `outbound_ai` (runtime → network) есть в `ocsf-1.1.0-6003-api_activity-*` (`match_method=tuple+time`, `delta_ms` сотни мс).

Открытый вопрос: связка **agent → runtime** для живых событий пока не проставляется
(`agent_match`), потому что `curl` — внук агента (`claude → sh → curl`), а Falco
не отдаёт `proc.apid` в JSON. Синтетическая пара в Redis коррелирует корректно
(`agent_pid+time`), значит логика работает; нужен полный `pid→ppid`-реестр из
spawn-событий Falco (или `proc.aname`), после чего `agent_match` появится и для
реальной цепочки. Контейнерный fallback убран по требованию (в проде Claude не в
контейнере).

Полный список открытых пунктов и приоритеты — в [labs/README.md](../README.md).
Дашборды: **http://localhost:5601** (индексы `ocsf-*`, `otel-v1-traces-*`).
При старте лабы `opensearch-init` ставит OCSF-шаблоны, а
`opensearch-dashboards-init` импортирует 20 готовых дашбордов
(`ocsf-outbound-ai`, `altprobe-agent-correlations`, `ocsf-siem-overview`,
`altprobe-otel-traces` и др.) из `labs/lab_outbound/opensearch/dashboards`.

## Заметки

- Мок-провайдер нужен, чтобы не логиниться в Claude Code; при наличии логина
  можно заменить `ANTHROPIC_BASE_URL` на реальный и убрать `mock`.
- `tls`-сервер самоподписанный; curl в лабе использует `-k` и
  `--connect-to api.openai.com:443:tls:443`.
- Конфиг лабы — `labs/lab_outbound/altprobe/etc/altprobe.yaml`; он копируется в
  образ поверх пакета. Параметры корреляции: `correlator.inbound`
  (proxy/API) и `correlator.outbound` (Falco runtime → network + agent).
