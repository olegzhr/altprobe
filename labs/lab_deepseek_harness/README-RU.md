# lab_deepseek_harness: DeepSeek Harness + Falco + Suricata + OpenSearch

Экспериментальная лаба: реальный `dsh --profile headless` в контейнере,
Anthropic-совместимый мок-провайдер (`DEEPSEEK_BASE_URL`), настоящие Falco и
Suricata, Altprobe и OpenSearch. OTel у DSH нет, поэтому в этой лабе только OCSF.

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
| `agent` | Node 22 + `@deepseek-ai/dsh`, `dsh --profile headless "<task>"`, провайдер — мок на `mock:4010` (`DEEPSEEK_BASE_URL`) |
| `mock` | Anthropic Messages API (SSE + `tool_use` Bash), `labs/lab_deepseek_harness/mock/mock_anthropic.py` |
| `tls` | локальный TLS с сертификатом `api.openai.com` |
| `falco` | Falco 0.38.2, modern eBPF |
| `suricata` | Suricata 7.0 в netns агента |
| `shipper` | Falco/Suricata → Redis |
| `altprobe` | пакет 1.0.2 из GitHub release, OCSF в OpenSearch |
| `opensearch` | OCSF-индексы, `127.0.0.1:19200` |

## Статус (31.10.2026)

- `dsh headless` запускается и получает ответ мока; в логе агента —
  `Fetched the OpenAI models endpoint with curl.`
- Suricata видит `api.openai.com` в EVE (SNI).
- **Falco не отдаёт `evt.type=connect`** на этом хосте (видит `clone`/`execve`
  для `curl`, но не connect), поэтому `outbound_ai` по runtime→network в этой
  лабе пока не формируется. Это тот же класс проблемы, что и в `lab_outbound`:
  нужен полный `proc.apid`/connect-фильтр на стороне Falco.
- Prempti для DSH не подключается (поддерживается Claude; Codex — экспериментально).
