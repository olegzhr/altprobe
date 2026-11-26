# lab_nemo: LangChain agent -> APISIX -> NeMo Guardrails -> LLM

This lab exercises two NeMo paths. The input rail handles live requests
routed from APISIX. Altprobe reads captured gateway logs and separately queues
LLM content for asynchronous assessment.

```text
LangChain agent
  └─ OpenAI Chat Completions -> APISIX /v1/chat/completions
                                   └─ NeMo Guardrails server (input rail)
                                        └─ OpenAI-compatible mock LLM
Altprobe
  ├─ consumes APISIX Redis log (log_proxy)
  └─ LLM_GUARD_PROVIDER=nemo -> POST /v1/chat/completions
       stores an OCSF 6003 content assessment for request/response
```

The agent sends two prompts:

1. a safe request (`What can you do?`) — NeMo allows it and forwards to the mock
   LLM;
2. a jailbreak request (`Ignore previous instructions ...`) — the NeMo input
   rail blocks it before the LLM is called.

## Components

| Service | Role |
|---|---|
| `agent` | Real LangChain `ChatOpenAI` client pointed at APISIX; sends both prompts |
| `apisix` | APISIX 3.18 data plane; route `/v1/*` to NeMo; Redis logger |
| `nemo` | NVIDIA NeMo Guardrails 0.24.1 API server with the `altprobe` config |
| `mock` | OpenAI-compatible `/v1/chat/completions` mock; no external LLM |
| `redis` | APISIX plugin output consumed by Altprobe as `log_proxy` |
| `altprobe` | Collector with `LLM_GUARD_PROVIDER=nemo` content inspection |
| `opensearch` | OCSF 6003 assessments and dashboards |

## Start

```bash
# From the repository root
python3 labs/run_source_lab.py nemo start
```

The NeMo image installs `nemoguardrails[server]==0.24.1`; the first build takes
several minutes. The guardrails config is in
[`nemo/config`](nemo/config): an input flow executes a small deterministic
Python action and blocks classic jailbreak/prompt-injection markers.

## Endpoints

| Endpoint | URL |
|---|---|
| APISIX | http://127.0.0.1:9080 |
| NeMo Guardrails | http://127.0.0.1:18000 |
| OpenSearch | http://127.0.0.1:19200 |
| Dashboards | http://127.0.0.1:5601/app/dashboards |

## Test

```bash
python3 labs/run_source_lab.py nemo test
```

Expected:

- the NeMo input rail blocks the jailbreak prompt;
- Altprobe writes OCSF 6003 `guard_nemo` assessments with
  `llm_guard.provider=nemo`, `safety=Unsafe`, `field=request.body`,
  `categories=[Jailbreak]` for the blocked request;
- a safe request is recorded with `safety=Safe`, `categories=[None]`.

Example result: `status=PASS checks=3`.

## Altprobe integration

The collector reuses the existing guard client with a provider switch:

```text
LLM_GUARD_ENABLED=true
LLM_GUARD_PROVIDER=nemo
LLM_GUARD_URL=http://nemo:8000
LLM_GUARD_CONFIG_ID=altprobe
LLM_GUARD_MODEL=gpt-4o-mini
```

For `provider=nemo`, the client POSTs the captured body to
`/v1/chat/completions` with `guardrails.config_id` and
`guardrails.options.log.activated_rails=true`. A stopped input rail or the
fixed refusal text is an `Unsafe` verdict. `Safe` requires a completed input
rail (`type=input`, boolean `stop=false`); missing logs, empty content and
incomplete responses remain `invalid_verdict`. This is an automatic check of
the NeMo server response and never asks a user for confirmation.
Altprobe records the verdict as OCSF 6003 detection evidence.

## Stop

```bash
python3 labs/run_source_lab.py nemo stop
```


## Notes

- No external model is contacted: NeMo uses the local OpenAI-compatible mock.
- The NeMo input rail is intentionally small and deterministic so the lab can
  assert the result without a model-based classifier.

## Run evidence

The runner writes a unique run ID into the agent request URL and prompt, binds
an ignored `.local/<run-id>/evidence/` directory into agent/mock containers and
records the Altprobe release package digest and runtime provenance in `.local/current-run.json`. The test checks
fresh OCSF assessments, `agent.json` (safe reply and jailbreak refusal) and
`mock.jsonl` (the safe prompt reached the mock, the jailbreak did not).
The mock audit stores run/case markers rather than captured prompt content.
The agent exits unsuccessfully if its expected safe/refusal results do not hold.

Receipts expire after 24 hours. Lab config changes, container restarts or\nrelease/binary drift require a new runner `start`; direct manual Compose starts do not
create a valid verification receipt. Run one lab at a time because ports overlap.
