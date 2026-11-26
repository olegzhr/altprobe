# OpenShell -> Altprobe -> OpenSearch lab

End-to-end lab for **real NVIDIA OpenShell** sandbox telemetry. It runs a
LangChain workload inside an OpenShell sandbox, collects the native OCSF 1.8
JSONL, and sends it through Altprobe to OpenSearch and OpenSearch Dashboards.

```text
OpenShell gateway
  └─ ai-client sandbox (LangChain)
        └─ native OCSF 1.8 JSONL
              └─ shipper → Redis → Altprobe → OpenSearch
                                             └─ OpenSearch Dashboards
```

APISIX and an OpenAI-compatible mock are included so the LangChain workload
has a realistic HTTP path.

## What it demonstrates

- a real OpenShell gateway and a real OpenShell sandbox;
- LangChain agent activity recorded as native OCSF 1.8;
- OCSF classes `0, 1007, 2004, 3002, 4001, 4002, 4007, 5019, 6002, 6003`;
- Altprobe enrichment and indexing into `ocsf-1.8.0-*`;
- OpenSearch Dashboards over the collected data;
- a shipper that tails JSONL files and feeds Redis.

## Repository layout

```text
lab_openshell/
├── compose.yaml                 OpenSearch, APISIX, mock, Redis, Altprobe, shipper
├── apisix/                      APISIX gateway for the model request
├── mock/                        OpenAI-compatible model mock
├── opensearch/                  templates, index patterns, dashboards
├── openshell/
│   ├── client.py                LangChain workload
│   ├── Dockerfile               sandbox image
│   ├── run_gateway.sh           real OpenShell gateway (mTLS, port 8080)
│   └── run_agent.sh             build image and create sandbox
├── shipper/                     config for connectors/shipper_altprobe
└── tests/verify_openshell.py    end-to-end check
```

## Requirements

- Linux or WSL2 with kernel **6.2+** (OpenShell needs Landlock ABI v3)
- Docker Engine, or Docker Desktop with WSL integration
- OpenShell CLI **0.1.7+** (`openshell` on `PATH`)

The Altprobe image installs the published release package with the shared [`labs/common/altprobe/Dockerfile`](../common/altprobe/Dockerfile) and verifies it against the release `SHA256SUMS`.

Check the kernel and tools:

```bash
uname -r
docker version
openshell --version
```

## Start

From this directory:

```bash
cd labs/lab_openshell

# 1. OpenSearch, APISIX, mock, Redis, Altprobe, shipper
docker compose up -d

# 2. Real OpenShell gateway (mTLS, 127.0.0.1:8080)
./openshell/run_gateway.sh

# 3. Build the LangChain image and create the real sandbox
./openshell/run_agent.sh
```

`run_gateway.sh` generates a local PKI, extracts the supervisor binary, starts
the gateway, and registers it with the OpenShell CLI. All generated files go to
`.local/` and are ignored by Git.

The agent writes OCSF here, inside the sandbox:

```text
/tmp/openshell-ocsf.jsonl
```

Copy it to the host and index it:

```bash
openshell sandbox exec -n ai-client --no-login-shell -- \
  cat /tmp/openshell-ocsf.jsonl > openshell-logs/ocsf.jsonl

docker compose up -d --force-recreate shipper
python tests/verify_openshell.py
```

## Endpoints

| Endpoint | URL |
|---|---|
| OpenSearch | http://127.0.0.1:19200 |
| OpenSearch Dashboards | http://127.0.0.1:15601/app/dashboards |
| APISIX | http://127.0.0.1:19080 |
| mock model | http://127.0.0.1:18003 |
| OpenShell gateway | https://127.0.0.1:8080 |

## OCSF storage

OpenShell emits native **OCSF 1.8.0**. Altprobe writes:

```text
ocsf-1.8.0-*
```

The `time` field is mapped as `date` with `epoch_millis`; Dashboards time
filters require this mapping.

## Verification

```bash
python tests/verify_openshell.py
```

This indexed-data smoke test checks that OpenShell classes, allowed/denied
network actions and a detection finding exist in OpenSearch. It does not
establish a new run ID or verify current image/binary provenance.

Expected result:

```text
OpenSearch is ready: PASS
all OpenShell OCSF classes reached OpenSearch: PASS
allowed and denied OpenShell network actions are visible: PASS
OpenShell detection finding is visible: PASS
status=PASS checks=4
```

## Troubleshooting

**`Landlock ABI v3 or newer is required`**

Update WSL and restart it:

```powershell
wsl --update --web-download
wsl --shutdown
```

**`ControlSupervisorStartFailed` / supervisor cannot connect**

The supervisor connects to `https://127.0.0.1:8080`. Start the gateway on port
8080, as `run_gateway.sh` does.

**No dashboards or no results**

- refresh Dashboards with `Ctrl+F5`;
- select **Last 7 days**;
- confirm data exists:

```bash
curl 'http://127.0.0.1:19200/_cat/indices?v'
```

## Files that must not be committed

```text
.local/                  generated certs, CLI, supervisor
openshell-logs/*.jsonl   runtime telemetry
results/                 test output
__pycache__/             Python caches
```

Never commit `openshell/tls/`; it contains private keys.

## Current source integration

This lab uses the [shared shipper](../../connectors/shipper_altprobe/README.md).
Altprobe forwards native OCSF records to the configured log destinations.
The lab covers sandbox process activity, application lifecycle, authentication,
network events and policy outcomes such as a denied connection.

The [NeMo](../lab_nemo/README.md), [SBOM](../lab_sbom/README.md) and
[Suricata](../lab_suricata/README.md) labs use a separate run-scoped runner.
OpenShell retains the external CLI/bootstrap workflow above. Preserve the local
PKI and generated gateway material. Stop the Compose services with plain
`docker compose down`; stop the external gateway separately when appropriate.
