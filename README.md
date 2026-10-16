# Altprobe

Altprobe gives security and platform teams visibility into AI agent, MCP, REST API, and gateway traffic, adding detection guardrails for AI and API interactions. It collects events from gateways, proxy logs, runtime sensors, and network security tools, normalizes them into OCSF, and sends them to OpenSearch or compatible downstream systems.

It discovers AI agents, MCP servers, and APIs (including undocumented ones), identifies threats based on OWASP Top 10, and correlates them by MITRE ATT&CK / ATLAS - providing observability and detection on top of your existing stack, without requiring you to build or expand a full SIEM.

## Table of Contents

- [Architecture](#architecture)
- [Components](#components)
- [Example Screenshots](#example-screenshots)
  - [Solution Overview](#solution-overview)
  - [Agent Correlations](#agent-correlations)
  - [MITRE ATT&CK / ATLAS Timeline](#mitre-attck--atlas-timeline)
- [Why Use Altprobe](#why-use-altprobe)
- [Repository Contents](#repository-contents)
- [Requirements](#requirements)
- [Install From Package](#install-from-package)
- [Run Altprobe](#run-altprobe)
- [Quick-Start Labs](#quick-start-labs)
  - [Quickest Path](#quickest-path)
- [License](#license)

## Architecture

### High-Level Design (HLD)

```mermaid
flowchart BT
    subgraph L1["Endpoint Layer"]
        AI["AI Agents"]
        MCP["MCP Servers"]
    end

    subgraph L2["Security Control Layer"]
        PROXY["AI/API Gateway"]
        SUR["Network IDS"]
        FALCO["Host IDS/Runtime Security"]
    end

    subgraph L3["Analytics & Storage Layer"]
        ALT["Altprobe"]
        GLLM["Guard LLM"]
        OS["Search & Analytics Store (OpenSearch)"]
    end

    AI <--> PROXY
    MCP <--> PROXY

    MCP -.->|traffic mirroring| SUR
    MCP -.->|runtime events| FALCO

    PROXY <-->|inbound control and monitoring| ALT
    SUR -->|out-of-band monitoring| ALT
    FALCO -->|out-of-band monitoring| ALT
    ALT <-->|analysis loop| GLLM
    ALT -->|indexing / storage| OS
```

### Low-Level Design (LLD)

```mermaid
flowchart TD
    NIDS["Suricata (NIDS)"]
    HIDS["Falco Security (HIDS)"]
    Proxy["AI/API Gateway:<br/>Nginx (OpenResty) / APISIX / Envoy / Kong OSS / Traefik / Higress"]

    Altprobe["<b>Altprobe</b><br/>Collector / Correlator,<br/>Embedded log-based WAF,<br/>Detection Guardrails (internal)"]

    GLLM["Guard LLM<br/>Detection Guardrails (external)<br/><i>runtime: Ollama; model: Qwen3Guard</i>"]
    Alertflex["Alertflex<br/><i>optional</i>"]
    OpenSearch["OpenSearch"]

    NIDS -->|Alerts/HTTP via Log file/Redis| Altprobe
    HIDS -->|Alerts via Log file/Redis| Altprobe
    Proxy -->|HTTP via Log file/Redis| Altprobe

    Altprobe <-->|analysis loop| GLLM
    Altprobe -->|A2A/MCP/REST/SBOM<br/>inventory info| Alertflex
    Altprobe -->|Security findings / HTTP activities<br/>in OCSF format| OpenSearch

    classDef source fill:#ffffff,stroke:#333,stroke-width:1px
    classDef core fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef downstream fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef store fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef optional stroke-dasharray: 5 5

    class NIDS,HIDS,Proxy source
    class Altprobe core
    class GLLM downstream
    class Alertflex downstream,optional
    class OpenSearch store
```

## Components
Component                             | Layer                       | Role                                                                 | Technology                                                                                  | Flow / Direction
--------------------------------------|-----------------------------|----------------------------------------------------------------------|---------------------------------------------------------------------------------------------|--------------------------------------------------------------
AI Agents                             | Endpoint                    | Autonomous AI workloads generating requests/actions                  | —                                                                                           | ↔ API/AI Gateway (in-band)
MCP Servers                           | Endpoint                    | Model Context Protocol servers providing tools/context               | —                                                                                           | ↔ API/AI Gateway (in-band)
API/AI Gateway                        | Security Control            | Front for MCP, A2A, REST; inbound control & monitoring               | Nginx (OpenResty) / APISIX / Envoy / Kong OSS / Traefik / Higress     | ↔ AI Agents, ↔ MCP Servers, ↔ Altprobe
Network IDS                           | Security Control            | Network intrusion detection & prevention                             | Suricata                                                                                    | Out-of-band monitoring → Altprobe (log file / Redis)
Host IDS / Runtime Security           | Security Control            | Host & container intrusion detection, runtime security               | Falco                                                                                       | Out-of-band monitoring → Altprobe (log file / Redis)
Altprobe                              | Analytics & Storage         | Collects, correlates, classifies, normalizes to OCSF, embedded WAF   | Custom (Collector / Correlator); Detection Guardrails (internal)                            | Core ↔ Gateway, ← Network IDS, ← Host IDS, ↔ Guard LLM, → OpenSearch, → Alertflex (optional)
Guard LLM                             | Analytics & Storage         | LLM-based guardrail: prompt/response inspection, policy, verdicts    | Detection Guardrails (external); runtime: Ollama; model: Qwen3Guard                         | ↔ Altprobe (analysis loop)
Search & Analytics Store (OpenSearch) | Analytics & Storage         | Search, dashboards, alerting on OCSF findings                        | OpenSearch                                                                                  | ← Altprobe (indexing / storage)
Alertflex (optional)                  | Analytics & Storage (down.) | Inventory & SBOM context enrichment                                  | Alertflex                                                                                   | ← Altprobe (A2A / MCP / REST / SBOM)

## Example Screenshots

The quick-start labs provision OpenSearch Dashboards so you can inspect
normalized OCSF events, agent correlations, and security timelines.

### Altprobe - Agent Correlations

![Altprobe - Agent Correlations](img/agent_correlations.png)

### MCP & Tool-Abuse Watchlist

![MCP & Tool-Abuse Watchlist](img/mcp_tools.png)

### MITRE ATT&CK / ATLAS Timeline

![Altprobe MITRE ATT&CK and ATLAS Dashboard](img/mitre_atlas.png)

## Why Use Altprobe

- Monitor MCP, AI Gateway, and REST API traffic from a single collector.
- Convert heterogeneous gateway and sensor events into OCSF.
- Send normalized events to OpenSearch for search, dashboards, and alerting.
- Correlate API and agent activity by host, session, route, and request data.
- Start with a local lab, then adapt the same source and sink pattern for a
  production gateway.

## Repository Contents

- `connectors/` - reusable integration code
- `docker/` - base Docker assets for Altprobe.
- `ids-rules/` - MCP / Shadow API / AI Detection rule files for Falco, Suricata.
- `labs/` - public quick-start labs for OpenResty, APISIX, Envoy, Kong OSS, Traefik and Higress.

## Requirements

- Docker and Docker Compose for the labs.
- Ubuntu 22.04 (the package versions below are pinned for this release) for the
  Linux package install path.
- Optional: OpenSearch or another supported sink for production deployments.

## Install From Package

```bash
sudo apt-get update
sudo apt-get install -y \
    libdaemon0 \
    libboost-system1.74.0 libboost-filesystem1.74.0 libboost-regex1.74.0 \
    libboost-iostreams1.74.0 libboost-thread1.74.0 \
    libyaml-cpp0.7 libhiredis0.14 libmodsecurity3 libmaxminddb0 \
    libssl3 libgrpc++1 libprotobuf23

ALTPROBE_VERSION=1.0.2
ALTPROBE_RELEASE_BASE_URL="https://github.com/olegzhr/altprobe/releases/download"
wget "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}.deb"
sudo dpkg -i "altprobe_${ALTPROBE_VERSION}.deb"
sudo ldconfig
```

Update `/etc/altprobe/altprobe.yaml` for your sources and sinks.

## Run Altprobe

```bash
altprobe-start
altprobe-status
altprobe-stop
altprobe run
```

## Quick-Start Labs

The public labs are designed for safe local evaluation. They use harmless mock
traffic only: MCP ping/tool calls, REST demo endpoints, and a local
OpenAI-compatible response mock.

### Quickest Path

If you are not sure which gateway to try first, start with APISIX:

```bash
cd labs/lab_apisix
docker compose build
docker compose up -d
cd ../tests
python3 -m pip install -r requirements.txt
LAB_BASE=http://localhost:9080 python3 run_tests.py smoke
```

Expected result: the smoke suite reports every test passed (e.g. `N passed`). Then open OpenSearch
Dashboards at `http://localhost:5601` and review the provisioned Altprobe
dashboards.

Use the same flow for any gateway:

```bash
cd <lab-directory>
docker compose build
docker compose up -d
cd ../tests
python3 -m pip install -r requirements.txt
LAB_BASE=<gateway-url> python3 run_tests.py smoke
```

| Gateway | Lab directory | Gateway URL | Details |
|---------|---------------|-------------|---------|
| APISIX | `labs/lab_apisix` | `http://localhost:9080` | `labs/lab_apisix/README.md` |
| Envoy | `labs/lab_envoy` | `http://localhost:9080` | `labs/lab_envoy/README.md` |
| Nginx (OpenResty) | `labs/lab_openresty` | `http://localhost:9080` | `labs/lab_openresty/README.md` |
| Kong OSS | `labs/lab_kong` | `http://localhost:9080` | `labs/lab_kong/README.md` |
| Traefik Proxy OSS | `labs/lab_traefik` | `http://localhost:9080` | `labs/lab_traefik/README.md` |
| Higress | `labs/lab_higress` | `http://localhost:9080` | `labs/lab_higress/README.md` |

All labs expose OpenSearch at `http://localhost:9200` and OpenSearch Dashboards
at `http://localhost:5601`.

## License

See [LICENSE](LICENSE).
