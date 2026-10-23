# Altprobe

Altprobe gives security and platform teams visibility into AI agent, MCP, REST API, and gateway traffic, adding detection guardrails for AI and API interactions. It collects events from API/AI gateways and proxy logs, normalizes them into OCSF, and sends them to OpenSearch or compatible downstream systems.

It discovers AI agents, MCP servers, and APIs (including undocumented ones), identifies threats based on OWASP Top 10, and correlates them by MITRE ATT&CK / ATLAS - providing observability and detection on top of your existing AI stack.

Altprobe is available as a free, ready-to-run Linux package. This repository
provides reusable gateway connectors, deployment assets, dashboards and
self-contained labs to help you get started.

## Table of Contents

- [Architecture](#architecture)
- [Components](#components)
- [Example Screenshots](#example-screenshots)
  - [Agent Correlations](#altprobe---agent-correlations)
  - [MCP & Tool-Abuse Watchlist](#mcp--tool-abuse-watchlist)
  - [MITRE ATT&CK / ATLAS Timeline](#mitre-attck--atlas-timeline)
  - [Vulnerability Findings](#vulnerability-findings)
- [Why Use Altprobe](#why-use-altprobe)
- [Repository Contents](#repository-contents)
- [Requirements](#requirements)
- [Install From Package](#install-from-package)
- [Run Altprobe](#run-altprobe)
- [Quick-Start Labs](#quick-start-labs)
  - [Quickest Path](#quickest-path)
- [License](#license)

## Architecture

Altprobe collects API/AI gateway and proxy logs (Redis lists or log files) plus
SBOM scan reports; it normalizes them into OCSF and writes to the configured
sink.

### High-Level Design (HLD)

```mermaid
flowchart BT
    subgraph L1["Endpoint Layer"]
        AI["AI Agents"]
        MCP["A2A / API / MCP Servers"]
    end

    subgraph L2["Security Control Layer"]
        PROXY["API/AI Gateway"]
        TRIVY["SBOM / Vulnerability Scanner"]
    end

    subgraph L3["Analytics & Storage Layer"]
        ALT["Altprobe"]
        AFX["Alertflex: Inventory, Tracing & Policy Control<br/><i>optional</i>"]
        GLLM["Guard LLM:<br/>External Detection Guardrails<br/><i>optional</i>"]
        OS["OpenSearch:<br/>Search & Analytics Store"]
    end

    AI <--> PROXY
    MCP <--> PROXY

    MCP -.->|SBOM generation / scan request| TRIVY

    PROXY -->|gateway / proxy logs| ALT
    TRIVY -->|vulnerability findings| ALT

    ALT <-->|inventory / policy| AFX
    ALT <-->|analysis loop| GLLM
    ALT -->|indexing / storage| OS

    classDef optional stroke-dasharray: 5 5
    class AFX,GLLM optional
```

### Low-Level Design (LLD)

```mermaid
flowchart TD
    Sbom["SBOM / Vulnerability Scanner<br/><i>Trivy</i>"]
    Proxy["API/AI Gateway<br/>Nginx (OpenResty) / APISIX / Envoy / Kong OSS / Traefik / Higress"]

    Altprobe["<b>Altprobe</b><br/>Collector &amp; Correlator<br/>Embedded Detection Guardrails &amp; log-based WAF"]

    GLLM["Guard LLM<br/><i>External Detection Guardrails</i><br/><i>runtime: Ollama; model: Qwen3Guard</i><br/><i>optional</i>"]
    Alertflex["Alertflex<br/><i>optional</i>"]
    OpenSearch["OpenSearch"]

    Proxy -->|gateway / proxy logs via Log file / Redis| Altprobe
    Sbom -->|Scan report<br/>CycloneDX JSON| Altprobe

    Altprobe <-->|analysis loop| GLLM
    Altprobe <-->|inventory / policy<br/>A2A / MCP / REST / SBOM| Alertflex
    Altprobe -->|Security findings / HTTP activities / Vulnerability findings<br/>OCSF| OpenSearch

    classDef source fill:#ffffff,stroke:#333,stroke-width:1px
    classDef core fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef downstream fill:#f3e5f5,stroke:#4a148c,stroke-width:2px
    classDef store fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef optional stroke-dasharray: 5 5

    class Proxy,Sbom source
    class Altprobe core
    class GLLM downstream,optional
    class Alertflex downstream,optional
    class OpenSearch store
```

## Components

| Component | Layer | Role | Technology |
|-----------|-------|------|------------|
| AI Agents | Endpoint | Autonomous AI workloads generating requests/actions | — |
| A2A / API / MCP Servers | Endpoint | MCP servers providing tools/context; A2A / REST endpoints | — |
| API/AI Gateway | Security Control | Front for MCP, A2A, REST; inbound control & monitoring | Nginx (OpenResty) / APISIX / Envoy / Kong OSS / Traefik / Higress |
| SBOM / Vulnerability Scanner | Security Control | Generates or scans SBOMs and reports software vulnerabilities | Trivy (CycloneDX JSON) |
| Altprobe | Analytics & Storage | Collects, correlates, classifies, normalizes to OCSF; embedded WAF; Detection Guardrails (internal); Policy/PEP for gateway authorization | Custom: Collector / Correlator / Scanner |
| Guard LLM *(optional)* | Analytics & Storage | External Detection Guardrails: prompt/response inspection, policy enforcement, verdicts | Ollama; Qwen3Guard |
| Search & Analytics Store | Analytics & Storage | Search, dashboards, alerting on OCSF findings | OpenSearch |
| Alertflex *(optional)* | Analytics & Storage | Inventory, tracing, and policy control | Alertflex |

## Example Screenshots

The quick-start labs provision OpenSearch Dashboards so you can inspect
normalized OCSF events, agent correlations, and security timelines.

### Altprobe - Agent Correlations

![Altprobe - Agent Correlations](img/agent_correlations.png)

### MCP & Tool-Abuse Watchlist

![MCP & Tool-Abuse Watchlist](img/mcp_tools.png)

### MITRE ATT&CK / ATLAS Timeline

![Altprobe MITRE ATT&CK and ATLAS Dashboard](img/mitre_atlas.png)

### Vulnerability Findings

![Altprobe Vulnerability findings](img/vulnr_findings.png)

## Why Use Altprobe

- Monitor MCP, AI Gateway, and REST API traffic from a single collector.
- Convert heterogeneous gateway and proxy events into OCSF.
- Send normalized events to OpenSearch for search, dashboards, and alerting.
- Correlate API and agent activity by host, route, authentication key or source
  IP, and request data.
- Start with a local lab, then adapt the same source and sink pattern for a
  production gateway.

## Repository Contents

- `connectors/` - reusable gateway connectors (APISIX, Envoy, Higress, Kong OSS, OpenResty, Traefik) plus OpenSearch dashboards and templates.
- `docker/` - base Docker assets for Altprobe.
- `labs/` - public quick-start labs for OpenResty, APISIX, Envoy, Kong OSS, Traefik and Higress.
- `img/` - screenshots used in this README.

Gateway connectors collect telemetry; access control is enforced separately by
the Altprobe Policy/PEP on protected routes. Altprobe identifies entities by the
gateway-authenticated auth key (`auth:<gateway>:<consumer>`) when present, and by
the observed source IP (`ip:<host>:<remote_addr>`) otherwise. Client identity
headers are not used.

## Requirements

- Docker and Docker Compose for the labs.
- Ubuntu 22.04 amd64 for the
  Linux package install path.
- Optional: OpenSearch or another supported sink for production deployments.

## Install From Package

```bash
ALTPROBE_VERSION=1.0.2
ALTPROBE_RELEASE_BASE_URL="https://github.com/olegzhr/altprobe/releases/download"
ALTPROBE_SHA256=d68fc81bce31321bf428444a4fa02868b0ea68e4e34b32c7b9a2e7fb8f91f3bb
wget "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}_amd64.deb"
echo "${ALTPROBE_SHA256}  altprobe_${ALTPROBE_VERSION}_amd64.deb" | sha256sum -c - \
  && sudo apt-get update \
  && sudo apt-get install -y "./altprobe_${ALTPROBE_VERSION}_amd64.deb" \
  && sudo ldconfig
```

APT installs the runtime libraries declared by this verified package. Docker
images use the same installation method and check for missing shared libraries
with `ldd` during the build. The default hash identifies the package uploaded on
2026-10-24; older `1.0.2` package files have different hashes. Ubuntu Jammy remains
the supported base for this binary.

The package includes OWASP CRS 4.29.0; Docker builds activate its configuration
without downloading another CRS archive. Altprobe does not use GeoIP databases
or a `geoip_db` setting.

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
OpenAI-compatible response mock. They exercise integration behavior and do not
measure detection accuracy against a comprehensive attack benchmark.

Captured traffic is analyzed asynchronously. Access control uses the separate
synchronous Policy listener on configured routes; a later finding cannot undo
a request that has already reached its upstream. OpenResty's demo collects
telemetry without enabling Policy.

### Quickest Path

If you are not sure which gateway to try first, start with APISIX:

```bash
git clone https://github.com/olegzhr/altprobe.git
cd altprobe/labs/lab_apisix
docker compose build --no-cache altprobe
docker compose up -d --build --wait
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
docker compose build --no-cache altprobe
docker compose up -d --build --wait
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

Altprobe collector binaries published in [GitHub Releases](https://github.com/olegzhr/altprobe/releases)
and the original code and assets in this repository are licensed under the
[Apache License, Version 2.0](LICENSE).

Third-party components retain their respective licenses and notices.
