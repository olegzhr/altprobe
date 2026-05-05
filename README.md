# Altprobe

Altprobe is a lightweight security collector for monitoring and controlling API and MCP services.

It collects runtime, network, normalizes events into OCSF, stores events in OpenSearch / ELK, and adds reactive protection through a log-based WAF workflow.

## Overview

Altprobe is built for environments where API services, AI agents, MCP servers, and service-to-service traffic need continuous visibility without deploying a full SIEM.

Its primary role is to monitor and control API and MCP activity while also providing:

- security findings and correlation
- centralized event logging to OpenSearch / ELK
- reactive WAF / IPS-style response

## Requirements

- **Operating System**: Ubuntu 20.04 or higher (for binary package)
- **Optional** (depending on configured sinks/sources):
  - OpenSearch / ELK stack
  - Redis
  - Falco, Suricata, or proxy logs from Nginx/Envoy

## Installation

### From DEB package

```bash
# Install system dependencies
sudo apt-get update
sudo apt-get -y install libyaml-cpp-dev libdaemon-dev libboost-all-dev libmodsecurity3

# Download the package
wget https://github.com/alertflex/altprobe/releases/download/v1.0.5/altprobe_1.0-5.deb

# Install the package
sudo dpkg -i altprobe_1.0-5.deb
sudo ldconfig

## Configure

See `/etc/altprobe/altprobe.yaml`

## Run altprobe

```bash
altprobe-start   # daemon mode
altprobe run     # cli mode


## Run container

```bash
docker build -t altprobe:latest .

docker run -d \
  --name altprobe \
  -e ALTPROBE_ASSET_NAME="my-server" \
  -e ALTPROBE_SYSLOG_DEBUG="true" \
  -e SINKS_AF_URL="indef" \
  -e SINKS_AF_KEY="your-key" \
  -e SINKS_OS_URL="indef" \
  -e SINKS_OS_USER="admin" \
  -e SINKS_OS_PWD="pass" \
  -e SOURCES_REDIS_HOST="indef" \
  -e SOURCES_REDIS_PORT="6379" \
  -e SOURCES_FALCO_LOG="indef" \
  -e SOURCES_PROXY_LOG="indef" \
  -e SOURCES_SURICATA_LOG="indef" \
  -e WAF_RULESET_PATH="indef" \
  -e WAF_SURICATA_SOCKET="indef" \
  -e WAF_HOSTBIT_RULE="indef" \
  -e WAF_IPBLOCK_TIMEOUT="3600" \
  altprobe:latest
