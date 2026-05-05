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
```

## Configure

Modify the file  `/etc/altprobe/altprobe.yaml` according to your configuration

```yaml
%YAML 1.1
---
# Altprobe configuration file version 1.0.1
# Configuration for monitoring sidecar agent

# Main Altprobe settings
altprobe:
  asset_name: "altprobe"
  syslog_debug: "false"

# Configuration for sending logs
sinks:
  # Alertflex cloud service url
  af_url: "indef"                # example: "https://cs.alertflex.org/sce/api/v1/logs/"
  af_key: "XXXXXXX-c568-46a4-a043-XXXXXXX"
  
  # OpenSearch
  os_url: "indef"                # example: "https://192.168.1.10:9200"
  os_user: "admin"
  os_pwd: "Password-12345"
  
# Sources configurations
sources:
  # Redis interface configuration
  redis_host: "indef"            # example: "192.168.1.20"
  redis_port: 6379
  
  # Altprobe supports two methods for reading logs:
  # 1. Directly from application and sensor log files
  # 2. From Redis list using RPOP command
  # If both xxx_log and xxx_redis are set to "indef", sensor is disabled
  
  # Falco Host IDS (runtime host/container security) log configuration
  falco_log: "indef"             # example: "/var/log/falco.json"
  falco_redis: "indef"           # example: "log_falco"
  
  # Proxy log configuration (Nginx, Envoy, etc)
  proxy_log: "indef"             # example: "/var/log/nginx/access.log"
  proxy_redis: "indef"           # example: "log_proxy"
  
  # Suricata Network IDS log configuration
  suricata_log: "indef"          # example: "/var/log/suricata/eve.json"
  suricata_redis:  "indef"       # example: "log_suri"

# Embedded ModSecurity WAF and Suricata IPS configuration
waf:
  # Path to OWASP Core Rule Set (CRS)
  ruleset_path: "indef"          # example: "/etc/altprobe/coreruleset"
  # Path to Suricata's Unix socket for IP blocking
  # Check suricata.yaml config, it also should be enabled
  # unix-command:
  #   enabled: yes
  #   filename: /var/run/suricata-command.socket
  suricata_socket: "indef"       # example: "/var/run/suricata-command.socket"
  # Hostbit Suricata rule to block IP detected by CRS, should be loaded by Suricata
  # example: alert ip !$HOME_NET any -> any any (msg:"Detected malicious host outside HOME_NET"; hostbit:malicious-ip; sid:1000002; rev:1;)
  hostbit_rule: "indef"          # example: malicious-ip
  # Timeout in seconds for automatic IP unblocking (1h default)
  ipblock_timeout: 3600
```

## Run altprobe

```bash
altprobe-start   # daemon mode
altprobe run     # cli mode
```

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
```
