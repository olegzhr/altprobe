# Altprobe

Altprobe is a lightweight security collector for monitoring and controlling API and MCP services.

It collects runtime, network, and HTTP telemetry, normalizes events into OCSF, exports metrics to Prometheus, stores events in OpenSearch / ELK and Loki, and adds reactive protection through a log-based WAF workflow.

## Overview

Altprobe is built for environments where API services, AI agents, MCP servers, and service-to-service traffic need continuous visibility without deploying a full SIEM stack on every node.

Its primary role is to monitor and control API and MCP activity while also providing:

- normalized API telemetry
- security findings and correlation
- Prometheus-ready operational metrics
- centralized event logging to OpenSearch / ELK and Loki
- reactive WAF / IPS-style response