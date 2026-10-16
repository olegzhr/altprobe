# Kong OSS -> Altprobe

Custom Lua plugin for Kong OSS 3.9.1. Captures request/response bodies in
`access`/`body_filter`, then sends the APISIX-compatible JSON envelope to Redis
with a zero-delay timer in `log`. `body_filter` does not buffer client delivery.

Copy `altprobe/` to `/usr/local/share/lua/5.1/kong/plugins/altprobe/` and set
`KONG_PLUGINS=bundled,altprobe`. Enable the plugin globally for telemetry:

```yaml
plugins:
- name: altprobe
  config:
    redis_host: redis
    redis_port: 6379
    redis_key: log_proxy
    host_name: my-kong
    max_body_size: 5000
```

On protected routes attach `key-auth` and a route-specific `altprobe` plugin with
the same telemetry settings plus `policy_enabled: true` and
`policy_url: http://127.0.0.1:8181/v1/data/altprobe/allow`.
Authentication must execute before this plugin (priority 700). Only
`kong.client.get_consumer().username` supplies the authenticated principal.
The stock commercial Kong OPA plugin is not required.

Policy accepts the APISIX `input.type/request/var/consumer` envelope and requires
HTTP 200 with `result.allow` boolean. Deny uses `result.status_code` (default 403);
invalid/unavailable Policy returns 503. An external OPA can use the same contract
by returning an object from its Rego decision. TLS verification is enabled.

Install the rebuilt Altprobe `1.0.2` package with `kong` gateway-type support
(`POLICY_TYPE_AGENT=kong`, HTTP sidecar enabled, `SOURCES_PROXY_REDIS=log_proxy`).
Share the gateway's network namespace when using loopback Policy. Authenticated
identity is `auth:kong:<consumer>`. Use the package digest pinned in the [labs guide](../../labs/README.md#collector-package);
earlier binaries under the same version may lack this gateway type.

Authorization/cookie/API-key headers are redacted. Bodies can contain sensitive
data and are only size-limited, not semantically redacted. Request bodies written
by nginx to a temporary file are marked missing rather than read without bounds.
Telemetry is best effort; Redis/timer failures are logged and do not deny traffic.
Policy checks protect incoming requests; response capture is asynchronous analysis.

Runnable demo: [`labs/lab_kong`](../../labs/lab_kong/README.md).
