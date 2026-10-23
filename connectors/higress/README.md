# Higress -> Altprobe

Go proxy-wasm filter built with TinyGo 0.34.0 and a pinned Higress SDK commit.
The Dockerfile builds `/etc/envoy/altprobe.wasm` into Higress gateway v2.1.5.
Request headers perform API-key authentication and asynchronously call the local
Altprobe Policy cluster while the request is paused. Only an explicit boolean
`result.allow=true` resumes the request. Invalid/unavailable Policy => 503.

The configuration is JSON in the Wasm filter's protobuf StringValue:

```json
{
  "host_name": "my-higress",
  "max_body_size": 5000,
  "policy_cluster": "altprobe_policy",
  "policy_path": "/v1/data/altprobe/allow",
  "policy_paths": ["/mcp"],
  "credentials": {"replace-with-private-api-key": "consumer-name"},
  "collector_cluster": "telemetry",
  "timeout_ms": 2000
}
```

Policy paths match exactly, ignoring query strings. Credentials are verified
against the private server-side map; the authenticated subject comes only from
that API key, and client identity headers never bind it. This implementation
supplies API-key auth, not JWT/OIDC validation. Strip the key before upstream
forwarding. Protect client traffic with TLS and keep credential configuration
private.

Define Envoy clusters `altprobe_policy` (loopback:8181) and `telemetry` (private
collector:8080). The included `collector.py` bridges HTTP POST `/events` to Redis
RPUSH `log_proxy`; Python stdlib only. Do not publish its port to an untrusted
network: the collector accepts trusted telemetry without client authentication.
Redis must be private; auth/TLS are not implemented in this small relay.

Body callbacks retain at most max_body_size bytes per direction and return
Continue, preserving streaming. Stream completion dispatches a best-effort HTTP
telemetry event; errors are logged, delivery is not durable. Headers containing
authorization/API keys/cookies are redacted, body contents are not semantically
redacted. Upgraded WebSocket frames are outside this HTTP capture.

The Policy envelope is identical to APISIX. Install the rebuilt Altprobe `1.0.2`
package using the digest pinned in the [labs guide](../../labs/README.md#collector-package), with
`POLICY_TYPE_AGENT=higress`, HTTP sidecar enabled, and
`SOURCES_PROXY_REDIS=log_proxy`. The identity key is `auth:higress:<consumer>`.
OPA can replace the Policy endpoint if its Rego decision returns the same object.

[`labs/lab_higress/higress/envoy.yaml`](../../labs/lab_higress/higress/envoy.yaml)
provides a complete static bootstrap.
This uses the real Higress gateway data plane in its documented plugin debug
mode, without the console/control plane. To deploy in a managed Higress cluster,
package the compiled Wasm as an OCI WasmPlugin and use platform-specific cluster
names instead of the lab's static clusters.

Reference: https://higress.io/en/docs/latest/user/wasm-go/
