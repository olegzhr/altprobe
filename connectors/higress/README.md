# Higress → Altprobe

Go proxy-wasm filter built with TinyGo. It captures HTTP telemetry, optionally
authenticates API keys and calls Altprobe Policy before resuming the request.

Configuration is JSON in the Wasm filter's `StringValue`:

```json
{
  "host_name": "my-higress",
  "gateway_origin_id": "higress-gateway-1",
  "max_body_size": 5000,
  "policy_cluster": "altprobe_policy",
  "policy_path": "/v1/data/altprobe/allow",
  "policy_paths": ["/mcp"],
  "credentials": {"replace-with-private-api-key": "consumer-name"},
  "collector_cluster": "telemetry",
  "timeout_ms": 2000
}
```

Define Envoy clusters `altprobe_policy` (loopback:8181) and `telemetry` (Altprobe
collector). `collector.py` bridges HTTP `POST /events` to Redis `log_proxy`;
keep it on a private network. Policy requires `result.allow=true`; invalid or
unavailable Policy returns 503. Identity is `auth:higress:<consumer>`.

Altprobe: `SOURCES_PROXY_REDIS=log_proxy`. The lab's
`labs/lab_higress/higress/envoy.yaml` is a complete static bootstrap.
