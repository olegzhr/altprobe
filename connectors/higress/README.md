# Higress → Altprobe

Go proxy-wasm filter built with TinyGo. It captures HTTP telemetry and continues
the request. It does not call a policy server or enforce access. HTTP ext_authz
belongs to the separate ctrlprobe integration and runs before telemetry WASM.

Configuration is JSON in the Wasm filter's `StringValue`:

```json
{
  "host_name": "my-higress",
  "gateway_origin_id": "higress-gateway-1",
  "max_body_size": 5000,
  "credentials": {"replace-with-private-api-key": "consumer-name"},
  "collector_cluster": "telemetry",
  "timeout_ms": 2000
}
```

Define a private `telemetry` cluster for the telemetry collector. `collector.py`
bridges HTTP `POST /events` to Redis `log_proxy`; it is not an authorization
service. The optional `credentials` lookup is legacy telemetry attribution,
not proof that a request was authorized. Do not use it as an authentication gate.

Altprobe: `SOURCES_PROXY_REDIS=log_proxy`, `ALTPROBE_GATEWAY_TYPE=higress`.
The Higress lab keeps its WASM, sources and collector inside
[`labs/lab_higress/higress`](../../labs/lab_higress/higress).

## Lab and content inspection

Use the [Higress lab](../../labs/lab_higress/README.md) and the
[integration catalog](../README.md). Keep WASM sources, the built filter and the private collector inside the lab higress/ directory. Access checks remain in HTTP ext_authz before WASM.
Optional Ollama/NeMo inspection is configured on Altprobe through `LLM_GUARD_*`;
it consumes the captured request/response bodies and writes OCSF assessments.
Capture limits remain significant: incomplete or oversized bodies must not be
interpreted as a successful content check.
