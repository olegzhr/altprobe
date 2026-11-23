# Traefik → Altprobe

Go middleware for Traefik 3.x, loaded through the local Yaegi plugin mechanism.
It sends one Redis record per request for asynchronous analysis.

Copy the directory to
`/plugins-local/src/github.com/altprobe/traefik-altprobe`, then enable it:

```yaml
experimental:
  localPlugins:
    altprobe:
      moduleName: github.com/altprobe/traefik-altprobe
```

Example middleware:

```yaml
http:
  middlewares:
    altprobe:
      plugin:
        altprobe:
          RedisAddress: redis:6379
          RedisKey: log_proxy
          HostName: my-traefik
          GatewayOriginID: traefik-gateway-1
          MaxBodySize: 5000
          Credentials:
            replace-with-private-api-key: consumer-name
```

Attach the middleware before path rewriting. This middleware collects telemetry
without an authorization call. The optional Credentials map attributes observed
traffic; it does not grant or deny access. Observed identity is
`auth:traefik:<consumer>` or the observed source IP. Keep credentials in private
configuration and use TLS for client traffic.

Altprobe: `SOURCES_PROXY_REDIS=log_proxy`; native Go tests: `go test ./...`.

## Lab and content inspection

Use the [Traefik lab](../../labs/lab_traefik/README.md) and the
[integration catalog](../README.md). The Credentials map is telemetry attribution only; it does not enforce an API-key policy.
Optional Ollama/NeMo inspection is configured on Altprobe through `LLM_GUARD_*`;
it consumes the captured request/response bodies and writes OCSF assessments.
Capture limits remain significant: incomplete or oversized bodies must not be
interpreted as a successful content check.
