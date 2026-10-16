# Traefik Proxy OSS -> Altprobe

Go middleware for Traefik Proxy v3.3.6, loaded through the local plugin mechanism
(Yaegi). No third-party Go libraries. Copy this directory under
`/plugins-local/src/github.com/altprobe/traefik-altprobe`.

Static configuration:

```yaml
experimental:
  localPlugins:
    altprobe:
      moduleName: github.com/altprobe/traefik-altprobe
```

Dynamic middleware example:

```yaml
http:
  middlewares:
    altprobe:
      plugin:
        altprobe:
          RedisAddress: redis:6379
          RedisKey: log_proxy
          HostName: my-traefik
          MaxBodySize: 5000
          TimeoutMS: 2000
          QueueSize: 256
          PolicyURL: http://127.0.0.1:8181/v1/data/altprobe/allow
          PolicyPaths: [/mcp]
          Credentials:
            replace-with-private-api-key: consumer-name
```

Attach the middleware to routers before path rewriting. PolicyPaths are exact,
case-sensitive URL paths; all other paths collect telemetry without authorization.
The credential map is server-side configuration: client identity headers cannot
select the subject. This adapter implements API-key authentication itself; it
does not validate JWT or trust arbitrary ForwardAuth identity headers. Keep
credentials in private mounted configuration and use TLS for client traffic.

Policy uses the APISIX envelope and `result.allow/status_code/reason` object.
Network/non-200/invalid/missing allow => 503, missing credentials => 401.
Both Altprobe Policy and an OPA decision returning this object are supported.
HTTP redirects are not followed and HTTPS uses the system trust store.

Altprobe: `POLICY_TYPE_AGENT=traefik`, HTTP sidecar enabled,
`SOURCES_PROXY_REDIS=log_proxy`; identity is `auth:traefik:<consumer>`.
Install the rebuilt Altprobe `1.0.2` package with `traefik` gateway-type support.
Use the digest pinned in the [labs guide](../../labs/README.md#collector-package);
earlier binaries under the same version may lack this gateway type.

Bodies are captured through a bounded tee on request reads and response writes;
SSE writes explicitly flush to preserve delivery across Yaegi's ResponseWriter
bridge. Native Go wrappers also implement Flush and Hijack; WebSocket upgrades
through Yaegi have not been validated and frame contents are not captured.
API-key/authorization/cookie headers are redacted; body content
is not semantically redacted. A bounded asynchronous queue sends Redis RPUSH;
overflow/delivery failure logs a dropped event, without blocking the request.
Queue shutdown may discard pending events. Redis authentication/TLS are not
implemented; use a private Redis network or add an appropriate transport.

Tests: `go test ./...`. Runnable demo: [`labs/lab_traefik`](../../labs/lab_traefik/README.md).
