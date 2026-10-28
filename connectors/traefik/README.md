# Traefik → Altprobe

Go middleware for Traefik 3.x, loaded through the local Yaegi plugin mechanism.
It sends one Redis record per request and optionally enforces API-key Policy.

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
          MaxBodySize: 5000
          PolicyURL: http://127.0.0.1:8181/v1/data/altprobe/allow
          PolicyPaths: [/mcp]
          Credentials:
            replace-with-private-api-key: consumer-name
```

Attach the middleware before path rewriting. `PolicyPaths` are exact paths; all
other paths collect telemetry without authorization. Identity is
`auth:traefik:<consumer>` or the observed source IP. Keep credentials in private
configuration and use TLS for client traffic.

Altprobe: `SOURCES_PROXY_REDIS=log_proxy`; native Go tests: `go test ./...`.
