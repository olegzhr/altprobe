# Envoy → Altprobe

Envoy's Lua HTTP filter captures request/response data and MCP fields into
dynamic metadata; the JSON access logger writes one line per request. Altprobe
reads the file through `SOURCES_PROXY_LOG`.

## Install

1. Merge `envoy.yaml` into the Envoy bootstrap configuration.
2. Point the `app` cluster at your upstream.
3. Create a writable access-log directory, for example:

```bash
mkdir -p /var/log/envoy
touch /var/log/envoy/access.log
```

## Altprobe

```yaml
sources:
  proxy_log: /var/log/envoy/access.log
  proxy_redis: ""
```

`max_body` caps captured bodies (4096 request / 8192 response). The filter does
not trust client identity headers; identity comes from an authenticated
principal when the deployment supplies one, otherwise from `remote_addr`.
