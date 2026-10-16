# Full gateway labs for Altprobe

Besides the three base labs (APISIX, OpenResty, Envoy), three standalone demo
stands are available, each with its own mock, OpenSearch, Redis, gateway
configuration and gateway connector plugin:

| Gateway | Lab | Connector | Implementation |
|---|---|---|---|
| Kong OSS | [lab_kong](lab_kong/README.md) | [connectors/kong](../connectors/kong/README.md) | Lua plugin, native key-auth |
| Traefik Proxy OSS | [lab_traefik](lab_traefik/README.md) | [connectors/traefik](../connectors/traefik/README.md) | Go/Yaegi middleware |
| Higress | [lab_higress](lab_higress/README.md) | [connectors/higress](../connectors/higress/README.md) | Go/Wasm filter, static data plane |

Base labs: [lab_apisix](lab_apisix/README.md),
[lab_openresty](lab_openresty/README.md), [lab_envoy](lab_envoy/README.md).

Every lab ships its own `mock`, `opensearch`, `altprobe`, gateway configuration,
Redis and OpenSearch/Dashboards assets and init jobs. This is a local demo
profile: inventory/traces/incidents are served by the mock, MCP is open, and
Policy is demonstrated on dedicated routes. No real AI or cloud service is
contacted by default.

## Shared tests

All labs use the shared suite in [tests](tests/README.md). The `gateway`
category (capture, Redis, real Altprobe, OCSF ingestion, Dashboards, body
limits, SSE and Policy) runs on the Kong OSS / Traefik / Higress labs; for
APISIX / OpenResty / Envoy those scenarios are skipped.

The labs share host ports, so run them **one at a time**:

```bash
cd labs/lab_apisix          # or lab_openresty | lab_envoy | lab_kong | lab_traefik | lab_higress
docker compose up -d --build --wait

cd ../tests
python -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_PROFILE=demo LAB_LOCAL_COLLECTOR=1 python run_tests.py
```

For the base APISIX/OpenResty/Envoy labs `LAB_BASE` is enough; the extended
gateway scenarios additionally use `LAB_GATEWAY`, `LAB_PROFILE=demo` and
`LAB_LOCAL_COLLECTOR=1` (see [tests](tests/README.md)). Stop with
`docker compose down` (`-v` also removes the OpenSearch data volume).

## How Altprobe is built

- APISIX / OpenResty / Envoy download the published `.deb` from GitHub Releases
  (`ALTPROBE_VERSION`, default `1.0.2`).
- Kong OSS / Traefik / Higress demonstrate new gateway types and therefore build
  Altprobe **from source**. A sibling directory `altprobe/` with the Altprobe
  source tree must exist next to this repository: the Docker build context is the
  parent directory that contains both `altprobe/` and `labs-altprobe/`. A
  published release may not support the `kong` / `traefik` / `higress` types.

Gateway plugin sources live in [connectors](../connectors/README.md).
