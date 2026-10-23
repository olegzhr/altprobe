# Full gateway labs for Altprobe

Besides the three base labs (APISIX, OpenResty, Envoy), three standalone demo
stands are available, each with its own mock, OpenSearch, gateway configuration
and gateway connector plugin (Redis is included where the plugin buffers events
in a Redis list):

| Gateway | Lab | Connector | Implementation |
|---|---|---|---|
| Kong OSS | [lab_kong](lab_kong/README.md) | [connectors/kong](../connectors/kong/README.md) | Lua plugin, native key-auth |
| Traefik Proxy OSS | [lab_traefik](lab_traefik/README.md) | [connectors/traefik](../connectors/traefik/README.md) | Go/Yaegi middleware |
| Higress | [lab_higress](lab_higress/README.md) | [connectors/higress](../connectors/higress/README.md) | Go/Wasm filter, static data plane |

Base labs: [lab_apisix](lab_apisix/README.md),
[lab_openresty](lab_openresty/README.md), [lab_envoy](lab_envoy/README.md).

Every lab ships its own `mock`, `opensearch`, `altprobe`, gateway configuration
and OpenSearch/Dashboards assets and init jobs; the gateway plugins that buffer
events in Redis also bring their own Redis, while the Envoy lab reads its
access-log file directly. This is a local demo profile: inventory/traces/
incidents are served by the mock, MCP is open, and Policy is demonstrated on
dedicated routes. No real AI or cloud service is contacted by default.

Identity is the gateway-authenticated auth key first
(`auth:<gateway>:<consumer>`) and the observed source address otherwise
(`ip:<host>:<remote_addr>`). Client-supplied identity headers are not used. MCP
session id and method are protocol metadata only.

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

## Collector package

All six labs install the published Altprobe `.deb`; the collector source code is
not needed. Clone this repository into any directory name:

```bash
git clone https://github.com/olegzhr/altprobe.git
cd altprobe/labs/lab_apisix
docker compose build --no-cache altprobe
docker compose up -d --build --wait
```

The package defaults are:

| Build argument | Default |
|---|---|
| `ALTPROBE_VERSION` | `1.0.2` |
| `ALTPROBE_RELEASE_BASE_URL` | `https://github.com/olegzhr/altprobe/releases/download` |
| `ALTPROBE_SHA256` | `d68fc81bce31321bf428444a4fa02868b0ea68e4e34b32c7b9a2e7fb8f91f3bb` |

SHA-256 is checked before installation. The digest identifies the rebuilt
`1.0.2` package uploaded on 2026-10-24, including the latest telemetry and policy fixes.
The release tag alone does not distinguish it from earlier `1.0.2` builds.
If you previously built a lab, rebuild its collector with `--no-cache` once;
Compose does not automatically refresh an existing image.

For a different package, set both `ALTPROBE_VERSION` and `ALTPROBE_SHA256` to
matching values. Set `ALTPROBE_RELEASE_BASE_URL` only when using a release mirror
with the same `v<version>/altprobe_<version>.deb` layout. A wrong digest stops
the build instead of silently installing a different binary.

Collector images use Ubuntu 22.04 (Jammy), install shared libraries from the
verified package's `Depends` metadata through APT, and fail the build if `ldd`
reports a missing library. All labs use the CRS 4.29.0 bundled in the package.
They use the bundled SBOM fixture by default; `LAB_INSTALL_TRIVY=true` optionally
installs Trivy, including in the Envoy lab. This does not download a vulnerability
database.

For strict endpoint policy (`unknown_endpoint=deny`), the updated collector
requires `accessApproved=true` as well as `authorizationReady=true`. Public
policy fixtures explicitly approve their declared demo routes. With a real
Alertflex collector, update its WARs/schema and approve the routes through the
console before enabling strict policy; discovery alone does not grant access.

Gateway plugin sources live in [connectors](../connectors/README.md).
