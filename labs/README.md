# Labs

Nine labs: five gateway stacks and four source/integration scenarios for
Altprobe and OpenSearch.

| Lab | Focus | Native OTEL |
|---|---|---|
| [`lab_apisix`](lab_apisix/README.md) | APISIX gateway, prebuilt WAF and MCP/AI traffic | HTTP/protobuf |
| [`lab_envoy`](lab_envoy/README.md) | Envoy AI Gateway | gRPC |
| [`lab_higress`](lab_higress/README.md) | Higress | gRPC |
| [`lab_kong`](lab_kong/README.md) | Kong OSS | HTTP |
| [`lab_traefik`](lab_traefik/README.md) | Traefik | HTTP |
| [`lab_nemo`](lab_nemo/README.md) | NeMo Guardrails with LangChain and APISIX | No |
| [`lab_sbom`](lab_sbom/README.md) | Trivy SBOM and OCSF vulnerability findings | No |
| [`lab_suricata`](lab_suricata/README.md) | Suricata TLS/DNS/flow -> Redis -> Altprobe | No |
| [`lab_openshell`](lab_openshell/README.md) | NVIDIA OpenShell | No |

Each lab uses real integration components with local provider mocks where needed.
OpenShell additionally needs its external CLI/gateway setup. Run one lab at a
time: source and gateway stacks reuse host ports, including OpenSearch and
Dashboards.

## Altprobe image

Every lab installs the published Altprobe release package
(`altprobe_1.0.2_amd64.deb`) with the shared
[`common/altprobe/Dockerfile`](common/altprobe/Dockerfile) and verifies it against
the release `SHA256SUMS`. Nothing is compiled from a source checkout.
Gateway labs enable OWASP CRS; `lab_suricata`, `lab_openshell`, `lab_sbom` and
`lab_nemo` install without it. `lab_sbom` also passes `TRIVY=true` to install
the Trivy binary.

The image contains the configuration shipped in the release package and records
the package and binary digests in
`/usr/local/share/altprobe/release-receipt.json`. Lab-specific settings are
passed as `ALTPROBE_*`, `SOURCES_*` and `SINKS_*` environment variables in each
compose file.

The image downloads the package during the build. Docker caches that layer, so
after a release is republished rebuild the image without cache
(`docker build --no-cache -f labs/common/altprobe/Dockerfile ...`), otherwise the
previous package is reused and the build fails the schema check with a clear
message.

## Lab security

These stacks are for local evaluation, not for shared or production hosts:

- published ports bind `127.0.0.1` only; nothing is exposed to the network;
- OpenSearch runs with its security plugin disabled (`DISABLE_SECURITY_PLUGIN`),
  and the shipped credentials (`SINKS_OS_PWD: admin`, `ALERTFLEX_KEY`) are lab
  placeholders, not secrets;
- `lab_suricata` runs Suricata `privileged` on `network_mode: host` to capture
  the lab bridge;
- the OpenShell gateway runs as root and mounts `/var/run/docker.sock` because it
  starts sandbox containers with the Docker compute driver.

Run these labs only on a disposable machine or lab VM. Replace every placeholder
credential before reusing a stack for anything but a local demo.

## Start

```bash
cd labs/lab_apisix
docker compose up -d --build --wait --wait-timeout 900
```

- Gateway: `http://localhost:9080`
- OpenSearch: `http://localhost:9200`
- Dashboards: `http://localhost:5601/app/dashboards`
- OTEL traces: `http://localhost:5601/app/dashboards#/view/altprobe-otel-traces`

The first run pulls the images, downloads the release package and builds the lab
gateway and mock; it can take several minutes.

## Test

```bash
cd labs/tests
python3 -m pip install -r requirements.txt
LAB_GATEWAY=apisix LAB_INDEX_WAIT=60 python3 run_tests.py
```

Use the lab's gateway name for `LAB_GATEWAY`: `apisix`, `envoy`, `kong`,
`traefik` or `higress`. See [`tests/README.md`](tests/README.md) for
categories and settings. `lab_suricata`, `lab_openshell`, `lab_sbom` and
`lab_nemo` contain their own verification scripts.

Native gateways use a separate `altprobe-otel` container because
`TRACE_MODE=internal` and `TRACE_MODE=external` are mutually exclusive. Its
receiver listens on loopback and preserves native trace, span and parent IDs.

## Refresh assets

```bash
docker compose run --rm opensearch-init
docker compose run --rm opensearch-dashboards-init
```

See [`ids/README.md`](ids/README.md) for the optional Suricata replay overlay.

## Source labs and fresh evidence

From the repository root:

```bash
python3 labs/run_source_lab.py nemo start   # or sbom / suricata
python3 labs/run_source_lab.py nemo test
python3 labs/run_source_lab.py nemo stop
```

`start` builds before running and preserves all existing data volumes. The
generated Compose override and run receipt live under the selected lab's
`.local/`. Tests validate the current source/config/image/binary provenance,
container start times and run-specific evidence; a receipt older than 24 hours
or a restarted/rebuilt container requires a new `start`. A manual `compose up`
remains useful for diagnosis but does not create a valid test receipt.

NeMo checks safe delivery, jailbreak refusal, absence of jailbreak calls to the
mock and current OCSF assessments. SBOM checks the expected CVEs for the run's
unique asset. `lab_suricata` checks TLS/DNS/flow through the shared shipper.

OpenShell follows its own [bootstrap instructions](lab_openshell/README.md).
Its indexed-data verifier is a smoke check and does not establish fresh binary
provenance or a new end-to-end run. Source-unit regressions separately exercise
allowed/denied network extraction and interruptible SBOM shutdown.

`stop`/plain `docker compose down` retain indexed data, Claude home, PKI and
Trivy cache. Existing results are never treated as proof of a new image.
