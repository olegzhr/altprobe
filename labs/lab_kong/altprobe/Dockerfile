FROM ubuntu:jammy AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
 build-essential dpkg-dev curl ca-certificates pkg-config libboost-all-dev \
 libhiredis-dev libyaml-cpp-dev libmodsecurity-dev libmaxminddb-dev libssl-dev \
 libdaemon-dev protobuf-compiler protobuf-compiler-grpc libgrpc++-dev libprotobuf-dev \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY altprobe/ ./
RUN make -j2 CONF=Debug
RUN find scripts tests -name '*.sh' -exec sed -i 's/\r$//' {} + \
 && sh tests/run_cpp_tests.sh
RUN make package ALTPROBE_VERSION=1.0.2

FROM ubuntu:jammy
USER root

# Runtime package is built from the modified local altprobe/ source above.
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget ca-certificates python3 libdaemon0 \
    libboost-system1.74.0 libboost-filesystem1.74.0 libboost-regex1.74.0 \
    libboost-iostreams1.74.0 libboost-thread1.74.0 \
    libyaml-cpp0.7 libhiredis0.14 libmodsecurity3 libmaxminddb0 \
    libssl3 libgrpc++1 libprotobuf23 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /build/pkg/dpkg/altprobe_1.0.2.deb /tmp/altprobe.deb
RUN dpkg -i /tmp/altprobe.deb && rm /tmp/altprobe.deb && ldconfig

# Refuse an old package that would silently ignore the new Policy settings.
RUN grep -q '^policy:' /etc/altprobe/altprobe.yaml \
 && grep -q 'incident_enabled:' /etc/altprobe/altprobe.yaml \
 && grep -q 'sidecar-grpc:' /etc/altprobe/altprobe.yaml \
 && grep -q 'af_tls_verify:' /etc/altprobe/altprobe.yaml \
 && grep -q 'os_tls_verify:' /etc/altprobe/altprobe.yaml

# Use the same pinned CRS release as src/Makefile's package target.
ARG CRS_VERSION=4.29.0
RUN python3 -c "import urllib.request; urllib.request.urlretrieve('https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz', '/tmp/crs.tar.gz')" \
 && mkdir -p /etc/altprobe/coreruleset \
 && tar -xzf /tmp/crs.tar.gz --strip-components=1 -C /etc/altprobe/coreruleset \
 && rm /tmp/crs.tar.gz

# Activate CRS defaults and omit the ModSecurity-3.0.6-incompatible rule file.
RUN cp /etc/altprobe/coreruleset/crs-setup.conf.example /etc/altprobe/coreruleset/crs-setup.conf \
 && rm -f /etc/altprobe/coreruleset/rules/REQUEST-922-MULTIPART-ATTACK.conf \
 && cat >> /etc/altprobe/coreruleset/crs-setup.conf <<'EOF'

# ---- Activated defaults (lab) ----
SecAction \
    "id:900998,\
    phase:1,\
    nolog,\
    pass,\
    t:none,\
    setvar:tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|,\
    setvar:tx.critical_anomaly_score=5,\
    setvar:tx.error_anomaly_score=4,\
    setvar:tx.warning_anomaly_score=3,\
    setvar:tx.notice_anomaly_score=2,\
    setvar:tx.inbound_anomaly_score_threshold=5,\
    setvar:tx.outbound_anomaly_score_threshold=4,\
    setvar:tx.paranoia_level=1"
EOF

# Public labs do not add custom detection rules. The empty file keeps the build
# path stable for users who compare this lab with internal examples.
COPY labs-altprobe/labs/lab_kong/altprobe/rules/secret_access.conf /etc/altprobe/coreruleset/rules/secret_access.conf

# SBOM regression uses the bundled CycloneDX fixture. Set LAB_INSTALL_TRIVY=true
# to install Trivy for optional scans with an available vulnerability database.
ARG TRIVY_VERSION=0.75.0
ARG INSTALL_TRIVY=false
RUN if [ "$INSTALL_TRIVY" = true ]; then \
    python3 -c "import urllib.request; urllib.request.urlretrieve('https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb', '/tmp/trivy.deb')" \
 && dpkg -i /tmp/trivy.deb \
 && rm -f /tmp/trivy.deb; fi

# Test-only, free MaxMind-compatible GeoLite2 database generated for private
# lab addresses, plus the SBOM pipeline fixture.
COPY labs-altprobe/labs/lab_kong/altprobe/GeoLite2-City-test.mmdb /etc/altprobe/GeoLite2-City-test.mmdb
COPY labs-altprobe/labs/lab_kong/altprobe/sbom-fixture.cdx.json /etc/altprobe/sbom-fixture.cdx.json
COPY labs-altprobe/labs/lab_kong/altprobe/sbom-test.yaml /etc/altprobe/sbom-test.yaml

COPY labs-altprobe/labs/lab_kong/altprobe/entrypoint.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
