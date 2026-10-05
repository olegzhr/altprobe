FROM ubuntu:jammy

# Builds the lab Altprobe image from the released .deb downloaded from GitHub
# (same release URL pattern as lab_apisix). The binary is fetched at build
# time, so the build context does NOT need a local .deb and the image always
# ships the published release.
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download

# Runtime dependencies for the current Altprobe build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    wget ca-certificates \
    libdaemon0 \
    libboost-system1.74.0 libboost-filesystem1.74.0 libboost-regex1.74.0 \
    libboost-iostreams1.74.0 libboost-thread1.74.0 \
    libyaml-cpp0.7 libhiredis0.14 libmodsecurity3 libmaxminddb0 \
    libssl3 libwebsockets16 libnghttp2-dev \
 && rm -rf /var/lib/apt/lists/*

RUN wget -q ${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}.deb -O /tmp/altprobe.deb \
 && dpkg -i /tmp/altprobe.deb \
 && rm -f /tmp/altprobe.deb \
 && ldconfig

# Same OWASP CRS activation as lab_v2 (see that Dockerfile for the detailed
# rationale) — `make package` now fetches CRS itself (Makefile:154-180 in
# the source tree), so this build's .deb already ships a populated
# etc/altprobe/coreruleset/ directory. We only need to activate the default
# config and drop the ModSecurity-3.0.6-incompatible rule file.
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
COPY rules/secret_access.conf /etc/altprobe/coreruleset/rules/secret_access.conf

# Trivy is installed so the SBOM test can run the real tool when a
# vulnerability DB is available; the lab falls back to a bundled CycloneDX
# fixture otherwise (see sbom-test.yaml).
ARG TRIVY_VERSION=0.75.0
RUN wget -q https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb -O /tmp/trivy.deb \
 && dpkg -i /tmp/trivy.deb \
 && rm -f /tmp/trivy.deb

# Test-only, free MaxMind-compatible GeoLite2 database generated for private
# lab addresses, plus the SBOM pipeline fixture.
COPY GeoLite2-City-test.mmdb /etc/altprobe/GeoLite2-City-test.mmdb
COPY sbom-fixture.cdx.json /etc/altprobe/sbom-fixture.cdx.json
COPY sbom-test.yaml /etc/altprobe/sbom-test.yaml

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
