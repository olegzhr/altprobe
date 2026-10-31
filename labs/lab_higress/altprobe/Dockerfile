ARG BUILD_IMAGE=ubuntu:jammy

FROM ${BUILD_IMAGE}
USER root
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download

# Install runtime libraries from the verified package's Depends metadata.
# The published amd64 package targets Ubuntu 22.04 (Jammy).
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates python3 \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}_amd64.deb" -O /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/SHA256SUMS" -O /tmp/SHA256SUMS \
 && (cd /tmp && grep " altprobe_${ALTPROBE_VERSION}_amd64.deb$" SHA256SUMS | sha256sum -c -) \
 && apt-get install -y --no-install-recommends /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb \
 && ldconfig \
 && ldd /usr/local/bin/altprobe > /tmp/altprobe-ldd.txt \
 && cat /tmp/altprobe-ldd.txt \
 && ! grep -q 'not found' /tmp/altprobe-ldd.txt \
 && rm -f /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb /tmp/altprobe-ldd.txt \
 && rm -rf /var/lib/apt/lists/*

# Require the current internal/external OTLP collector and selectable OS streams.
RUN grep -q 'trace_mode:' /etc/altprobe/altprobe.yaml \
 && grep -q 'os_types:' /etc/altprobe/altprobe.yaml \
 && grep -q 'trusted_peers:' /etc/altprobe/altprobe.yaml

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
COPY labs/lab_higress/altprobe/rules/secret_access.conf /etc/altprobe/coreruleset/rules/secret_access.conf

# SBOM regression uses the bundled CycloneDX fixture. Set LAB_INSTALL_TRIVY=true
# to install Trivy for optional scans with an available vulnerability database.
ARG TRIVY_VERSION=0.75.0
ARG INSTALL_TRIVY=false
RUN if [ "$INSTALL_TRIVY" = true ]; then \
    python3 -c "import urllib.request; urllib.request.urlretrieve('https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb', '/tmp/trivy.deb')" \
 && dpkg -i /tmp/trivy.deb \
 && rm -f /tmp/trivy.deb; fi

# SBOM pipeline fixture (CycloneDX) used by the vulnerability-finding test.
COPY labs/lab_higress/altprobe/sbom-fixture.cdx.json /etc/altprobe/sbom-fixture.cdx.json
COPY labs/lab_higress/altprobe/sbom-test.yaml /etc/altprobe/sbom-test.yaml

COPY labs/lab_higress/altprobe/entrypoint.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
