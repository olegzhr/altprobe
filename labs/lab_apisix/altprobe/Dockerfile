ARG BUILD_IMAGE=ubuntu:jammy
FROM ${BUILD_IMAGE}
USER root
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_SHA256=d68fc81bce31321bf428444a4fa02868b0ea68e4e34b32c7b9a2e7fb8f91f3bb
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download

# Install runtime libraries from the verified package's Depends metadata.
# The published amd64 package targets Ubuntu 22.04 (Jammy).
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates python3 \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}_amd64.deb" -O /tmp/altprobe.deb \
 && echo "${ALTPROBE_SHA256}  /tmp/altprobe.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends /tmp/altprobe.deb \
 && ldconfig \
 && ldd /usr/local/bin/altprobe > /tmp/altprobe-ldd.txt \
 && cat /tmp/altprobe-ldd.txt \
 && ! grep -q 'not found' /tmp/altprobe-ldd.txt \
 && rm -f /tmp/altprobe.deb /tmp/altprobe-ldd.txt \
 && rm -rf /var/lib/apt/lists/*

# Refuse an old package that would silently ignore the new Policy settings.
RUN grep -q '^policy:' /etc/altprobe/altprobe.yaml \
 && grep -q 'incident_enabled:' /etc/altprobe/altprobe.yaml \
 && grep -q 'sidecar-grpc:' /etc/altprobe/altprobe.yaml \
 && grep -q 'af_tls_verify:' /etc/altprobe/altprobe.yaml \
 && grep -q 'os_tls_verify:' /etc/altprobe/altprobe.yaml

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
COPY labs/lab_apisix/altprobe/rules/secret_access.conf /etc/altprobe/coreruleset/rules/secret_access.conf

# SBOM regression uses the bundled CycloneDX fixture. Set LAB_INSTALL_TRIVY=true
# to install Trivy for optional scans with an available vulnerability database.
ARG TRIVY_VERSION=0.75.0
ARG INSTALL_TRIVY=false
RUN if [ "$INSTALL_TRIVY" = true ]; then \
    python3 -c "import urllib.request; urllib.request.urlretrieve('https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.deb', '/tmp/trivy.deb')" \
 && dpkg -i /tmp/trivy.deb \
 && rm -f /tmp/trivy.deb; fi

# SBOM pipeline fixture (CycloneDX) used by the vulnerability-finding test.
COPY labs/lab_apisix/altprobe/sbom-fixture.cdx.json /etc/altprobe/sbom-fixture.cdx.json
COPY labs/lab_apisix/altprobe/sbom-test.yaml /etc/altprobe/sbom-test.yaml

COPY labs/lab_apisix/altprobe/entrypoint.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
