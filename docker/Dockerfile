FROM ubuntu:jammy

# Altprobe version to install. Override at build time with:
#   --build-arg ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_SHA256=9d4106796e7bf16bbd9b789aae7c3c36742c4b2a82f69a5dd94b11a1f5b2e25a
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download

# Install runtime libraries from the verified package's Depends metadata.
# The published amd64 package targets Ubuntu 22.04 (Jammy).
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}_amd64.deb" -O /tmp/altprobe.deb \
 && echo "${ALTPROBE_SHA256}  /tmp/altprobe.deb" | sha256sum -c - \
 && apt-get install -y --no-install-recommends /tmp/altprobe.deb \
 && ldconfig \
 && ldd /usr/local/bin/altprobe > /tmp/altprobe-ldd.txt \
 && cat /tmp/altprobe-ldd.txt \
 && ! grep -q 'not found' /tmp/altprobe-ldd.txt \
 && rm -f /tmp/altprobe.deb /tmp/altprobe-ldd.txt \
 && rm -rf /var/lib/apt/lists/*

# Activate the bundled OWASP CRS so ModSecurity starts: the package ships only
# crs-setup.conf.example, and REQUEST-922-MULTIPART-ATTACK.conf is incompatible
# with ModSecurity 3.0.6. Allowed content types and anomaly thresholds mirror
# the lab images.
RUN cp /etc/altprobe/coreruleset/crs-setup.conf.example /etc/altprobe/coreruleset/crs-setup.conf \
 && rm -f /etc/altprobe/coreruleset/rules/REQUEST-922-MULTIPART-ATTACK.conf \
 && cat >> /etc/altprobe/coreruleset/crs-setup.conf <<'EOF'

# ---- Activated defaults ----
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

COPY entrypoint.sh /usr/local/bin/
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
 && chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
