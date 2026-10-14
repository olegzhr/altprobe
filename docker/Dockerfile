FROM ubuntu:jammy

# Altprobe version to install. Override at build time with:
#   --build-arg ALTPROBE_VERSION=1.0.2
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
    libssl3 libgrpc++1 libprotobuf23 \
 && rm -rf /var/lib/apt/lists/*

RUN wget -q ${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}.deb -O /tmp/altprobe.deb \
 && dpkg -i /tmp/altprobe.deb \
 && rm -f /tmp/altprobe.deb \
 && ldconfig

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
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
