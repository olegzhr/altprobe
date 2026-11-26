# Single Altprobe image definition shared by every lab.
#
# The image installs the published `altprobe_<version>_amd64.deb` from the
# Altprobe GitHub release and verifies the selected snapshot and `SHA256SUMS`. It
# never compiles this repository and never copies a local binary, so a lab run
# always proves something about the published package. The exact package and
# installed binary digests are recorded in
# /usr/local/share/altprobe/release-receipt.json.
#
# Gateway labs enable OWASP CRS; source labs do not need it.
#
# docker compose in each lab passes the repository root as context and this
# Dockerfile.

ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download
ARG ALTPROBE_PACKAGE_SHA256
ARG CRS=true
ARG CRS_VERSION=4.29.0
ARG TRIVY=false
ARG TRIVY_VERSION=0.75.0
# Official SHA-256 of trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz from
# https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_checksums.txt
ARG TRIVY_SHA256=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f

COPY labs/common/altprobe/release_metadata.py /usr/local/lib/altprobe_release_metadata.py

# Download and verify the immutable release asset, then install it with its
# declared runtime dependencies.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 tar \
    && python3 /usr/local/lib/altprobe_release_metadata.py \
        --version "$ALTPROBE_VERSION" --base-url "$ALTPROBE_RELEASE_BASE_URL" \
        --download-dir /tmp/altprobe-release --expected-sha256 "$ALTPROBE_PACKAGE_SHA256" \
    && apt-get install -y --no-install-recommends "/tmp/altprobe-release/altprobe_${ALTPROBE_VERSION}_amd64.deb" \
    && ldconfig \
    && ldd /usr/local/bin/altprobe > /tmp/altprobe-ldd.txt \
    && ! grep -q 'not found' /tmp/altprobe-ldd.txt \
    && python3 /usr/local/lib/altprobe_release_metadata.py \
        --version "$ALTPROBE_VERSION" --base-url "$ALTPROBE_RELEASE_BASE_URL" \
        --package "/tmp/altprobe-release/altprobe_${ALTPROBE_VERSION}_amd64.deb" --sums /tmp/altprobe-release/SHA256SUMS \
        --binary /usr/local/bin/altprobe \
        --receipt /usr/local/share/altprobe/release-receipt.json \
    && rm -rf /tmp/altprobe-release /tmp/altprobe-ldd.txt \
    && rm -rf /var/lib/apt/lists/*

# SBOM lab only: install the official Trivy binary. The vulnerability database
# is downloaded on the first scan into the image's cache directory.
RUN if [ "$TRIVY" = "true" ]; then \
      curl -fsSL --retry 3 \
        "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        -o /tmp/trivy.tgz \
      && echo "${TRIVY_SHA256}  /tmp/trivy.tgz" | sha256sum -c - \
      && tar -xzf /tmp/trivy.tgz -C /usr/local/bin trivy \
      && chmod 0755 /usr/local/bin/trivy \
      && rm -f /tmp/trivy.tgz; \
    fi

COPY labs/common/altprobe/sbom/ /etc/altprobe/
COPY labs/common/altprobe/rules/secret_access.conf /opt/altprobe/secret_access.conf
COPY labs/common/altprobe/entrypoint.sh /usr/local/bin/entrypoint.sh

# Gateway labs use ModSecurity with OWASP CRS. Source labs build with CRS=false
# and leave ruleset_path empty in their configuration.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod +x /usr/local/bin/entrypoint.sh \
    && if [ "$CRS" = "true" ]; then \
         cp /etc/altprobe/coreruleset/crs-setup.conf.example \
            /etc/altprobe/coreruleset/crs-setup.conf \
         && rm -f /etc/altprobe/coreruleset/rules/REQUEST-922-MULTIPART-ATTACK.conf \
         && cp /opt/altprobe/secret_access.conf \
               /etc/altprobe/coreruleset/rules/secret_access.conf \
         && printf '%s\n' \
              '# ---- Activated defaults (lab) ----' \
              'SecAction \' \
              '    "id:900998,\' \
              '    phase:1,\' \
              '    nolog,\' \
              '    pass,\' \
              '    t:none,\' \
              '    setvar:tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json|,\' \
              '    setvar:tx.critical_anomaly_score=5,\' \
              '    setvar:tx.error_anomaly_score=4,\' \
              '    setvar:tx.warning_anomaly_score=3,\' \
              '    setvar:tx.notice_anomaly_score=2,\' \
              '    setvar:tx.inbound_anomaly_score_threshold=5,\' \
              '    setvar:tx.outbound_anomaly_score_threshold=4,\' \
              '    setvar:tx.paranoia_level=1"' \
              >> /etc/altprobe/coreruleset/crs-setup.conf \
         && rm -f /opt/altprobe/secret_access.conf; \
       else \
         rm -rf /etc/altprobe/coreruleset /opt/altprobe/secret_access.conf; \
       fi

# Fail the build if the published package predates the collector schema the
# labs configure (authorization moved to ctrlprobe and gateway identity became
# an explicit namespace). A stale release must be republished, not silently run.
RUN test -x /usr/local/bin/altprobe \
    && if ! grep -q 'gateway_type:' /etc/altprobe/altprobe.yaml \
       || ! grep -q 'trace_mode:' /etc/altprobe/altprobe.yaml \
       || ! grep -q 'os_types:' /etc/altprobe/altprobe.yaml \
       || ! grep -q 'trusted_peers:' /etc/altprobe/altprobe.yaml \
       || grep -q '^policy:' /etc/altprobe/altprobe.yaml \
       || grep -q 'sidecar-grpc:' /etc/altprobe/altprobe.yaml; then \
         echo "ERROR: the installed Altprobe release package is older than this lab configuration." >&2; \
         echo "Republish altprobe_${ALTPROBE_VERSION}_amd64.deb and SHA256SUMS from the altprobe repository (v1.0.2 release), then rebuild." >&2; \
         exit 1; \
       fi \
    && test -f /usr/local/share/altprobe/release-receipt.json

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
