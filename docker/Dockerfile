# Runtime image built from the published Altprobe release package.
#
# The binary is never compiled from this repository: the image installs
# `altprobe_<version>_amd64.deb` from the Altprobe GitHub release, verifies every
# asset against the release `SHA256SUMS`, and records the exact package and
# binary digests in /usr/local/share/altprobe/release-receipt.json.
#
#   docker build -f docker/Dockerfile -t altprobe:release .
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download
ARG ALTPROBE_PACKAGE_SHA256

COPY labs/common/altprobe/release_metadata.py /usr/local/lib/altprobe_release_metadata.py

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl python3 \
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

ENTRYPOINT ["/usr/local/bin/altprobe"]
CMD ["docker"]
