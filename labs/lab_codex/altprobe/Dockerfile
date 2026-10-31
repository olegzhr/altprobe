ARG BUILD_IMAGE=ubuntu:jammy

FROM ${BUILD_IMAGE}
USER root
ARG ALTPROBE_VERSION=1.0.2
ARG ALTPROBE_RELEASE_BASE_URL=https://github.com/olegzhr/altprobe/releases/download

# Install the published package, verified against the release SHA256SUMS.
RUN apt-get update \
 && apt-get install -y --no-install-recommends wget ca-certificates \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/altprobe_${ALTPROBE_VERSION}_amd64.deb" -O /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb \
 && wget -q "${ALTPROBE_RELEASE_BASE_URL}/v${ALTPROBE_VERSION}/SHA256SUMS" -O /tmp/SHA256SUMS \
 && (cd /tmp && grep " altprobe_${ALTPROBE_VERSION}_amd64.deb$" SHA256SUMS | sha256sum -c -) \
 && apt-get install -y --no-install-recommends /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb \
 && ldconfig \
 && ldd /usr/local/bin/altprobe > /tmp/altprobe-ldd.txt \
 && cat /tmp/altprobe-ldd.txt \
 && ! grep -q 'not found' /tmp/altprobe-ldd.txt \
 && rm -f /tmp/altprobe_${ALTPROBE_VERSION}_amd64.deb /tmp/SHA256SUMS /tmp/altprobe-ldd.txt \
 && rm -rf /var/lib/apt/lists/*

# Lab overlay: agent source, inbound/outbound correlation, OpenSearch trace sink.
COPY etc/ /etc/altprobe/
RUN sed -i 's/\r$//' /etc/altprobe/*.yaml

ENTRYPOINT ["/usr/local/bin/altprobe"]
CMD ["docker"]
