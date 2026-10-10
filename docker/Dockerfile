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

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
