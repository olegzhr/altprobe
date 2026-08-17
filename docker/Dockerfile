FROM ubuntu:jammy

# Altprobe version to install: package name and GitHub tag.
# Override at build time: --build-arg ALTPROBE_VERSION=1.0.1 --build-arg ALTPROBE_TAG=v1.0.1
ARG ALTPROBE_VERSION=1.0.1
ARG ALTPROBE_TAG=v1.0.1

# Runtime dependencies for the current Altprobe XDR build.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    wget ca-certificates \
    libdaemon0 \
    libboost-system1.74.0 libboost-filesystem1.74.0 libboost-regex1.74.0 \
    libboost-iostreams1.74.0 libboost-thread1.74.0 \
    libyaml-cpp0.7 libhiredis0.14 libmodsecurity3 libmaxminddb0 \
    libssl3 libwebsockets16 \
 && rm -rf /var/lib/apt/lists/*

RUN wget -q "https://github.com/olegzhr/altprobe/releases/download/${ALTPROBE_TAG}/altprobe_${ALTPROBE_VERSION}.deb" \
 && dpkg -i altprobe_${ALTPROBE_VERSION}.deb \
 && rm -f altprobe_${ALTPROBE_VERSION}.deb \
 && ldconfig

COPY entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
