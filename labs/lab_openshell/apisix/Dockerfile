# APISIX 3.13 includes the built-in ai-proxy plugin used by the demo
# AI Gateway route.
FROM apache/apisix:3.13.0-debian

USER root

COPY conf/config.yaml /usr/local/apisix/conf/config.yaml
COPY redis-logger/redis-logger.lua /usr/local/apisix/apisix/plugins/redis-logger.lua
COPY entrypoint.sh /entrypoint.sh

# The apache/apisix:3.13.0-debian base is Debian bullseye and its configured
# deb.debian.org index went stale (libnghttp2-14 404s). The image itself ships
# commented-out snapshot.debian.org pins; use those, with [trusted=yes] and
# Acquire::Check-Valid-Until=false because the 20250610 snapshot's Release
# files are now expired. Only curl is needed (etcd health + Admin API).
# The APISIX vendor repo (repos.apiseven.com) is kept in place — its missing
# GPG key only produces a warning and apt-get update still exits 0.
RUN sed -i \
      -e 's|^deb http://deb.debian.org/debian bullseye main|deb [trusted=yes] http://snapshot.debian.org/archive/debian/20250610T000000Z bullseye main|' \
      -e 's|^deb http://deb.debian.org/debian-security bullseye-security main|deb [trusted=yes] http://snapshot.debian.org/archive/debian-security/20250610T000000Z bullseye-security main|' \
      -e 's|^deb http://deb.debian.org/debian bullseye-updates main|deb [trusted=yes] http://snapshot.debian.org/archive/debian/20250610T000000Z bullseye-updates main|' \
      /etc/apt/sources.list \
 && apt-get -o Acquire::Check-Valid-Until=false update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && chmod +x /entrypoint.sh

USER apisix

ENTRYPOINT ["/entrypoint.sh"]
