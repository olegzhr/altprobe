FROM kong:3.9.0

USER root

RUN mkdir -p /usr/local/share/lua/5.1/kong/plugins/custom-log-redis

COPY custom-log-redis/handler.lua \
    /usr/local/share/lua/5.1/kong/plugins/custom-log-redis/

COPY custom-log-redis/schema.lua \
    /usr/local/share/lua/5.1/kong/plugins/custom-log-redis/

COPY kong.yaml /etc/kong/kong.yaml

USER kong
