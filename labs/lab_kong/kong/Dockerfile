FROM kong:3.9.1
USER root
COPY altprobe /usr/local/share/lua/5.1/kong/plugins/altprobe
COPY kong.yaml /etc/kong/kong.yaml
USER kong
ENV KONG_DATABASE=off KONG_DECLARATIVE_CONFIG=/etc/kong/kong.yaml KONG_PLUGINS=bundled,altprobe
ENV KONG_PROXY_LISTEN=0.0.0.0:9080 KONG_ADMIN_LISTEN=off
