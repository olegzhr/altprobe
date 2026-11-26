FROM apache/apisix:3.18.0-debian

USER root
COPY conf/config.yaml /usr/local/apisix/conf/config.yaml
COPY conf/apisix.yaml /usr/local/apisix/conf/apisix.yaml
COPY redis-logger.lua /usr/local/apisix/apisix/plugins/redis-logger.lua
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh

USER apisix
ENTRYPOINT ["/entrypoint.sh"]
