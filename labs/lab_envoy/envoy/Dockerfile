FROM envoyproxy/ai-gateway-cli:latest AS aigw

# Runs the Envoy data-plane binary that ships inside the Envoy AI Gateway CLI
# image. The CLI itself (`aigw run`) generates its own Envoy config and does
# not expose the file access-log config Altprobe's proxy file source needs, so
# the lab drives the bundled Envoy directly with a static envoy.yaml.
FROM envoyproxy/ai-gateway-cli:latest

USER root

# Envoy 1.x data plane bundled by the AI Gateway project (version glob so a
# tag bump does not require editing a hardcoded path).
COPY --from=aigw /home/nonroot/.local/share/aigw/envoy-versions/*/bin/envoy /usr/local/bin/envoy
COPY --chown=nonroot:nonroot envoy.yaml /etc/envoy/envoy.yaml

USER nonroot

# The aigw base image ships a healthcheck for the aigw admin server on 1064,
# which is not running here (we run Envoy directly on 9901).
HEALTHCHECK NONE

ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml"]
