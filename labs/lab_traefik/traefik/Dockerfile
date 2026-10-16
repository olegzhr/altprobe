FROM traefik:v3.3.6
COPY altprobe.go go.mod .traefik.yml /plugins-local/src/github.com/altprobe/traefik-altprobe/
COPY traefik.yaml /etc/traefik/traefik.yaml
COPY dynamic.yaml /etc/traefik/dynamic.yaml
