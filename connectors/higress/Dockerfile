FROM tinygo/tinygo:0.34.0 AS build
USER root
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN tinygo build -o /plugin.wasm -target=wasi -scheduler=none -gc=custom -tags=custommalloc -no-debug .

FROM higress-registry.cn-hangzhou.cr.aliyuncs.com/higress/gateway:v2.1.5
COPY --from=build /plugin.wasm /etc/envoy/altprobe.wasm
ENTRYPOINT ["/usr/local/bin/envoy"]
CMD ["-c", "/etc/envoy/envoy.yaml"]
