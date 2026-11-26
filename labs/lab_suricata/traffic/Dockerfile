FROM alpine:3.20
RUN apk add --no-cache bind-tools curl openssl
COPY run.sh /run.sh
RUN chmod 0755 /run.sh
ENTRYPOINT ["/run.sh"]
