FROM alpine:3.20
RUN apk add --no-cache openssl \
 && openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
      -keyout /key.pem -out /cert.pem \
      -subj "/CN=api.openai.com" \
      -addext "subjectAltName=DNS:api.openai.com"
CMD ["openssl", "s_server", "-accept", "443", "-cert", "/cert.pem", "-key", "/key.pem", "-www", "-quiet"]
