#!/bin/sh
set -eu
umask 077
cd /certs
# Keep valid lab certificates on repeated compose up; a running gateway uses this CA.
valid=true
for name in ca server policy-active policy-blocked policy-unknown; do
  if [ ! -s "$name.key" ] || ! openssl x509 -checkend 3600 -noout -in "$name.crt" >/dev/null 2>&1; then
    valid=false
    break
  fi
done
if [ "$valid" = true ]; then exit 0; fi
# Lab-only CA. Generate into a volume; never commit private keys.
openssl req -x509 -newkey rsa:2048 -nodes -days 7 -subj /CN=Altprobe-lab-CA -keyout ca.key -out ca.crt
openssl req -newkey rsa:2048 -nodes -subj /CN=localhost -keyout server.key -out server.csr
printf '%s\n' 'subjectAltName=DNS:localhost,DNS:envoy,IP:127.0.0.1' 'extendedKeyUsage=serverAuth' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 7 -extfile server.ext -out server.crt
for name in policy-active policy-blocked policy-unknown; do
  openssl req -newkey rsa:2048 -nodes -subj "/CN=$name" -keyout "$name.key" -out "$name.csr"
  printf '%s\n' "subjectAltName=URI:spiffe://lab/$name" 'extendedKeyUsage=clientAuth' > "$name.ext"
  openssl x509 -req -in "$name.csr" -CA ca.crt -CAkey ca.key -CAserial ca.srl -days 7 -extfile "$name.ext" -out "$name.crt"
done
# Envoy runs unprivileged. Only this isolated lab volume contains these keys.
chmod 0644 *.crt server.key policy-*.key
