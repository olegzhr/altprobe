#!/bin/sh
cat > /tmp/otlp.json <<'JSON'
{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"claude-code"}}]},"scopeLogs":[{"logRecords":[{"timeUnixNano":"1793436000000000000","eventName":"api_request","attributes":[{"key":"session.id","value":{"stringValue":"probe"}}]}]}]}]}
JSON
curl -s -o /tmp/otlp.out -w 'code=%{http_code}\n' -X POST http://altprobe:4318/v1/logs \
  -H 'Content-Type: application/json' --data-binary @/tmp/otlp.json
cat /tmp/otlp.out
echo
