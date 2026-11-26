#!/bin/sh
set -eu
apisix init
apisix start
exec tail -f /usr/local/apisix/logs/error.log
