#!/bin/bash

# Starting a collector must preserve queued telemetry, including during outages.
exec altprobe start
