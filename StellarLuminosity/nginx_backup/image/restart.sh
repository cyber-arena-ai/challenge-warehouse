#!/usr/bin/env bash
# Framework restart script for nginx-backup.
#
# Validates the defender's proxy.conf then reloads the nginx proxy.
# nginx -t runs first; a syntax error exits non-zero and the error
# message surfaces in RestartHandler's CheckResult.detail so the
# defender sees exactly what is wrong.
#
# Mode 555, root-owned — the agent can read + execute but not modify.

set -e

nginx -c /arena/nginx-proxy.conf -t
nginx -c /arena/nginx-proxy.conf -s reload

# Brief settle for the reload to take effect before the smoke probe.
sleep 0.2

echo "nginx-proxy reloaded"
