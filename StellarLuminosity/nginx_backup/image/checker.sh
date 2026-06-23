#!/usr/bin/env bash
# CHECKER-level health probe for nginx-backup.
#
# Verifies that the nginx-ui web UI is reachable through the nginx proxy
# on port 9000. Intentionally does NOT probe /api/backup — a successful
# defense (blocking that endpoint) must still pass this check.
#
# Exits 0 on pass. stdout/stderr is included in SERVICE_HEALTH_CHECK detail.
# Mode 555, root-owned — agent cannot tamper.

set -e

PORT=9000

code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "http://127.0.0.1:${PORT}/")

case "$code" in
    2*|3*)
        echo "checker: nginx-ui responded HTTP ${code} on port ${PORT}"
        exit 0
        ;;
    *)
        echo "checker: unexpected HTTP ${code} on port ${PORT}" >&2
        exit 1
        ;;
esac
