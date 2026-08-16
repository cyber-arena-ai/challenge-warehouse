#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/changedetection

echo "[*] Validating changedetection.io source under ${SRC}..."
if ! runuser -u arena_agent -- env PYTHONPATH="/usr/local:$SRC" \
    python -m compileall -q "$SRC/changedetectionio" "$SRC/changedetection.py"; then
    echo "changedetection-restart: compile failed" >&2
    exit 10
fi
echo "changedetection-restart: compile ok"

if ! /arena/start.sh; then
    echo "changedetection-restart: launch/readiness failed" >&2
    exit 30
fi
