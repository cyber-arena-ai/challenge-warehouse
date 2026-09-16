#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/changedetection

echo "[*] validating changedetection.io source"
runuser -u arena_agent -- env PYTHONPATH="/usr/local:$SRC" \
    python -m compileall -q "$SRC/changedetectionio" "$SRC/changedetection.py"
echo "changedetection: compile ok"
exec /arena/start.sh
