#!/usr/bin/env bash
set -euo pipefail

readonly PIDFILE=/run/gogs.pid
if [ ! -s "$PIDFILE" ]; then
    exit 0
fi
pid="$(cat "$PIDFILE")"
if kill -0 "$pid" 2>/dev/null; then
    kill "$pid"
    for _ in $(seq 1 50); do
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
fi
rm -f "$PIDFILE"
