#!/usr/bin/env bash

set -euo pipefail

PIDFILE=/run/marimo/service.pid
GENERATION_FILE=/run/marimo/service.generation

pkill -TERM -u marimo 2>/dev/null || true
for _ in $(seq 1 50); do
    if ! pgrep -u marimo >/dev/null 2>&1; then
        rm -f "${PIDFILE}" "${GENERATION_FILE}"
        exit 0
    fi
    sleep 0.1
done
pkill -KILL -u marimo 2>/dev/null || true
for _ in $(seq 1 20); do
    if ! pgrep -u marimo >/dev/null 2>&1; then
        rm -f "${PIDFILE}" "${GENERATION_FILE}"
        exit 0
    fi
    sleep 0.1
done
echo "marimo processes survived SIGKILL" >&2
exit 1
