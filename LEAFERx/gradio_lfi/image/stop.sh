#!/usr/bin/env bash
set -euo pipefail

pkill -TERM -f '/srv/challenge/app.py' 2>/dev/null || true
for _ in $(seq 1 20); do
    if ! pgrep -f '/srv/challenge/app.py' >/dev/null; then
        rm -f /run/gradio-service.pid
        exit 0
    fi
    sleep 0.25
done
pkill -KILL -f '/srv/challenge/app.py' 2>/dev/null || true
rm -f /run/gradio-service.pid
