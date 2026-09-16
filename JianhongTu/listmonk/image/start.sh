#!/usr/bin/env bash
set -euo pipefail

readonly PORT=9000
readonly SRC=/srv/challenge/listmonk
readonly BIN=/srv/listmonk/bin/listmonk
readonly CONFIG=/etc/listmonk/config.toml
readonly LOG=/srv/listmonk/listmonk.log

pkill -f '[l]istmonk/bin/listmonk' 2>/dev/null || true
for _ in $(seq 1 15); do
    pgrep -f '[l]istmonk/bin/listmonk' >/dev/null || break
    sleep 1
done
pkill -9 -f '[l]istmonk/bin/listmonk' 2>/dev/null || true

cd "$SRC"
nohup "$BIN" --config "$CONFIG" >"$LOG" 2>&1 &
pid=$!
echo "listmonk: process started pid=${pid}"
for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    if curl -sf -o /dev/null "http://127.0.0.1:${PORT}/health" 2>/dev/null; then
        echo "listmonk: service ready on :${PORT}"
        exit 0
    fi
    sleep 1
done
echo "listmonk: service failed to become ready" >&2
tail -n 80 "$LOG" >&2 || true
exit 1
