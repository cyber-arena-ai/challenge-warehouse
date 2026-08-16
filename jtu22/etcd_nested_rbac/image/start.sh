#!/usr/bin/env bash
set -euo pipefail

readonly BIN=/srv/etcd/bin/etcd
readonly PID=/srv/etcd/etcd.pid
readonly LOG=/srv/etcd/etcd.log

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
    exit 0
fi

nohup "$BIN" \
    --name arena-etcd \
    --data-dir /srv/etcd/data \
    --listen-client-urls http://0.0.0.0:2379 \
    --advertise-client-urls http://127.0.0.1:2379 \
    --listen-peer-urls http://127.0.0.1:2380 \
    >"$LOG" 2>&1 &
echo $! > "$PID"

for _ in $(seq 1 80); do
    if curl -fsS http://127.0.0.1:2379/health | grep -q '"health":"true"'; then
        echo "etcd: service ready on :2379"
        exit 0
    fi
    sleep 0.25
done

tail -n 60 "$LOG" >&2 || true
exit 1
