#!/usr/bin/env bash
set -euo pipefail

readonly PIDFILE=/run/gogs.pid
readonly LOG=/srv/gogs-data/log/gogs.log
readonly CONFIG=/srv/gogs-data/custom/conf/app.ini

if [ -s "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
    echo "gogs-start: process is already running" >&2
    exit 1
fi
rm -f "$PIDFILE"
mkdir -p "$(dirname "$LOG")"
chown -R arena_agent:arena_agent /srv/gogs-data

su-exec arena_agent env \
  HOME=/home/arena_agent \
  GOGS_CUSTOM=/srv/gogs-data/custom \
  /srv/gogs/bin/gogs web --config "$CONFIG" >>"$LOG" 2>&1 &
pid=$!
echo "$pid" > "$PIDFILE"

for _ in $(seq 1 90); do
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "gogs-start: process exited during readiness" >&2
        tail -n 40 "$LOG" >&2 || true
        exit 1
    fi
    if curl -fsS http://127.0.0.1:3000/healthcheck >/dev/null; then
        exit 0
    fi
    sleep 1
done
echo "gogs-start: /healthcheck did not become ready" >&2
tail -n 40 "$LOG" >&2 || true
exit 1
