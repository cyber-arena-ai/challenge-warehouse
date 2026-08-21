#!/usr/bin/env bash
set -eu

ROOT=/srv/challenge/caddy
RUNTIME=/srv/runtime/caddy
PIDFILE=/run/caddy/caddy.pid
LOG=/tmp/caddy.log

cd "$ROOT"
started=$(date +%s)
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
    go build -buildvcs=false -mod=readonly -trimpath \
    -ldflags '-X github.com/caddyserver/caddy/v2.CustomVersion=v2.11.1' \
    -o "$RUNTIME.new" ./cmd/caddy
"$RUNTIME.new" validate --config /etc/caddy/Caddyfile --adapter caddyfile
chown root:root "$RUNTIME.new"
chmod 0755 "$RUNTIME.new"

old_pid=$(cat "$PIDFILE" 2>/dev/null || true)
if [ -n "$old_pid" ]; then
    kill -TERM "$old_pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
        ! kill -0 "$old_pid" 2>/dev/null && break
        sleep .1
    done
    kill -KILL "$old_pid" 2>/dev/null || true
fi
mv -f "$RUNTIME.new" "$RUNTIME"

su-exec service:service env \
    XDG_CONFIG_HOME=/tmp/caddy-config XDG_DATA_HOME=/tmp/caddy-data \
    "$RUNTIME" run --config /etc/caddy/Caddyfile --adapter caddyfile \
    >>"$LOG" 2>&1 &
new_pid=$!
printf '%s\n' "$new_pid" > "$PIDFILE"

for _ in $(seq 1 300); do
    status=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:8080/status.php 2>/dev/null || true)
    if kill -0 "$new_pid" 2>/dev/null && [ "$status" = 401 ]; then
        uid=$(awk '/^Uid:/{print $2}' "/proc/$new_pid/status")
        [ "$uid" = 1000 ]
        /arena/facility.py status >/dev/null
        printf 'READY seconds=%s pid=%s uid=%s\n' \
            "$(($(date +%s) - started))" "$new_pid" "$uid"
        exit 0
    fi
    sleep .1
done
echo "Caddy failed to become ready" >&2
tail -30 "$LOG" >&2 2>/dev/null || true
exit 1
