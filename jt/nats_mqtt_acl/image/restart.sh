#!/usr/bin/env bash
set -u

MODE="${1:-restart}"
ROOT=/srv/challenge/nats-server
RUNTIME=/srv/runtime/nats-server
PIDFILE=/run/nats-server.pid
LOG=/var/log/nats-server.log
COMMIT=0f6c831ec1df25bc3dc81d25faae0ed0bac15a96

if [ "$MODE" != initial ]; then
    cd "$ROOT" || exit 1
    GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=0 \
        go build -buildvcs=false -mod=readonly -trimpath \
        -ldflags "-X github.com/nats-io/nats-server/v2/server.gitCommit=$COMMIT -X github.com/nats-io/nats-server/v2/server.serverVersion=v2.12.5" \
        -o "$RUNTIME.new" . || { echo "NATS build failed" >&2; exit 1; }
    chown root:root "$RUNTIME.new"
    chmod 0755 "$RUNTIME.new"
    mv -f "$RUNTIME.new" "$RUNTIME"
fi

if [ -s "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    [ -n "${pid:-}" ] && kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do
        [ -z "${pid:-}" ] || ! kill -0 "$pid" 2>/dev/null && break
        sleep .1
    done
    [ -z "${pid:-}" ] || kill -KILL "$pid" 2>/dev/null || true
fi

su-exec nats:nats "$RUNTIME" -c /etc/nats/nats.conf >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 300); do
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null \
       && (exec 3<>/dev/tcp/127.0.0.1/1883) 2>/dev/null \
       && (exec 3<>/dev/tcp/127.0.0.1/4222) 2>/dev/null; then
        uid=$(awk '/^Uid:/{print $2}' "/proc/$pid/status" 2>/dev/null || true)
        [ "$uid" = 1000 ] || { echo "NATS did not drop to UID 1000" >&2; exit 1; }
        echo "NATS ready (mode=$MODE)"
        exit 0
    fi
    sleep .1
done
echo "NATS failed to become ready" >&2
tail -30 "$LOG" >&2 2>/dev/null || true
exit 1
