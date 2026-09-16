#!/usr/bin/env bash
set -eu

MODE="${1:-restart}"
ROOT=/srv/challenge/vikunja
PIDFILE=/run/vikunja.pid
LOG=/var/log/vikunja.log

service_running() {
    ps -u vikunja -o stat= -o args= 2>/dev/null \
        | grep -Eq '^[[:space:]]*[^Z[:space:]][^[:space:]]*[[:space:]]+/arena/vikunja web$'
}

stop_service() {
    if [ -s "$PIDFILE" ]; then
        pid=$(cat "$PIDFILE" 2>/dev/null || true)
        [ -n "${pid:-}" ] && kill -TERM "$pid" 2>/dev/null || true
    fi
    pkill -TERM -u vikunja -f '^/arena/vikunja web$' 2>/dev/null || true
    for _ in $(seq 1 20); do
        service_running || break
        sleep .2
    done
    if service_running; then
        pkill -KILL -u vikunja -f '^/arena/vikunja web$' 2>/dev/null || true
        for _ in $(seq 1 10); do
            service_running || break
            sleep .2
        done
    fi
    if service_running; then
        echo "Vikunja processes survived shutdown" >&2
        return 1
    fi
    rm -f "$PIDFILE"
}

if [ "$MODE" != initial ]; then
    # A failed defender build must not leave the previous generation serving.
    stop_service
    rm -f /arena/vikunja.new
    cd "$ROOT/frontend"
    COREPACK_ENABLE_NETWORK=0 npm_config_offline=true \
        pnpm run build || { echo "frontend build failed" >&2; exit 1; }
    cd "$ROOT"
    GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
        go build -buildvcs=false -tags osusergo \
        -ldflags '-s -w -X code.vikunja.io/api/pkg/version.Version=v2.2.0 -X main.Tags=osusergo' \
        -o /arena/vikunja.new . || { echo "backend build failed" >&2; exit 1; }
    chown root:root /arena/vikunja.new
    chmod 0755 /arena/vikunja.new
    mv -f /arena/vikunja.new /arena/vikunja
else
    stop_service
fi

set -a
. /arena/secrets/service.env
set +a
su-exec vikunja:vikunja /arena/vikunja web >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 300); do
    if wget -q -T 2 -O - http://127.0.0.1:3456/api/v1/info \
        | grep -q '"version":"v2.2.0"'; then
        echo "Vikunja ready (mode=$MODE)"
        exit 0
    fi
    sleep .2
done
echo "Vikunja failed to become ready" >&2
tail -20 "$LOG" >&2 2>/dev/null || true
stop_service
exit 1
