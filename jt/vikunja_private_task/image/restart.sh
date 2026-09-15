#!/usr/bin/env bash
set -u

MODE="${1:-restart}"
ROOT=/srv/challenge/vikunja
PIDFILE=/run/vikunja.pid
LOG=/var/log/vikunja.log

if [ "$MODE" != initial ]; then
    cd "$ROOT/frontend" || exit 1
    COREPACK_ENABLE_NETWORK=0 npm_config_offline=true \
        pnpm run build || { echo "frontend build failed" >&2; exit 1; }
    cd "$ROOT" || exit 1
    GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
        go build -buildvcs=false -tags osusergo \
        -ldflags '-s -w -X code.vikunja.io/api/pkg/version.Version=v2.2.0 -X main.Tags=osusergo' \
        -o /arena/vikunja.new . || { echo "backend build failed" >&2; exit 1; }
    chown root:root /arena/vikunja.new
    chmod 0755 /arena/vikunja.new
    mv -f /arena/vikunja.new /arena/vikunja
fi

if [ -s "$PIDFILE" ]; then
    pid=$(cat "$PIDFILE" 2>/dev/null || true)
    [ -n "${pid:-}" ] && kill -TERM "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
        [ -z "${pid:-}" ] || ! kill -0 "$pid" 2>/dev/null && break
        sleep .2
    done
    [ -z "${pid:-}" ] || kill -KILL "$pid" 2>/dev/null || true
fi

set -a
. /arena/secrets/service.env
set +a
su-exec vikunja:vikunja /arena/vikunja web >>"$LOG" 2>&1 &
echo $! > "$PIDFILE"

for _ in $(seq 1 300); do
    if curl -fsS --max-time 2 http://127.0.0.1:3456/api/v1/info \
        | grep -q '"version":"v2.2.0"'; then
        echo "Vikunja ready (mode=$MODE)"
        exit 0
    fi
    sleep .2
done
echo "Vikunja failed to become ready" >&2
tail -20 "$LOG" >&2 2>/dev/null || true
exit 1
