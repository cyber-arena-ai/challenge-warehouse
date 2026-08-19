#!/usr/bin/env bash
# Framework restart script for listmonk.
#
# Invoked by the MCP `restart_service` tool via docker exec (root). Rebuilds the
# defender's edited Go source into a new binary, atomically swaps it in, and
# relaunches the backend. `set -e` aborts on a failed `go build` so a broken
# edit is never deployed and the compiler error surfaces in the CheckResult.
# PostgreSQL keeps running untouched, so all application and flag state persists.
set -euo pipefail

readonly SRC=/srv/challenge/listmonk
readonly LIVE=/srv/listmonk/bin/listmonk
readonly NEXT=/srv/listmonk/bin/listmonk.next

stop_backend() {
    pkill -f '[l]istmonk/bin/listmonk' 2>/dev/null || true
    for _ in $(seq 1 15); do
        pgrep -f '[l]istmonk/bin/listmonk' >/dev/null || return 0
        sleep 1
    done
    pkill -9 -f '[l]istmonk/bin/listmonk' 2>/dev/null || true
}

cleanup() {
    rc=$?
    rm -f "$NEXT"
    if [ "$rc" -ne 0 ]; then
        stop_backend
        echo "listmonk-restart: prior backend stopped after failed deployment" >&2
    fi
}
trap cleanup EXIT

cd "$SRC"
echo "[*] Rebuilding listmonk backend from ${SRC}..."
# The defender's box is offline; build from the baked module cache only.
export GOPROXY=off GOFLAGS=-mod=mod GOSUMDB=off GOTOOLCHAIN=local
if ! go build -buildvcs=false -o "$NEXT" ./cmd; then
    echo "listmonk-restart: compile failed" >&2
    exit 10
fi
echo "listmonk-restart: compile ok"

if ! chmod 0755 "$NEXT" || ! mv -f "$NEXT" "$LIVE"; then
    echo "listmonk-restart: binary deployment failed" >&2
    exit 20
fi

echo "[*] Relaunching backend..."
if ! /arena/start.sh; then
    echo "listmonk-restart: launch/readiness failed" >&2
    exit 30
fi
