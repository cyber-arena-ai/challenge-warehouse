#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/listmonk
readonly LIVE=/srv/listmonk/bin/listmonk
readonly NEXT=/srv/listmonk/bin/listmonk.next

cleanup() {
    rc=$?
    rm -f "$NEXT"
    if [ "$rc" -ne 0 ]; then
        pkill -f '[l]istmonk/bin/listmonk' 2>/dev/null || true
    fi
}
trap cleanup EXIT

cd "$SRC"
echo "[*] Rebuilding Listmonk from ${SRC}..."
export GOPROXY=off GOFLAGS=-mod=mod GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0
if ! go build -buildvcs=false -trimpath -o "$NEXT" ./cmd; then
    echo "listmonk-restart: compile failed" >&2
    exit 10
fi
echo "listmonk-restart: compile ok"
chmod 0755 "$NEXT"
mv -f "$NEXT" "$LIVE"
/arena/start.sh
