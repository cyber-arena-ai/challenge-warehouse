#!/usr/bin/env bash
set -euo pipefail

readonly SOURCE=/srv/challenge/gogs
readonly LIVE=/srv/gogs/bin/gogs
readonly NEXT=/srv/gogs/bin/gogs.next

cleanup() {
    rm -f "$NEXT"
}
trap cleanup EXIT

export PATH="/usr/local/go/bin:${PATH}"
export GOPATH=/go GOCACHE=/root/.cache/go-build
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local GOFLAGS=-mod=mod

cd "$SOURCE"
if ! go build -buildvcs=false -trimpath -tags "cert pam prod" \
    -ldflags "-X 'gogs.io/gogs/internal/conf.BuildCommit=${GOGS_COMMIT}'" \
    -o "$NEXT" .; then
    echo "gogs-restart: compile failed" >&2
    exit 10
fi
chmod 0755 "$NEXT"
echo GOGS_RESTART_COMPILE_OK

/arena/stop.sh
mv -f "$NEXT" "$LIVE"
if ! /arena/start.sh; then
    echo "gogs-restart: spawn/readiness failed" >&2
    exit 20
fi
echo GOGS_RESTART_SPAWN_OK
echo GOGS_RESTART_READY_OK
