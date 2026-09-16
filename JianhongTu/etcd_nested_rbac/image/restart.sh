#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/etcd
readonly NEXT_DIR=/srv/etcd/build-next
readonly LIVE=/srv/etcd/bin/etcd
readonly PID=/srv/etcd/etcd.pid

cleanup() {
    rc=$?
    if [ "$rc" -ne 0 ]; then
        rm -rf "$NEXT_DIR"
    fi
}
trap cleanup EXIT

rm -rf "$NEXT_DIR"
mkdir -p "$NEXT_DIR"
cd "$SRC"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local CGO_ENABLED=0
export BINDIR="$NEXT_DIR"
if ! ./build; then
    echo "etcd-restart: compile failed" >&2
    exit 10
fi
test -x "$NEXT_DIR/etcd"
echo "etcd-restart: compile ok"

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
    old_pid="$(cat "$PID")"
    kill "$old_pid"
    for _ in $(seq 1 60); do
        kill -0 "$old_pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "etcd-restart: old process did not exit" >&2
        exit 11
    fi
fi

install -o root -g root -m 0755 "$NEXT_DIR/etcd" "$LIVE"
rm -rf "$NEXT_DIR"
rm -f "$PID"
/arena/start.sh
echo "etcd-restart: process started"
echo "etcd-restart: service ready"
