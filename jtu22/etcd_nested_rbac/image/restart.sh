#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/etcd
readonly NEXT_DIR=/srv/etcd/build-next
readonly LIVE=/srv/etcd/bin/etcd
readonly PID=/srv/etcd/etcd.pid

rm -rf "$NEXT_DIR"
mkdir -p "$NEXT_DIR"
cd "$SRC"
export PATH="/usr/local/go/bin:/go/bin:${PATH}"
export GOPROXY=off GOSUMDB=off GOTOOLCHAIN=local BINDIR="$NEXT_DIR"
export GIT_CONFIG_COUNT=1
export GIT_CONFIG_KEY_0=safe.directory
export GIT_CONFIG_VALUE_0="$SRC"
./build
test -x "$NEXT_DIR/etcd"
echo "etcd-restart: compile ok"

if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
    old_pid="$(cat "$PID")"
    kill "$old_pid"
    for _ in $(seq 1 40); do
        kill -0 "$old_pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$old_pid" 2>/dev/null; then
        kill -KILL "$old_pid"
        for _ in $(seq 1 20); do
            kill -0 "$old_pid" 2>/dev/null || break
            sleep 0.1
        done
    fi
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "etcd-restart: old process did not exit" >&2
        exit 1
    fi
fi
install -o root -g root -m 0755 "$NEXT_DIR/etcd" "$LIVE"
rm -f "$PID"
/arena/start.sh
echo "etcd-restart: process started"
echo "etcd-restart: service ready"
