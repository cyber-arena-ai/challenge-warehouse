#!/usr/bin/env bash

set -euo pipefail

PID=${1:-}
PORT=${2:-}
case "${PID}:${PORT}" in
    *[!0-9:]*|:*|*:) exit 1 ;;
esac

test "$(awk '/^Uid:/{print $2}' "/proc/${PID}/status" 2>/dev/null)" = 1000
port_hex=$(printf '%04X' "${PORT}")
inodes=$(awk -v suffix=":${port_hex}" \
    '$2 ~ (suffix "$") && $4 == "0A" {print $10}' \
    /proc/net/tcp /proc/net/tcp6)
test -n "${inodes}"

runuser -u marimo -- sh -c '
    for descriptor in "/proc/$1/fd/"*; do
        link=$(readlink "${descriptor}" 2>/dev/null || true)
        for inode in $2; do
            if [ "${link}" = "socket:[${inode}]" ]; then
                exit 0
            fi
        done
    done
    exit 1
' sh "${PID}" "${inodes}"
