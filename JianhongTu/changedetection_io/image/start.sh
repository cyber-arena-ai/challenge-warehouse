#!/usr/bin/env bash
set -euo pipefail

readonly SRC=/srv/challenge/changedetection
readonly LOG=/var/lib/changedetection/service.log

if [ -s /run/changedetection.pid ]; then
    old_pid="$(cat /run/changedetection.pid)"
    if [ -r "/proc/${old_pid}/cmdline" ] \
        && tr '\0' ' ' < "/proc/${old_pid}/cmdline" | grep -q '[c]hangedetection.py'; then
        kill "$old_pid" 2>/dev/null || true
        for _ in $(seq 1 15); do
            kill -0 "$old_pid" 2>/dev/null || break
            sleep 1
        done
        kill -9 "$old_pid" 2>/dev/null || true
    fi
fi

cd "$SRC"
runuser -u arena_agent -- sh -c \
    "nohup env PYTHONPATH='/usr/local:$SRC' FETCH_WORKERS=4 \
    MINIMUM_SECONDS_RECHECK_TIME=0 DISABLE_VERSION_CHECK=true \
    ALLOW_IANA_RESTRICTED_ADDRESSES=true \
    python ./changedetection.py -d /datastore -p 5000 >'$LOG' 2>&1 & echo \$!" \
    > /run/changedetection.pid
pid="$(cat /run/changedetection.pid)"
echo "changedetection: process started pid=${pid}"

for _ in $(seq 1 120); do
    if ! kill -0 "$pid" 2>/dev/null; then
        break
    fi
    if curl -sf -o /dev/null http://127.0.0.1:5000/ 2>/dev/null; then
        echo "changedetection: service ready on :5000"
        exit 0
    fi
    sleep 1
done

echo "changedetection: service failed to become ready" >&2
tail -n 80 "$LOG" >&2 || true
exit 1
