#!/usr/bin/env bash
set -euo pipefail

SRC=/srv/challenge/opentsdb
PID=/run/opentsdb/tsdb.pid
LOG=/var/log/opentsdb/tsdb.log
PORT=4242
export JAVA_HOME=/opt/java/openjdk
export PATH="${JAVA_HOME}/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

if [ -f "${PID}" ]; then
    old_pid="$(cat "${PID}" 2>/dev/null || true)"
    if [ -n "${old_pid}" ]; then
        kill "${old_pid}" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "${old_pid}" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 "${old_pid}" 2>/dev/null || true
    fi
fi
pkill -f 'net.opentsdb.tools.TSDMain' 2>/dev/null || true

mkdir -p /run/opentsdb /var/lib/opentsdb/cache /var/log/opentsdb
chown -R opentsdb:opentsdb /var/lib/opentsdb /var/log/opentsdb /run/opentsdb

nohup /usr/bin/setsid /usr/sbin/runuser -u opentsdb -- bash -c \
    "cd /var/lib/opentsdb && exec '${SRC}/build/tsdb' tsd \
        --config=/etc/opentsdb/opentsdb.conf \
        --port=${PORT} \
        --staticroot='${SRC}/build/staticroot' \
        --cachedir=/var/lib/opentsdb/cache \
        --zkquorum=127.0.0.1" \
    </dev/null > "${LOG}" 2>&1 &
echo $! > "${PID}"

for _ in $(seq 1 60); do
    status="$(curl -sS --max-time 4 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:${PORT}/api/version" || true)"
    if [ "${status}" = "401" ]; then
        echo "OpenTSDB ready on :${PORT}"
        exit 0
    fi
    if ! kill -0 "$(cat "${PID}")" 2>/dev/null; then
        break
    fi
    sleep 1
done

echo "OpenTSDB failed to become ready" >&2
tail -n 80 "${LOG}" >&2 || true
exit 1
