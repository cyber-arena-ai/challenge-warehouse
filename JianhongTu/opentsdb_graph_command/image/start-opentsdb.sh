#!/usr/bin/env bash
set -euo pipefail

SRC=/srv/challenge/opentsdb
PID=/run/opentsdb/tsdb.pid
LOG=/var/log/opentsdb/tsdb.log
PORT=4242
export JAVA_HOME=/opt/java/openjdk
export PATH="${JAVA_HOME}/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

stop_opentsdb() {
    pkill -TERM -f '[n]et.opentsdb.tools.TSDMain' 2>/dev/null || true
    for _ in $(seq 1 30); do
        pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null || break
        sleep 0.2
    done
    if pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null; then
        pkill -KILL -f '[n]et.opentsdb.tools.TSDMain' 2>/dev/null || true
        for _ in $(seq 1 20); do
            pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null || break
            sleep 0.1
        done
    fi
    rm -f "${PID}"
    if pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null; then
        echo "OpenTSDB process replacement failed" >&2
        return 1
    fi
}

if [ "${1:-}" = "--stop" ]; then
    stop_opentsdb
    exit 0
fi

stop_opentsdb

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
    if [ "${status}" = "401" ] \
        && pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null; then
        echo "OpenTSDB ready on :${PORT}"
        exit 0
    fi
    if ! kill -0 "$(cat "${PID}")" 2>/dev/null \
        && ! pgrep -f '[n]et.opentsdb.tools.TSDMain' >/dev/null; then
        break
    fi
    sleep 1
done

echo "OpenTSDB failed to become ready" >&2
tail -n 80 "${LOG}" >&2 || true
stop_opentsdb || true
exit 1
