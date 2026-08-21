#!/usr/bin/env bash
set -euo pipefail

pid_file=/run/geoserver/service.pid
log_file=/var/log/geoserver-arena.log

start_service() {
    if test -s "$pid_file" && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
        return 0
    fi
    rm -f "$pid_file"
    touch "$log_file"
    chown geoserver:geoserver "$log_file"
    setsid setpriv --reuid=1000 --regid=1000 --clear-groups \
        env HOME=/opt/geoserver_home GEOSERVER_DATA_DIR=/opt/geoserver_data \
        /opt/startup.sh >>"$log_file" 2>&1 &
    echo "$!" > "$pid_file"
}

stop_service() {
    if ! test -s "$pid_file"; then
        return 0
    fi
    pid=$(cat "$pid_file")
    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 300); do
            kill -0 "$pid" 2>/dev/null || break
            sleep .1
        done
        if kill -0 "$pid" 2>/dev/null; then
            kill -KILL -- "-$pid" 2>/dev/null || kill -KILL "$pid" 2>/dev/null || true
        fi
    fi
    rm -f "$pid_file"
}

await_service() {
    for _ in $(seq 1 1500); do
        if curl -fsS --max-time 2 \
            'http://127.0.0.1:8080/geoserver/wfs?service=WFS&version=2.0.0&request=GetCapabilities' \
            -o /dev/null; then
            return 0
        fi
        sleep .1
    done
    tail -n 80 "$log_file" >&2 || true
    return 1
}

case "${1:-}" in
    start) start_service ;;
    stop) stop_service ;;
    restart) stop_service; start_service ;;
    ready) await_service ;;
    status)
        test -s "$pid_file" && kill -0 "$(cat "$pid_file")" 2>/dev/null
        ;;
    *) exit 2 ;;
esac
