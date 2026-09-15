#!/usr/bin/env bash
set -eu

SOURCE=/srv/challenge/airflow/source
PGID_FILE=/run/airflow-api.pgid
LOG=/var/lib/airflow/api-server.log
HEALTH=http://127.0.0.1:8080/api/v2/monitor/health

port_open() {
    (exec 3<>/dev/tcp/127.0.0.1/8080) >/dev/null 2>&1
}

stop_airflow() {
    pkill -TERM -u airflow 2>/dev/null || true
    for _ in $(seq 1 20); do
        if ! port_open; then
            break
        fi
        sleep 0.25
    done
    pkill -KILL -u airflow 2>/dev/null || true
    for _ in $(seq 1 10); do
        if ! port_open; then
            return 0
        fi
        pkill -KILL -u airflow 2>/dev/null || true
        sleep 0.2
    done
    return 1
}

stop_on_signal() {
    trap - HUP INT TERM
    stop_airflow || true
    exit 1
}

trap stop_on_signal HUP INT TERM

if ! stop_airflow; then
    echo "old Airflow API server still owns port 8080" >&2
    exit 1
fi

timeout --signal=TERM --kill-after=5 20 \
    runuser -u airflow -- python - "$SOURCE" <<'PY'
import pathlib
import sys

roots = (
    pathlib.Path(sys.argv[1]) / "airflow-core" / "src",
    pathlib.Path(sys.argv[1]) / "task-sdk" / "src",
    pathlib.Path(sys.argv[1]) / "providers" / "fab" / "src",
)
for root in roots:
    for path in root.rglob("*.py"):
        compile(path.read_bytes(), str(path), "exec")
PY

install -o airflow -g root -m 0640 /dev/null "$PGID_FILE"
install -o airflow -g root -m 0640 /dev/null "$LOG"
runuser -u airflow -- bash -c \
    "setsid /arena/start.sh >> '$LOG' 2>&1 & echo \$! > '$PGID_FILE'"

# Non-initial failure, including both listener-close passes, stays below SSH's
# 120-second command deadline. Initial boot has no enclosing SSH command.
ready_timeout=50
if [ "${1:-}" = initial ]; then
    ready_timeout=240
fi
ready_deadline=$((SECONDS + ready_timeout))
while [ "$SECONDS" -lt "$ready_deadline" ]; do
    if curl -fsS --max-time 2 "$HEALTH" >/dev/null 2>&1; then
        echo "Airflow source reload complete"
        exit 0
    fi
    sleep 2
done
if ! stop_airflow; then
    echo "failed Airflow generation still owns port 8080" >&2
fi
tail -n 30 "$LOG" >&2 || true
echo "Airflow API server did not become healthy" >&2
exit 1
