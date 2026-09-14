#!/usr/bin/env bash
set -euo pipefail

SRC=/srv/challenge
APP=${SRC}/app.py
LOG=/var/log/gradio-service.log
PID=/run/gradio-service.pid

/arena/stop.sh
trap '/arena/stop.sh' ERR

PYTHONPATH=${SRC} python3 -m compileall -q "${SRC}/gradio" "${APP}"
PYTHONPATH=${SRC} python3 -c 'import gradio.routes'
echo GRADIO_RESTART_COMPILE_OK

mkdir -p /tmp/gradio /tmp/matplotlib
chown -R appuser:appuser /tmp/gradio /tmp/matplotlib

runuser -u appuser -- bash -c \
    "export PYTHONPATH='${SRC}' HOME=/tmp MPLCONFIGDIR=/tmp/matplotlib GRADIO_ANALYTICS_ENABLED=False PORT=7860; cd /tmp; exec python3 '${APP}'" \
    >"${LOG}" 2>&1 &
echo "$!" >"${PID}"
echo GRADIO_RESTART_SPAWN_OK

for _ in $(seq 1 "${GRADIO_READY_ATTEMPTS:-90}"); do
    if python3 -c "import urllib.request; r=urllib.request.urlopen('http://127.0.0.1:7860/', timeout=2); raise SystemExit(0 if r.status == 200 else 1)"; then
        echo GRADIO_RESTART_READY_OK
        trap - ERR
        exit 0
    fi
    sleep 1
done

tail -n 80 "${LOG}" >&2 || true
/arena/stop.sh
exit 1
