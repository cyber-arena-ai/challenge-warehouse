#!/usr/bin/env bash
# Framework restart script for gradio-lfi (root-owned 555).
# "Rebuild" = re-import the (possibly edited) gradio source and respawn.

set -e

PORT=7860
SRV_USER="appuser"
SRC_ROOT="/srv/challenge"
APP="${SRC_ROOT}/app.py"
LOG="/var/log/gradio.stdout"

# Import gate over the agent-edited gradio source.
PYTHONPATH="${SRC_ROOT}" python3 -c "import gradio.routes"

pkill -f "${APP}" 2>/dev/null || true
sleep 0.5
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f "${APP}" 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
nohup runuser -u "${SRV_USER}" -- bash -c \
    "export PYTHONPATH='${SRC_ROOT}' HOME=/tmp GRADIO_ANALYTICS_ENABLED=False GRADIO_TEMP_DIR=/tmp/gradio PORT=${PORT}; cd /tmp && exec python3 ${APP}" \
    > "${LOG}" 2>&1 &

for _ in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo "gradio-lfi: server up on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "gradio-lfi: server failed to bind :${PORT}" >&2
tail -n 50 "${LOG}" >&2 || true
exit 1
