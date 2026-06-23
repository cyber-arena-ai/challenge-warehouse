#!/usr/bin/env bash
# Framework restart script for aiohttp-lfi (root-owned 555).
# No compile step — "rebuild" = re-parse the agent-edited app and relaunch.

set -e

PORT=8080
SRV_USER="appuser"
APP="/srv/challenge/server.py"
LOG="/var/log/aiohttp.stdout"

# Syntax gate: fail fast if the agent's edit broke Python.
python3 -c "import ast; ast.parse(open('${APP}').read())"

pkill -f "${APP}" 2>/dev/null || true
sleep 0.5

mkdir -p "$(dirname "${LOG}")"
nohup runuser -u "${SRV_USER}" -- bash -c \
    "export PORT=${PORT} HOME=/tmp; exec python3 ${APP}" \
    > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo "aiohttp-lfi: server up on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "aiohttp-lfi: server failed to bind :${PORT}" >&2
tail -n 40 "${LOG}" >&2 || true
exit 1
