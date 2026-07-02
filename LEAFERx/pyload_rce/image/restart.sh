#!/usr/bin/env bash
# Framework restart script for pyload-rce (root-owned 555).
# "Rebuild" = re-import the (possibly edited) pyload source and respawn.

set -e

PORT=8000
SRV_USER="pyload"
SRC_ROOT="/srv/challenge"
DATA="/srv/pyload"
LOG="/var/log/pyload.stdout"

# Import gate over the agent-edited handler.
PYTHONPATH="${SRC_ROOT}" python3 -c "import pyload.webui.app.blueprints.cnl_blueprint"

pkill -f "pyload" 2>/dev/null || true
sleep 1
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'pyload' 2>/dev/null || true

chown -R "${SRV_USER}:${SRV_USER}" "${DATA}"
mkdir -p /tmp/pyLoad && chown "${SRV_USER}:${SRV_USER}" /tmp/pyLoad
mkdir -p "$(dirname "${LOG}")"
nohup runuser -u "${SRV_USER}" -- bash -c \
    "export PYTHONPATH='${SRC_ROOT}' HOME=/tmp; exec pyload --userdir ${DATA}/u --storagedir ${DATA}/s --tempdir ${DATA}/t --pidfile ${DATA}/pyload.pid" \
    > "${LOG}" 2>&1 &

for _ in $(seq 1 45); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo "pyload-rce: server up on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "pyload-rce: server failed to bind :${PORT}" >&2
tail -n 50 "${LOG}" >&2 || true
exit 1
