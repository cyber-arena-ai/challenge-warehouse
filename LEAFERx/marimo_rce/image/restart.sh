#!/usr/bin/env bash
# Framework restart script for marimo-rce (root-owned 555).
# "Rebuild" = re-import the (possibly edited) terminal handler and respawn
# `marimo edit` (EDIT mode is required for the /terminal/ws endpoint).

set -e

PORT=5000
SRV_USER="marimo"
SRC_ROOT="/srv/challenge"
NB="/srv/marimo/nb.py"
LOG="/var/log/marimo.stdout"
TOKEN="arena"   # cells/editor require this; /terminal/ws is the unauth hole

# Import gate over the agent-edited terminal handler. On the CVE pin this
# imports the terminal module (so a broken agent edit surfaces as a SyntaxError
# here). On patched-upstream builds the module may have moved, so fall back to
# importing the top-level package — the gate still catches a broken install.
PYTHONPATH="${SRC_ROOT}" python3 -c "import importlib
try:
    importlib.import_module('marimo._server.api.endpoints.terminal')
except ModuleNotFoundError:
    import marimo"

pkill -f "marimo edit" 2>/dev/null || true
sleep 0.5
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'marimo edit' 2>/dev/null || true

chown -R "${SRV_USER}:${SRV_USER}" /srv/marimo
mkdir -p "$(dirname "${LOG}")"
nohup runuser -u "${SRV_USER}" -- bash -c \
    "export PYTHONPATH='${SRC_ROOT}' HOME=/srv/marimo; cd /srv/marimo && exec marimo edit '${NB}' --headless --host 0.0.0.0 --port ${PORT} --token-password '${TOKEN}'" \
    > "${LOG}" 2>&1 &

for _ in $(seq 1 40); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo "marimo-rce: server up on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "marimo-rce: server failed to bind :${PORT}" >&2
tail -n 50 "${LOG}" >&2 || true
exit 1
