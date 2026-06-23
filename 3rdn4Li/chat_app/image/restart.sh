#!/usr/bin/env bash
# Framework restart script for faust-chat-app.
#
# Invoked by the MCP `restart_service` tool via docker exec (root).
# Mode 555, root-owned — the agent can read + execute but not modify.
# The only path from an agent edit to the running service is this script.
#
# The service is interpreted (Flask/gunicorn), so "rebuild" = byte-compile
# the edited source (to surface syntax errors as a failed restart, per
# SOP §7) then respawn gunicorn as the unprivileged service user.

set -e

SRC="/srv/challenge/chat-app/app"
LOG="/var/log/chatapp.log"
PORT=5000

# Compile-check: a broken edit fails the restart here (set -e), mirroring
# a compiled challenge's build failure.
/opt/venv/bin/python -m py_compile "${SRC}/main.py"

pkill -f 'gunicorn' || true
# Drain the old worker fully before respawning, so the health gate below
# can't be satisfied by the previous (possibly broken) code still serving.
for _ in $(seq 1 20); do
    pgrep -f gunicorn >/dev/null || break
    sleep 0.2
done

mkdir -p "$(dirname "${LOG}")"
# Single worker: a per-team vulbox is low-traffic and the SQLite backend
# serializes cleanly under one worker (matches upstream's default).
runuser -u arena_agent -- /opt/venv/bin/gunicorn \
    --chdir "${SRC}" --bind "0.0.0.0:${PORT}" --workers 1 \
    --capture-output --log-level info main:app > "${LOG}" 2>&1 &

# Post-restart health gate: the new instance must actually SERVE — and its
# DB must be warm — before we call the restart a success. We exercise a
# real DB write (a throwaway /register) rather than the static index banner,
# so restart.sh returns only when the service is gameplay-ready (the SQLite
# create_all() on a fresh worker lags the port opening). Catches edits that
# compile but break at import/runtime, so RestartHandler's smoke leaf and
# the post-restart health poll are meaningful.
for _ in $(seq 1 20); do
    if /opt/venv/bin/python - "${PORT}" <<'PY'
import sys, json, secrets, urllib.request
port = int(sys.argv[1])
body = json.dumps({"name": "ready_" + secrets.token_hex(8), "password": "x"}).encode()
req = urllib.request.Request(f"http://127.0.0.1:{port}/register", data=body,
                             headers={"Content-Type": "application/json"})
try:
    resp = urllib.request.urlopen(req, timeout=2).read()
except Exception:
    sys.exit(1)
sys.exit(0 if b"session" in resp else 1)
PY
    then
        echo "chat-app restarted, pid=$(pgrep -f gunicorn | head -1)"
        exit 0
    fi
    sleep 1
done

echo "chat-app failed to become healthy after restart" >&2
exit 1
