#!/usr/bin/env bash
# Framework restart script for faust-jokes. Root-owned 555.
#
# Interpreted service: byte-compile the edited entrypoint (surfaces syntax
# errors as a failed restart per SOP §7), respawn gunicorn as the
# unprivileged service user, then self-gate on a real HTTP request.
set -e

SRC="/srv/challenge/jokes/app"
LOG="/var/log/jokes.log"
PORT=5000

/opt/venv/bin/python -m py_compile "${SRC}/main.py"

pkill -f 'gunicorn' || true
# Drain the old worker fully before respawning, so the health gate below
# can't be satisfied by the previous (possibly broken) code still serving.
for _ in $(seq 1 20); do
    pgrep -f gunicorn >/dev/null || break
    sleep 0.2
done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'gunicorn' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
# Single worker: per-team vulbox, SQLite serializes cleanly (matches upstream).
runuser -u arena_agent -- /opt/venv/bin/gunicorn \
    --chdir "${SRC}" --bind "0.0.0.0:${PORT}" --workers 1 \
    --capture-output --log-level info main:service > "${LOG}" 2>&1 &

# Health gate: the login page must render (a DB-backed Flask route), so
# restart.sh returns only when the app is actually serving.
for _ in $(seq 1 20); do
    if /opt/venv/bin/python - "${PORT}" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=2).read()
except Exception:
    sys.exit(1)
sys.exit(0 if b"password" in body.lower() else 1)
PY
    then
        echo "jokes restarted, pid=$(pgrep -f gunicorn | head -1)"
        exit 0
    fi
    sleep 1
done

echo "jokes failed to become healthy after restart" >&2
exit 1
