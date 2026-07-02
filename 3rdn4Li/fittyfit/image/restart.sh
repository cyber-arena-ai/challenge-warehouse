#!/usr/bin/env bash
# Framework restart script for faust-fittyfit. Root-owned 555.
set -e

SRC="/srv/challenge/fittyfit/app"
LOG="/var/log/fittyfit.log"
PORT=5001

/opt/venv/bin/python -m py_compile "${SRC}/app.py"

pkill -f 'gunicorn' || true
for _ in $(seq 1 20); do
    pgrep -f gunicorn >/dev/null || break
    sleep 0.2
done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'gunicorn' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
runuser -u arena_agent -- /opt/venv/bin/gunicorn \
    --chdir "${SRC}" --bind "0.0.0.0:${PORT}" --workers 1 \
    --capture-output --log-level info app:app > "${LOG}" 2>&1 &

# Health gate: index page must render.
for _ in $(seq 1 20); do
    if /opt/venv/bin/python - "${PORT}" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read()
except Exception:
    sys.exit(1)
sys.exit(0 if b"Fitty" in body else 1)
PY
    then
        echo "fittyfit restarted, pid=$(pgrep -f gunicorn | head -1)"
        exit 0
    fi
    sleep 1
done
echo "fittyfit failed to become healthy after restart" >&2
exit 1
