#!/usr/bin/env bash
# Rebuild = py_compile the edited Flask source (a broken edit fails the restart,
# SOP §7) and respawn the gunicorn daemon as the service user. Runs as root
# (privileged docker exec), so it can write logs and chown the data dir.
set -e
SRC="/srv/challenge/deutsches-flugzeug/app"
VENV="${SRC}/venv"
LOG="/var/log/deutsches-flugzeug.log"
PORT=5000

# Compile gate: any Python syntax error in the app fails here and fails the
# restart. Compile the whole package tree.
"${VENV}/bin/python" -m py_compile \
    "${SRC}/wsgi.py" \
    "${SRC}/dieAnwendung/__init__.py" \
    "${SRC}/dieAnwendung/dieRouten.py" \
    "${SRC}/dieAnwendung/auth.py" \
    "${SRC}/dieAnwendung/db.py" \
    "${SRC}/dieAnwendung/iata.py"

# Ensure the runtime data dir exists + is writable by the service user.
mkdir -p "${SRC}/data"
chown -R arena_agent:arena_agent "${SRC}/data"

# Kill any old gunicorn for this app.
pkill -f "gunicorn.*deutsches-flugzeug" || true
pkill -f "gunicorn.*wsgi:dieApplikation" || true
for _ in $(seq 1 20); do pgrep -f "gunicorn.*wsgi:dieApplikation" >/dev/null || break; sleep 0.2; done

mkdir -p "$(dirname "${LOG}")"

# Launch gunicorn with cwd = app dir (so the relative data/ paths resolve there),
# as the service user.
runuser -u arena_agent -- bash -c \
    "cd '${SRC}' && exec '${VENV}/bin/gunicorn' --chdir '${SRC}' \
        --bind 0.0.0.0:${PORT} --workers 2 --timeout 60 \
        --name deutsches-flugzeug 'wsgi:dieApplikation'" \
    > "${LOG}" 2>&1 &

# Health probe: wait for HTTP 200 on /auth/login.
for _ in $(seq 1 30); do
    if "${VENV}/bin/python" - "${PORT}" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    r = urllib.request.urlopen(f"http://127.0.0.1:{port}/auth/login", timeout=2)
    sys.exit(0 if r.status == 200 else 1)
except Exception:
    sys.exit(1)
PY
    then echo "deutsches-flugzeug restarted, pid=$(pgrep -f "gunicorn.*wsgi:dieApplikation" | head -1)"; exit 0; fi
    sleep 1
done
echo "deutsches-flugzeug failed to become healthy after restart" >&2
tail -n 40 "${LOG}" >&2 || true
exit 1
