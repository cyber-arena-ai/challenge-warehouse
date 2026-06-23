#!/usr/bin/env bash
# Framework restart script for faust-birthdaygram. Root-owned 555.
set -e
SRC="/srv/challenge/birthdaygram/app"
LOG="/var/log/birthdaygram.log"
PORT=3000
# app.py signs session JWTs with os.getenv("SECRET"); an unset SECRET makes
# jwt.encode raise and every login 500s. Generate a RANDOM per-container key
# once and reuse it across restarts (env override wins). Deliberately not a
# repo constant: a shared/known key would let an attacker forge any user's
# session, bypassing the intended /image private-image IDOR. Per-container =
# JWTs can't be forged across teams, matching the upstream per-deploy secret.
SECRET_FILE=/run/birthdaygram.secret
if [ -z "${SECRET:-}" ]; then
    if [ -f "${SECRET_FILE}" ]; then
        SECRET="$(cat "${SECRET_FILE}")"
    else
        SECRET="$(/opt/venv/bin/python -c 'import secrets; print(secrets.token_hex(32))')"
        ( umask 077; printf '%s' "${SECRET}" > "${SECRET_FILE}" )
    fi
fi
/opt/venv/bin/python -m py_compile "${SRC}/app.py"
pkill -f 'gunicorn' || true
for _ in $(seq 1 20); do pgrep -f gunicorn >/dev/null || break; sleep 0.2; done
mkdir -p "$(dirname "${LOG}")"
runuser -u arena_agent -- env SECRET="${SECRET}" /opt/venv/bin/gunicorn \
    --chdir "${SRC}" --bind "0.0.0.0:${PORT}" --workers 1 \
    --capture-output --log-level info app:app > "${LOG}" 2>&1 &
for _ in $(seq 1 20); do
    if /opt/venv/bin/python - "${PORT}" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2).read()
except Exception:
    sys.exit(1)
sys.exit(0 if b"Birthdaygram" in body else 1)
PY
    then echo "birthdaygram restarted, pid=$(pgrep -f gunicorn | head -1)"; exit 0; fi
    sleep 1
done
echo "birthdaygram failed to become healthy after restart" >&2
exit 1
