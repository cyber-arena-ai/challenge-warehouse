#!/usr/bin/env bash
set -e
SRC="/srv/challenge/marscasino/app"; LOG="/var/log/marscasino.log"; PORT=7777
/opt/venv/bin/python -m py_compile "${SRC}/app.py"
pkill -f 'gunicorn' || true
for _ in $(seq 1 20); do pgrep -f gunicorn >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'gunicorn' 2>/dev/null || true
mkdir -p "$(dirname "${LOG}")"
runuser -u arena_agent -- /opt/venv/bin/gunicorn --chdir "${SRC}" --bind "0.0.0.0:${PORT}" --workers 1 \
    --capture-output --log-level info app:app > "${LOG}" 2>&1 &
for _ in $(seq 1 20); do
    if /opt/venv/bin/python - "${PORT}" <<'PY'
import http.cookiejar
import os
import re
import sys
import time
import urllib.parse
import urllib.request

port=int(sys.argv[1])
base=f"http://127.0.0.1:{port}/"

def post(opener, path, data):
    payload = urllib.parse.urlencode(data).encode()
    return opener.open(base + path, data=payload, timeout=2).read().decode(errors="replace")

try:
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    body = opener.open(base, timeout=2).read()
    if b"asino" not in body:
        raise RuntimeError("index marker missing")

    suffix = f"{os.getpid()}{int(time.time() * 1000)}"
    username = f"ready{suffix}"[-32:]
    password = f"pw{suffix}"[-32:]
    body = post(opener, "register", {
        "username": username,
        "password": password,
        "ip": "127.0.0.1",
        "fcode": "",
    })
    match = re.search(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", body)
    if not match:
        raise RuntimeError("activation code missing")

    opener.open(base + "verify?code=" + match.group(0), timeout=2).read()
    body = post(opener, "login", {"username": username, "password": password})
    if b"Wrong" in body.encode() or "Account is not activated" in body:
        raise RuntimeError("login failed")

    post(opener, "home", {"item": "rdyy", "item_cost": "3"})
    body = post(opener, "game2", {"bet": "3"})
    match = re.search(r"Voucher: <b>(.*?)<", body)
    if not match:
        raise RuntimeError("voucher missing")

    body = post(opener, "voucher", {"voucher": match.group(1)})
    if "You won" not in body:
        raise RuntimeError("voucher activation failed")
except Exception:
    sys.exit(1)
PY
    then echo "marscasino restarted, pid=$(pgrep -f gunicorn | head -1)"; exit 0; fi
    sleep 1
done
echo "marscasino failed to become gameplay-ready" >&2; exit 1
