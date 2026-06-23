#!/usr/bin/env bash
# Re-check the Python sources (a broken edit fails the restart, SOP §7), then
# respawn the inetd wrapper as the service user. No compile step — the service
# is interpreted Python with a flat-file backend (no database to start).
set -e
APP="/srv/challenge/btx/app"
SRC="${APP}/server"
LOG="/var/log/btx.log"
PORT=1983

# Syntax gate: a broken edit must fail the restart, not crash per-connection.
python3 -m py_compile \
    "${SRC}/neu-ulm.py" "${SRC}/blog.py" "${SRC}/user.py" \
    "${SRC}/login.py" "${SRC}/editor.py" "${SRC}/util.py" "${SRC}/cept.py"

pkill -f '/arena/inetd.py' || true
for _ in $(seq 1 20); do pgrep -f '/arena/inetd.py' >/dev/null || break; sleep 0.2; done

mkdir -p "$(dirname "${LOG}")"

# Per-connection handler: `python3 -u neu-ulm.py`, cwd = the server dir so its
# relative ../users ../secrets ../blogs ../data paths resolve.
INETD_APP="${SRC}" INETD_PORT="${PORT}" \
    INETD_HANDLER="/usr/bin/python3 -u neu-ulm.py" \
    runuser -u arena_agent -- /usr/bin/python3 -u /arena/inetd.py > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    data=b""
    while b"Participant" not in data and len(data) < 65536:
        try: chunk=s.recv(4096)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception: sys.exit(1)
sys.exit(0 if b"Participant" in data else 1)
PY
    then echo "btx restarted, pid=$(pgrep -f '/arena/inetd.py' | head -1)"; exit 0; fi
    sleep 1
done
echo "btx failed to become healthy after restart" >&2
exit 1
