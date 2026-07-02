#!/usr/bin/env bash
# Re-check the Python sources (a broken edit fails the restart, SOP §7), then
# respawn the inetd wrapper + log-cleaner as the service user. No compile step —
# the service is interpreted Python.
set -e
SRC="/srv/challenge/blockrope/app"
LOG="/var/log/blockrope.log"
PORT=1337

# Syntax gate: a broken edit must fail the restart, not crash per-connection.
python3 -m py_compile "${SRC}/main.py" "${SRC}/util.py" "${SRC}/cleaner.py"

pkill -f '/arena/inetd.py' || true
pkill -f 'blockrope/app/cleaner.py' || true
for _ in $(seq 1 20); do pgrep -f '/arena/inetd.py' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f '/arena/inetd.py' 2>/dev/null || true
pkill -9 -f 'blockrope/app/cleaner.py' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"

# Per-connection handler: `python3 -u main.py`, cwd = service dir (set by inetd).
# TERM is needed so the service's os.system("clear") emits clean escape codes.
TERM=xterm INETD_APP="${SRC}" INETD_PORT="${PORT}" \
    INETD_HANDLER="/usr/bin/python3 -u main.py" \
    runuser -u arena_agent -- /usr/bin/python3 -u /arena/inetd.py > "${LOG}" 2>&1 &

# Background log-rotation job (writes ${SRC}/logs/). Non-fatal if it dies.
runuser -u arena_agent -- bash -c "cd '${SRC}' && exec /usr/bin/python3 -u cleaner.py" \
    >> "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    data=b""
    while b"> " not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception: sys.exit(1)
sys.exit(0 if b"> " in data else 1)
PY
    then echo "blockrope restarted, pid=$(pgrep -f '/arena/inetd.py' | head -1)"; exit 0; fi
    sleep 1
done
echo "blockrope failed to become healthy after restart" >&2
exit 1
