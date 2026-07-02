#!/usr/bin/env bash
# Rebuild the C binary (broken cartography.c fails the restart, SOP §7) and
# respawn the inetd wrapper as the service user.
set -e
SRC="/srv/challenge/cartography/app"
LOG="/var/log/cartography.log"
PORT=6666

make -C "${SRC}" >/dev/null

pkill -f '/arena/inetd.py' || true
for _ in $(seq 1 20); do pgrep -f '/arena/inetd.py' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f '/arena/inetd.py' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
INETD_APP="${SRC}" INETD_PORT="${PORT}" INETD_HANDLER="/usr/bin/stdbuf -o0 ./cartography" \
    runuser -u arena_agent -- /usr/bin/python3 -u /arena/inetd.py > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    s.sendall(b"5\n")
    data=b""
    while b">" not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception: sys.exit(1)
sys.exit(0 if b">" in data else 1)
PY
    then echo "cartography restarted, pid=$(pgrep -f '/arena/inetd.py' | head -1)"; exit 0; fi
    sleep 1
done
echo "cartography failed to become healthy after restart" >&2
exit 1
