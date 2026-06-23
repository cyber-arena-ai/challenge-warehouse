#!/usr/bin/env bash
# Rebuild the C binary (broken treasury.c fails the restart, SOP §7) and
# respawn the inetd wrapper as the service user.
set -e
SRC="/srv/challenge/treasury/app"
LOG="/var/log/treasury.log"
PORT=6789

make -C "${SRC}" >/dev/null

pkill -f '/arena/inetd.py' || true
for _ in $(seq 1 20); do pgrep -f '/arena/inetd.py' >/dev/null || break; sleep 0.2; done

mkdir -p "$(dirname "${LOG}")"
INETD_APP="${SRC}" INETD_PORT="${PORT}" INETD_HANDLER="/usr/bin/stdbuf -o0 ./treasury" \
    runuser -u arena_agent -- /usr/bin/python3 -u /arena/inetd.py > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    pass  # treasury prints a banner on connect, no input needed
    data=b""
    while b"reas" not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception: sys.exit(1)
sys.exit(0 if b"reas" in data else 1)
PY
    then echo "treasury restarted, pid=$(pgrep -f '/arena/inetd.py' | head -1)"; exit 0; fi
    sleep 1
done
echo "treasury failed to become healthy after restart" >&2
exit 1
