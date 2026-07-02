#!/usr/bin/env bash
# Rebuild the Rust binary offline (a broken edit fails the build, SOP §7) and
# respawn the inetd wrapper as the service user. Runs as root (privileged
# docker exec), so it can write the CARGO_HOME cache and target/.
set -e
SRC="/srv/challenge/rceaas/app"
BIN="${SRC}/target/release/RCEaaS"
LOG="/var/log/rceaas.log"
PORT=1835

# Be independent of how we're invoked (login shells can drop the image PATH):
# pin the Rust toolchain + its offline crate cache.
export PATH="/usr/local/cargo/bin:${PATH}"
export CARGO_HOME="${CARGO_HOME:-/usr/local/cargo}"
export RUSTUP_HOME="${RUSTUP_HOME:-/usr/local/rustup}"

# Compile gate: every crate dep is cached in CARGO_HOME, so --offline never
# touches the network; a source error fails here and fails the restart.
( cd "${SRC}" && cargo build --release --offline )
chmod 0755 "${BIN}"

pkill -f '/arena/inetd.py' || true
for _ in $(seq 1 20); do pgrep -f '/arena/inetd.py' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f '/arena/inetd.py' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"

# Per-connection handler: the compiled binary, cwd = service dir (set by inetd,
# so jails/ + passwords/ land under ${SRC}).
INETD_APP="${SRC}" INETD_PORT="${PORT}" INETD_HANDLER="${BIN}" \
    runuser -u arena_agent -- /usr/bin/python3 -u /arena/inetd.py > "${LOG}" 2>&1 &

for _ in $(seq 1 20); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    data=b""
    while b"username" not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception: sys.exit(1)
sys.exit(0 if b"username" in data else 1)
PY
    then echo "rceaas restarted, pid=$(pgrep -f '/arena/inetd.py' | head -1)"; exit 0; fi
    sleep 1
done
echo "rceaas failed to become healthy after restart" >&2
exit 1
