#!/usr/bin/env bash
# Rebuild the Go binaries offline (a broken edit fails the build, SOP §7) and
# respawn the two daemons (log :3000 + monitor :3001) as the service user.
# Runs as root (privileged docker exec), so it can write GOCACHE + bin/.
set -e
SRC="/srv/challenge/certified-transparency/app"
LOG_LOG="/var/log/ct-log.log"
MON_LOG="/var/log/ct-monitor.log"
PORT=3000
MON_PORT=3001

# Be independent of how we're invoked (login shells can drop the image PATH):
# pin the Go toolchain + its offline module/build cache.
export PATH="/usr/local/go/bin:${PATH}"
export GOPATH="${GOPATH:-/go}"
export GOCACHE="${GOCACHE:-/root/.cache/go-build}"
# Every dep is cached in $GOPATH/pkg/mod, so the build never touches the network;
# a source error fails here and fails the restart.
export GOFLAGS="-mod=mod"
export GOPROXY=off

# Compile gate.
( cd "${SRC}" && go build -o bin/log ./cmd/log && go build -o bin/monitor ./cmd/monitor )
chmod 0755 "${SRC}/bin/log" "${SRC}/bin/monitor"

# Stop the old daemons. The processes run as `./bin/log` / `./bin/monitor`
# (relative cwd), so match on the basenames, not the absolute path. Use
# whole-string anchors so we don't also kill this script (pkill -f matches the
# full command line). The old log holds the BadgerDB lock, so a new log cannot
# open the DB until the old one is gone — wait for it to actually exit.
pkill -f 'bin/log( |$)' || true
pkill -f 'bin/monitor( |$)' || true
for _ in $(seq 1 50); do
    pgrep -f 'bin/(log|monitor)( |$)' >/dev/null || break
    sleep 0.2
done
# Hard-kill anything still clinging to the DB lock.
pkill -9 -f 'bin/log( |$)' 2>/dev/null || true
pkill -9 -f 'bin/monitor( |$)' 2>/dev/null || true
sleep 0.3

mkdir -p "$(dirname "${LOG_LOG}")"

# Make state writable by the service user (badger DB + keys live under data/).
mkdir -p "${SRC}/data" "${SRC}/data-client"
chown -R arena_agent:arena_agent "${SRC}/data" "${SRC}/data-client" "${SRC}/bin" 2>/dev/null || true

# log server (opens the embedded BadgerDB; cwd = app dir so data/ lands there).
( cd "${SRC}" && runuser -u arena_agent -- ./bin/log ) > "${LOG_LOG}" 2>&1 &

# Wait for the log server to answer before launching monitor (monitor fetches
# the pubkey from log at start).
log_ready=0
for _ in $(seq 1 30); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    s.sendall(b"GET /api/v1/get-pubkey HTTP/1.0\r\nHost: x\r\n\r\n")
    data=b""
    while True:
        chunk=s.recv(4096)
        if not chunk: break
        data+=chunk
    s.close()
except Exception:
    sys.exit(1)
sys.exit(0 if b'"pubkey"' in data else 1)
PY
    then log_ready=1; break; fi
    sleep 1
done
if [ "${log_ready}" != "1" ]; then
    echo "certified-transparency: log server failed to become healthy" >&2
    exit 1
fi

# monitor server (cwd = app dir to share data/encrypt-key with log).
( cd "${SRC}" && runuser -u arena_agent -- ./bin/monitor --host "http://127.0.0.1:${PORT}" ) > "${MON_LOG}" 2>&1 &

for _ in $(seq 1 30); do
    if python3 - "${MON_PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    s.sendall(b"GET /api/v1/get-pubkey HTTP/1.0\r\nHost: x\r\n\r\n")
    data=b""
    while True:
        chunk=s.recv(4096)
        if not chunk: break
        data+=chunk
    s.close()
except Exception:
    sys.exit(1)
sys.exit(0 if b'"pubkey"' in data else 1)
PY
    then echo "certified-transparency restarted: log pid=$(pgrep -f 'bin/log( |$)' | head -1) monitor pid=$(pgrep -f 'bin/monitor( |$)' | head -1)"; exit 0; fi
    sleep 1
done
echo "certified-transparency: monitor server failed to become healthy after restart" >&2
exit 1
