#!/usr/bin/env bash
# Recompile the Java service (a broken edit fails javac -> fails the restart,
# SOP §7), kill the old long-lived daemon, relaunch it as the DB-matching user
# "8BitOracle" (unix_socket auth), then health-probe 17280. Runs as root
# (privileged docker exec).
set -e
SRC="/srv/challenge/8-bit-oracle/app"
PROJ="${SRC}/_8BitOracle"
JAR="${SRC}/EightBitOracle.jar"
LOG="/var/log/8-bit-oracle.log"
PORT=17280

# --- Compile gate: recompile classes + repackage the jar from edited source --
# Every SQLDriver dep is local under ${PROJ}/SQLDriver, so this never touches
# the network; a source error fails here and fails the restart.
#
# SKIP_COMPILE (set by entrypoint on the INITIAL boot): the jar is already
# pre-built at image-build time, so skip javac entirely. Recompiling on every
# boot is a ~2s CPU spike per container that, multiplied across a concurrent
# batch deploy, pushed the service past the round-0 flag-plant window. Only a
# defender rebuild (MCP restart_service, no SKIP_COMPILE) needs to recompile.
if [ -z "${SKIP_COMPILE:-}" ]; then
    rm -rf "${PROJ}/build"
    mkdir -p "${PROJ}/build"
    ( cd "${PROJ}" && javac -cp "SQLDriver/*" -sourcepath . -d build src/*.java )
    ( cd "${PROJ}/build" && jar cfm "${JAR}" "${PROJ}/oracle.mf" *.class )
elif [ ! -f "${JAR}" ]; then
    echo "restart.sh: SKIP_COMPILE set but ${JAR} missing" >&2
    exit 1
fi
# Keep the runtime jars next to the app jar (manifest Class-Path is relative).
cp "${PROJ}"/SQLDriver/*.jar "${SRC}/" 2>/dev/null || true
chmod -R a+rX "${SRC}"

# --- Respawn the daemon ------------------------------------------------------
pkill -f 'EightBitOracle.jar' || true
for _ in $(seq 1 20); do pgrep -f 'EightBitOracle.jar' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'EightBitOracle.jar' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
# cwd = ${SRC} so the relative Class-Path in the manifest resolves the jars.
runuser -u 8BitOracle -- bash -c "cd '${SRC}' && exec java -jar '${JAR}'" > "${LOG}" 2>&1 &

# --- Health probe: connect, send a bogus line, expect an ERROR reply --------
for _ in $(seq 1 30); do
    if python3 - "${PORT}" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(2); s.connect(("127.0.0.1",port))
    s.sendall(b"PING\n")
    data=b""
    while b"\n" not in data:
        chunk=s.recv(256)
        if not chunk: break
        data+=chunk
    s.close()
except Exception:
    sys.exit(1)
sys.exit(0 if b"ERROR" in data else 1)
PY
    then echo "8-bit-oracle restarted, pid=$(pgrep -f 'EightBitOracle.jar' | head -1)"; exit 0; fi
    sleep 1
done
echo "8-bit-oracle failed to become healthy after restart" >&2
exit 1
