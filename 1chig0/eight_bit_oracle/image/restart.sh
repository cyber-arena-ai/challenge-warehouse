#!/usr/bin/env bash
# Recompile the Java service (a broken edit fails javac -> fails the restart,
# SOP §7), kill the old long-lived daemon, relaunch it as the DB-matching user
# "8BitOracle" (unix_socket auth), then health-probe 17280. Runs as root
# (privileged docker exec).
#
# Modes:
#   (no arg)  DEFENSE restart: recompile from the (possibly edited) source, then
#             respawn. Used by restart_handler when the agent calls restart_service.
#   initial   COLD START (entrypoint): the jar was already compiled at image-build
#             time and copied into place, so SKIP the javac+jar recompile and spawn
#             the pre-baked jar directly. That removes two redundant JVM cold-starts
#             (javac, jar) from the round-0 critical path — under a concurrent batch
#             deploy (many java+mariadb boxes on one host) those redundant compiles
#             starved the CPU so the service didn't bind 17280 within the flag-plant
#             window (issue #25). A javac OOM under that load also tripped `set -e`
#             and skipped the spawn entirely; skipping it removes that vector too.
set -e
MODE="${1:-restart}"
SRC="/srv/challenge/8-bit-oracle/app"
PROJ="${SRC}/_8BitOracle"
JAR="${SRC}/EightBitOracle.jar"
LOG="/var/log/8-bit-oracle.log"
PORT=17280

# --- Compile gate: recompile classes + repackage the jar from edited source --
# Every SQLDriver dep is local under ${PROJ}/SQLDriver, so this never touches
# the network; a source error fails here and fails the restart. Skipped on the
# initial cold start (the baked jar is already valid); still runs if that jar is
# somehow absent, so a stripped image can't silently start nothing.
if [ "${MODE}" != "initial" ] || [ ! -f "${JAR}" ]; then
    rm -rf "${PROJ}/build"
    mkdir -p "${PROJ}/build"
    ( cd "${PROJ}" && javac -cp "SQLDriver/*" -sourcepath . -d build src/*.java )
    ( cd "${PROJ}/build" && jar cfm "${JAR}" "${PROJ}/oracle.mf" *.class )
    # Keep the runtime jars next to the app jar (manifest Class-Path is relative).
    cp "${PROJ}"/SQLDriver/*.jar "${SRC}/" 2>/dev/null || true
    chmod -R a+rX "${SRC}"
else
    echo "8-bit-oracle: initial cold start — using pre-baked jar, skipping recompile"
fi

# --- Respawn the daemon ------------------------------------------------------
pkill -f 'EightBitOracle.jar' || true
for _ in $(seq 1 20); do pgrep -f 'EightBitOracle.jar' >/dev/null || break; sleep 0.2; done
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'EightBitOracle.jar' 2>/dev/null || true

mkdir -p "$(dirname "${LOG}")"
# cwd = ${SRC} so the relative Class-Path in the manifest resolves the jars.
# Lightweight JVM flags keep the per-box footprint small so many boxes can
# cold-start concurrently without OOM / CPU starvation (issue #25): cap the heap,
# use the single-threaded serial GC (no GC-thread fan-out scaled to host cores),
# and stop JIT at C1 for a cheaper, faster startup. This is a small socket
# oracle; none of these limit it in practice.
JAVA_OPTS="-Xmx256m -XX:+UseSerialGC -XX:TieredStopAtLevel=1"
runuser -u 8BitOracle -- bash -c "cd '${SRC}' && exec java ${JAVA_OPTS} -jar '${JAR}'" > "${LOG}" 2>&1 &

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
