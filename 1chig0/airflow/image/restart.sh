#!/usr/bin/env bash
# Airflow challenge — rebuild + restart. Runs as ROOT via privileged docker-exec
# when the agent calls restart_service (also used by entrypoint with `initial`).
#
# Airflow-specific facts that drive the design:
#   1. Python ⇒ "rebuild" is a SYNTAX GATE (compileall), not a compile.
#   2. The service is a multi-process tree (api-server + scheduler + dag-processor).
#      A naive `pkill -f airflow` leaves the old api-server bound to :8080 STILL
#      SERVING OLD CODE — the SOP failure "old serving code must not remain active"
#      (observed in the feasibility spike). So we launch the components under one
#      session and tear the whole GROUP down, verifying :8080 is DOWN before
#      respawning.
#   3. Deps live in the airflow user's ~/.local, so the service runs as that user.
#   4. FabAuthManager (per-DAG RBAC) — NOT `airflow standalone` (that forces
#      SimpleAuthManager, whose linear roles can't express the V0 authz gap).
set -u
MODE="${1:-restart}"          # `initial` (entrypoint cold start) or `restart` (agent)
SVC_USER="airflow"
OVERLAY="/srv/challenge/airflow"          # == the prompt's /srv/challenge/<svc>/airflow parent
SRC="${OVERLAY}/airflow"
PGID_FILE="/run/airflow-svc.pgid"
LOG="/opt/airflow/airflow-svc.log"     # airflow-user-writable (gid 0); /var/log is root-only
PORT=8080
HEALTH="http://127.0.0.1:${PORT}/api/v2/version"

log(){ echo "restart.sh: $*"; }
port_up(){ curl -s -o /dev/null --max-time 2 "$HEALTH"; }

# --- 1. Syntax gate BEFORE touching the running service (fail-safe). ----------
# Parse every source file with the builtin compile() — pure in-memory parse, no
# bytecode written to disk, so the gate needs write access NOWHERE (the tree's
# __pycache__ dirs are root-owned from the image copy and the gate runs as the
# non-root service user). A syntax error fails here, before we touch the service.
if ! err=$(runuser -u "$SVC_USER" -- python - "$SRC" <<'PY' 2>&1
import sys, pathlib
root = pathlib.Path(sys.argv[1]); bad = 0
for f in root.rglob("*.py"):
    try:
        compile(f.read_bytes(), str(f), "exec")
    except SyntaxError as e:
        bad += 1; print(f"{f}: {e}")
sys.exit(1 if bad else 0)
PY
    ); then
    echo "COMPILE FAILED:" >&2; echo "$err" | tail -20 >&2
    exit 1
fi
log "syntax gate passed"

# --- 2. Teardown by process group; verify :$PORT frees. On `initial` there is no
#        prior instance, so this is a no-op. ------------------------------------
if [ -f "$PGID_FILE" ]; then
    pgid=$(cat "$PGID_FILE" 2>/dev/null || true)
    if [ -n "${pgid:-}" ]; then
        kill -TERM -"$pgid" 2>/dev/null || true
        for _ in $(seq 1 20); do port_up || break; sleep 1; done
        kill -9 -"$pgid" 2>/dev/null || true
        sleep 2
    fi
fi
if port_up; then echo "TEARDOWN FAILED: :$PORT still serving after kill" >&2; exit 1; fi
log "no prior service on :$PORT"

# --- 3. Respawn api-server + scheduler + dag-processor in ONE fresh session. ---
mkdir -p "$(dirname "$LOG")"; : > "$PGID_FILE"; chown "$SVC_USER" "$PGID_FILE"
# Per-box JWT signing secret (entrypoint generated it; read it so a restart_service
# keeps the SAME secret and previously-issued tokens still verify). Never baked into
# the image — a shared secret would be forgeable across boxes.
JWT_SECRET="$(cat /opt/airflow/jwt_secret 2>/dev/null || true)"
runuser -u "$SVC_USER" -- bash -c "
    export PATH='/home/${SVC_USER}/.local/bin':\$PATH
    export PYTHONPATH='${OVERLAY}':\${PYTHONPATH:-}
    export AIRFLOW__API_AUTH__JWT_SECRET='${JWT_SECRET}'
    setsid bash -c '
        echo \$\$ > ${PGID_FILE}
        airflow scheduler      >> ${LOG} 2>&1 &
        airflow dag-processor   >> ${LOG} 2>&1 &
        exec airflow api-server >> ${LOG} 2>&1
    ' &
"
log "respawned pgid=$(cat "$PGID_FILE" 2>/dev/null)"

# --- 4. Health probe: the NEW api-server must answer 200. ---------------------
for _ in $(seq 1 120); do
    [ "$(curl -s -o /dev/null -w '%{http_code}' "$HEALTH" 2>/dev/null)" = "200" ] \
        && { log "healthy on :$PORT"; exit 0; }
    sleep 2
done
echo "HEALTH FAILED: :$PORT not 200 within window" >&2
exit 1
