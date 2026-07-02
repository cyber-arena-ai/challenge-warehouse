#!/usr/bin/env bash
# Framework restart script for mlflow-lfi.
#
# Invoked by the MCP `restart_service` tool via docker exec (root).
# Mode 555, root-owned — the agent can read + execute but not modify.
# The only path from an agent edit to the running server is this script.
#
# No compile step (MLflow is interpreted): "rebuild" = re-import the
# (possibly edited) source and respawn the server. The import gate turns
# a syntax/import error in the agent's edit into a clean non-zero exit so
# the RestartHandler reports a failed restart instead of a silent crash.

set -e

PORT=5000
SRV_USER="mlflow"
SRC_ROOT="/srv/challenge"          # PYTHONPATH root; package dir is $SRC_ROOT/mlflow
DATA_DIR="/srv/mlflow"
LOG="/var/log/mlflow.stdout"

# 1. Import gate over the agent-edited server code. Fails fast (and, under
#    `set -e`, aborts the restart) if the edit broke Python import.
PYTHONPATH="${SRC_ROOT}" python3 -c "import mlflow.server.handlers"

# 2. Kill any prior instance. Fresh container has none, hence `|| true`.
pkill -f "gunicorn" 2>/dev/null || true
pkill -f "mlflow server" 2>/dev/null || true
sleep 0.5
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'gunicorn' 2>/dev/null || true
pkill -9 -f 'mlflow server' 2>/dev/null || true

# 3. Respawn as the runtime user with the PYTHONPATH shadow in place.
mkdir -p "${DATA_DIR}/artifacts"
chown -R "${SRV_USER}:${SRV_USER}" "${DATA_DIR}"
mkdir -p "$(dirname "${LOG}")"

nohup runuser -u "${SRV_USER}" -- bash -c "\
  export PYTHONPATH='${SRC_ROOT}' HOME='${DATA_DIR}' GIT_PYTHON_REFRESH=quiet; \
  cd '${DATA_DIR}' && exec mlflow server \
    --host 0.0.0.0 --port ${PORT} --workers 1 \
    --backend-store-uri 'sqlite:///${DATA_DIR}/mlflow.db' \
    --serve-artifacts \
    --artifacts-destination 'file://${DATA_DIR}/artifacts' \
    --default-artifact-root 'mlflow-artifacts:/'" \
  > "${LOG}" 2>&1 &

# 4. Wait (up to ~30s) for the port to bind, using bash's /dev/tcp.
for _ in $(seq 1 30); do
    if (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; then
        exec 3>&- 3<&-
        echo "mlflow-lfi: server up on :${PORT}"
        exit 0
    fi
    sleep 1
done

echo "mlflow-lfi: server failed to bind :${PORT} within 30s" >&2
tail -n 60 "${LOG}" >&2 || true
exit 1
