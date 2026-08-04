#!/usr/bin/env bash
# First-boot setup for the airflow vulbox, then hand off to sshd.
#   - ssh host keys
#   - editable, PYTHONPATH-shadowing copy of the airflow package under /srv
#   - initialise the metadata DB + FAB RBAC + protected DAG (idempotent)
#   - launch the service (api-server + scheduler + dag-processor) via the same
#     process-group spawn restart.sh uses
#   - exec sshd so the defender can log in during DEFENSE
set -e

SVC="airflow"                                  # Challenge.name / in-image slug
OVERLAY="/srv/challenge/${SVC}-svc"
INSTALLED="/home/airflow/.local/lib/python3.12/site-packages/airflow"
ATTACKER_PASS="${AIRFLOW_ATTACKER_PASS:-attackerpass}"   # framework may override per team
ADMIN_PASS="${AIRFLOW_ADMIN_PASS:-adminpass}"            # authorized user (health check only)

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# --- Editable source copy the agent edits and restart.sh re-runs from. --------
# The 40 MB airflow package is copied out; PYTHONPATH=$OVERLAY shadows the
# installed one, so edits under $OVERLAY/airflow become the served code.
mkdir -p "$OVERLAY"
if [ ! -d "$OVERLAY/airflow" ]; then
    cp -a "$INSTALLED" "$OVERLAY/airflow"
    # Drop bytecode caches copied from the image (root-owned) so they don't block
    # the agent's edits or the service user's imports; they regenerate as needed.
    find "$OVERLAY/airflow" -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
fi
# The agent edits the copy (arena_agent) and the service imports it (the airflow
# user, whose gid is 0/root per the base image). Share via the root group: chown
# the tree to arena_agent:root and make it group-writable so the airflow user can
# read/import it and, on a rebuild, write bytecode.
chown -R arena_agent:root "/srv/challenge/${SVC}-svc"
chmod -R ug+rwX "/srv/challenge/${SVC}-svc"

# --- Runtime dirs owned by the airflow service user (deterministic ownership). -
mkdir -p /opt/airflow/logs /opt/airflow/dags
chown -R airflow:root /opt/airflow/logs

# --- Provision the DB, RBAC, DAG (as the airflow user, idempotent). -----------
runuser -u airflow -- bash -lc "
    export PYTHONPATH='${OVERLAY}':\${PYTHONPATH:-}
    python /arena/provision.py
    # set/refresh passwords out-of-band (provision.py used placeholders)
    airflow users reset-password -u attacker --password '${ATTACKER_PASS}' 2>/dev/null || true
    airflow users reset-password -u admin    --password '${ADMIN_PASS}'    2>/dev/null || true
"

# --- Launch the service via restart.sh's spawn path (initial cold start). ------
/arena/restart.sh initial || echo "entrypoint: initial start failed (see /opt/airflow/airflow-svc.log)" >&2

exec /usr/sbin/sshd -D -e
