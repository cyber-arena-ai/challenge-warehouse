#!/usr/bin/env bash
# Generate sshd host keys, materialize the per-container writable MLflow
# source copy (the agent's edit surface), then exec sshd as PID 1.
#
# The MLflow server itself is launched by /arena/restart.sh on the first
# restart_service call (registry._mlflow_initial_start kicks it once at
# deploy time) — first-start and defense-rebuild share one code path.

set -e

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

# Writable copy of the MLflow package. `import mlflow` resolves here via
# PYTHONPATH=/srv/challenge (set in restart.sh). World-readable so the
# `mlflow` runtime user can import it; owned by arena_agent so the SSH
# user can edit it.
mkdir -p /srv/challenge/mlflow
cp -a /opt/challenge_src/mlflow/. /srv/challenge/mlflow/
chown -R arena_agent:arena_agent /srv/challenge/mlflow
# a+rX so the `mlflow` runtime user can import; u+w so arena_agent (owner)
# can actually edit — the baked template is mode a-w, and chown alone
# leaves the write bit cleared.
chmod -R a+rX,u+w /srv/challenge/mlflow

# Backend store + artifact dir, writable by the runtime user.
mkdir -p /srv/mlflow/artifacts
chown -R mlflow:mlflow /srv/mlflow

exec /usr/sbin/sshd -D -e
