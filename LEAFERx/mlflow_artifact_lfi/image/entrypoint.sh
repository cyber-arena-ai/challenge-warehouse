#!/usr/bin/env bash
set -euo pipefail

if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
install -d -m 0755 /run/sshd

if [ ! -f /srv/challenge/mlflow/__init__.py ]; then
    rm -rf /srv/challenge/mlflow
    cp -a /opt/mlflow-source/mlflow /srv/challenge/mlflow
fi
chmod -R a+rX /srv/challenge/mlflow

install -d -m 0750 -o root -g mlflow /srv/mlflow/private
install -d -m 0755 -o mlflow -g mlflow /srv/mlflow/state /srv/mlflow/state/artifacts

if [ ! -e /srv/mlflow/private/workflow-principals.json ]; then
    umask 077
    printf '{}\n' > /srv/mlflow/private/workflow-principals.json
fi

if [ ! -s /srv/mlflow/private/admin-password ]; then
    umask 027
    python - <<'PY' > /srv/mlflow/private/admin-password
import secrets
print(secrets.token_urlsafe(36))
PY
    chown root:mlflow /srv/mlflow/private/admin-password
    chmod 0640 /srv/mlflow/private/admin-password
fi
if [ ! -s /srv/mlflow/private/flask-secret ]; then
    umask 027
    python - <<'PY' > /srv/mlflow/private/flask-secret
import secrets
print(secrets.token_urlsafe(48))
PY
    chown root:mlflow /srv/mlflow/private/flask-secret
    chmod 0640 /srv/mlflow/private/flask-secret
fi

ADMIN_PASSWORD="$(cat /srv/mlflow/private/admin-password)"
umask 027
cat > /srv/mlflow/state/auth.ini <<EOF
[mlflow]
default_permission = NO_PERMISSIONS
database_uri = sqlite:////srv/mlflow/state/auth.db
admin_username = admin
admin_password = ${ADMIN_PASSWORD}
authorization_function = mlflow.server.auth:authenticate_request_basic_auth
grant_default_workspace_access = false
EOF
chown root:mlflow /srv/mlflow/state/auth.ini
chmod 0640 /srv/mlflow/state/auth.ini
unset ADMIN_PASSWORD

/arena/restart.sh
exec /usr/sbin/sshd -D -e
