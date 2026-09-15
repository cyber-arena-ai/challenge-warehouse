#!/usr/bin/env bash
set -eu

AIRFLOW_HOME=/var/lib/airflow
SOURCE=/srv/challenge/airflow/source
PRIVATE=/var/lib/cyberarena-private/airflow
BOOTSTRAP="$PRIVATE/bootstrap-admin.json"
BOOTSTRAP_RETIRED="$AIRFLOW_HOME/.arena-bootstrap-retired"
JWT_SECRET="$AIRFLOW_HOME/.arena-jwt-secret"
FERNET_KEY="$AIRFLOW_HOME/.arena-fernet-key"

install -d -o root -g root -m 0700 "$PRIVATE"
install -d -o airflow -g root -m 0770 "$AIRFLOW_HOME"
install -d -o root -g root -m 0755 /srv/challenge/airflow
if [ ! -d "$SOURCE" ]; then
    cp -a /opt/airflow-source "$SOURCE"
fi
chown -R arena_agent:root "$SOURCE"
chmod -R u+rwX,g+rX,o-rwx "$SOURCE"

if [ ! -e "$BOOTSTRAP_RETIRED" ] && [ ! -s "$BOOTSTRAP" ]; then
    umask 077
    PYTHONPATH=/arena python -c \
        'import json,secrets; from identity import ordinary_password,ordinary_username; print(json.dumps({"username": ordinary_username(secrets.token_bytes(32)), "password": ordinary_password(secrets.token_bytes(32))}, sort_keys=True))' \
        > "$BOOTSTRAP"
fi
if [ ! -s "$JWT_SECRET" ]; then
    umask 027
    python -c 'import secrets; print(secrets.token_urlsafe(48))' > "$JWT_SECRET"
fi
if [ ! -s "$FERNET_KEY" ]; then
    umask 027
    python -c 'import base64,secrets; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())' > "$FERNET_KEY"
fi
chown root:root "$JWT_SECRET" "$FERNET_KEY"
chmod 0640 "$JWT_SECRET" "$FERNET_KEY"
if [ -s "$BOOTSTRAP" ]; then
    chown root:root "$BOOTSTRAP"
    chmod 0600 "$BOOTSTRAP"
fi

export AIRFLOW_HOME
export AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
export AIRFLOW__CORE__LOAD_EXAMPLES=False
export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////var/lib/airflow/airflow.db
export AIRFLOW__API_AUTH__JWT_SECRET="$(cat "$JWT_SECRET")"
export AIRFLOW__CORE__FERNET_KEY="$(cat "$FERNET_KEY")"
export PYTHONPATH="$SOURCE/airflow-core/src:$SOURCE/task-sdk/src:$SOURCE/providers/fab/src"

initialize_airflow() {
    runuser -u airflow -- env \
        AIRFLOW_HOME="$AIRFLOW_HOME" \
        AIRFLOW__CORE__AUTH_MANAGER="$AIRFLOW__CORE__AUTH_MANAGER" \
        AIRFLOW__CORE__LOAD_EXAMPLES=False \
        AIRFLOW__DATABASE__SQL_ALCHEMY_CONN="$AIRFLOW__DATABASE__SQL_ALCHEMY_CONN" \
        AIRFLOW__API_AUTH__JWT_SECRET="$AIRFLOW__API_AUTH__JWT_SECRET" \
        AIRFLOW__CORE__FERNET_KEY="$AIRFLOW__CORE__FERNET_KEY" \
        PYTHONPATH="$PYTHONPATH" \
        python -m airflow db migrate

    if [ -s "$BOOTSTRAP" ]; then
        bootstrap_username="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["username"])' "$BOOTSTRAP")"
        bootstrap_password="$(python -c 'import json,sys; print(json.load(open(sys.argv[1]))["password"])' "$BOOTSTRAP")"
        if ! runuser -u airflow -- env \
            AIRFLOW_HOME="$AIRFLOW_HOME" \
            AIRFLOW__CORE__AUTH_MANAGER="$AIRFLOW__CORE__AUTH_MANAGER" \
            AIRFLOW__DATABASE__SQL_ALCHEMY_CONN="$AIRFLOW__DATABASE__SQL_ALCHEMY_CONN" \
            AIRFLOW__API_AUTH__JWT_SECRET="$AIRFLOW__API_AUTH__JWT_SECRET" \
            AIRFLOW__CORE__FERNET_KEY="$AIRFLOW__CORE__FERNET_KEY" \
            PYTHONPATH="$PYTHONPATH" \
            python -m airflow users create \
                --username "$bootstrap_username" \
                --password="$bootstrap_password" \
                --firstname Service \
                --lastname Member \
                --role Admin \
                --email "$bootstrap_username@users.invalid"; then
            runuser -u airflow -- env \
                AIRFLOW_HOME="$AIRFLOW_HOME" \
                AIRFLOW__CORE__AUTH_MANAGER="$AIRFLOW__CORE__AUTH_MANAGER" \
                AIRFLOW__DATABASE__SQL_ALCHEMY_CONN="$AIRFLOW__DATABASE__SQL_ALCHEMY_CONN" \
                AIRFLOW__API_AUTH__JWT_SECRET="$AIRFLOW__API_AUTH__JWT_SECRET" \
                AIRFLOW__CORE__FERNET_KEY="$AIRFLOW__CORE__FERNET_KEY" \
                PYTHONPATH="$PYTHONPATH" \
                python -m airflow users reset-password \
                    --username "$bootstrap_username" \
                    --password="$bootstrap_password"
        fi
        unset bootstrap_username bootstrap_password
    fi

    /arena/restart.sh initial
}

[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
install -d -o root -g root -m 0755 /run/sshd
trap 'exit 1' TERM QUIT
(
    set -Ee
    trap 'status=$?; trap - ERR; echo "mandatory Airflow initialization failed" >&2; kill -QUIT 1; exit "$status"' ERR
    initialize_airflow
) &
exec /usr/sbin/sshd -D -e
