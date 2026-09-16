#!/usr/bin/env bash
set -eu

SOURCE=/srv/challenge/airflow/source
export AIRFLOW_HOME=/var/lib/airflow
export AIRFLOW__CORE__AUTH_MANAGER=airflow.providers.fab.auth_manager.fab_auth_manager.FabAuthManager
export AIRFLOW__CORE__LOAD_EXAMPLES=False
export AIRFLOW__DATABASE__SQL_ALCHEMY_CONN=sqlite:////var/lib/airflow/airflow.db
export AIRFLOW__API__WORKERS=1
export AIRFLOW__LOGGING__LOGGING_LEVEL=WARNING
export AIRFLOW__API_AUTH__JWT_SECRET="$(cat "$AIRFLOW_HOME/.arena-jwt-secret")"
export AIRFLOW__CORE__FERNET_KEY="$(cat "$AIRFLOW_HOME/.arena-fernet-key")"
export PYTHONPATH="$SOURCE/airflow-core/src:$SOURCE/task-sdk/src:$SOURCE/providers/fab/src"

exec python -m airflow api-server --host 0.0.0.0 --port 8080 --workers 1
