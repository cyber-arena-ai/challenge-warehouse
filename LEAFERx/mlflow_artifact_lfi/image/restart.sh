#!/usr/bin/env bash
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1

if [ -s /run/mlflow.pid ]; then
    old_pid="$(cat /run/mlflow.pid)"
    if kill -0 "${old_pid}" 2>/dev/null; then
        kill -- "-${old_pid}" 2>/dev/null || true
        kill "${old_pid}" 2>/dev/null || true
        for _ in $(seq 1 30); do
            kill -0 "${old_pid}" 2>/dev/null || break
            sleep 0.2
        done
        kill -9 -- "-${old_pid}" 2>/dev/null || true
        kill -9 "${old_pid}" 2>/dev/null || true
    fi
fi
pkill -f '[p]ython -m mlflow server' 2>/dev/null || true
rm -f /run/mlflow.pid

# Validate only after the serving worker is gone. A broken edit must fail
# closed instead of leaving the previously loaded source available.
PYTHONPATH=/srv/challenge python -c 'import mlflow.server.auth, mlflow.server.handlers'

install -d -m 0755 -o mlflow -g mlflow /srv/mlflow/state/artifacts
setsid runuser -u mlflow -- bash -c '
  export PYTHONPATH=/srv/challenge
  export PYTHONDONTWRITEBYTECODE=1
  export MLFLOW_AUTH_CONFIG_PATH=/srv/mlflow/state/auth.ini
  export MLFLOW_FLASK_SERVER_SECRET_KEY="$(cat /srv/mlflow/private/flask-secret)"
  cd /srv/challenge
  exec python -m mlflow server \
    --app-name basic-auth \
    --host 0.0.0.0 \
    --port 5000 \
    --workers 1 \
    --allowed-hosts "*" \
    --backend-store-uri sqlite:////srv/mlflow/state/tracking.db \
    --artifacts-destination /srv/mlflow/state/artifacts
' > /var/log/mlflow.stdout 2>&1 &
spawned_pid="$!"
echo "${spawned_pid}" > /run/mlflow.pid

for _ in $(seq 1 90); do
    if python - <<'PY'
import urllib.request
try:
    with urllib.request.urlopen("http://127.0.0.1:5000/health", timeout=2) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except Exception:
    raise SystemExit(1)
PY
    then
        echo "MLflow tracking server is ready"
        exit 0
    fi
    if ! kill -0 "${spawned_pid}" 2>/dev/null; then
        break
    fi
    sleep 1
done

kill -- "-${spawned_pid}" 2>/dev/null || true
kill "${spawned_pid}" 2>/dev/null || true
pkill -f '[p]ython -m mlflow server' 2>/dev/null || true
for _ in $(seq 1 30); do
    if ! kill -0 "${spawned_pid}" 2>/dev/null \
        && ! pgrep -f '[p]ython -m mlflow server' >/dev/null; then
        break
    fi
    sleep 0.2
done
kill -9 -- "-${spawned_pid}" 2>/dev/null || true
kill -9 "${spawned_pid}" 2>/dev/null || true
pkill -9 -f '[p]ython -m mlflow server' 2>/dev/null || true
wait "${spawned_pid}" 2>/dev/null || true
rm -f /run/mlflow.pid
tail -n 100 /var/log/mlflow.stdout >&2 || true
exit 1
