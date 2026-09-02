#!/usr/bin/env bash
set -euo pipefail

pid_file=/run/grafana/grafana.pid
accounts=/arena/secrets/accounts.json

credentials() {
  python3 -c 'import json,sys; d=json.load(open(sys.argv[1]))["admin"]; print(d["username"]); print(d["password"])' "$accounts"
}

case "${1:-}" in
  start)
    if test -s "$pid_file" && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
      exit 0
    fi
    mapfile -t auth < <(credentials)
    install -d -o 472 -g 0 -m 0770 /var/lib/grafana /var/lib/grafana/plugins /var/log/grafana
    setpriv --reuid=472 --regid=0 --clear-groups \
      env HOME=/var/lib/grafana \
      GF_SECURITY_ADMIN_USER="${auth[0]}" \
      GF_SECURITY_ADMIN_PASSWORD="${auth[1]}" \
      GF_SECURITY_DISABLE_GRAVATAR=true \
      GF_PLUGINS_PREINSTALL_DISABLED=true \
      /usr/share/grafana/bin/grafana server \
        --homepath=/usr/share/grafana \
        --config=/etc/grafana/grafana.ini \
        >>/var/log/grafana/arena.log 2>&1 &
    echo "$!" > "$pid_file"
    ;;
  stop)
    if test -s "$pid_file"; then
      pid=$(cat "$pid_file")
      if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 100); do
          kill -0 "$pid" 2>/dev/null || break
          sleep .1
        done
        kill -KILL "$pid" 2>/dev/null || true
      fi
      rm -f "$pid_file"
    fi
    ;;
  *)
    echo "usage: $0 start|stop" >&2
    exit 2
    ;;
esac
