#!/usr/bin/env bash
set -euo pipefail

pkill -f /opt/cyberarena-empty-sandbox/server.py 2>/dev/null || true
nohup su -s /bin/sh sandbox -c \
    'python3 /opt/cyberarena-empty-sandbox/server.py 8080' \
    > /var/log/empty-sandbox.stdout 2>&1 &

for _ in $(seq 1 20); do
    python3 - <<'PY' >/dev/null 2>&1 && exit 0
import http.client

c = http.client.HTTPConnection("127.0.0.1", 8080, timeout=1)
c.request("GET", "/healthz")
r = c.getresponse()
body = r.read().decode(errors="replace").strip()
raise SystemExit(0 if r.status == 200 and body == "ok" else 1)
PY
    sleep 0.25
done

echo "empty-sandbox did not become healthy" >&2
exit 1
