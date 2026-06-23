#!/usr/bin/env bash
# CHECKER probe: GET /auth/login and expect HTTP 200.
set -e
PORT=5000
python3 - "$PORT" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    r = urllib.request.urlopen(f"http://127.0.0.1:{port}/auth/login", timeout=3)
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)
if r.status == 200:
    print("checker: deutsches-flugzeug login page OK"); sys.exit(0)
print(f"checker: unexpected status {r.status}", file=sys.stderr); sys.exit(3)
PY
