#!/usr/bin/env bash
# CHECKER-level health probe for faust-jokes. Root-owned 555.
#
# Confirms the real Flask app serves the login page (DB-backed route) — an
# echo/redirect stub or dead port can't reproduce it.
set -e

PORT=5000

/opt/venv/bin/python - "$PORT" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/login", timeout=3).read()
except Exception as e:
    print(f"checker: HTTP request failed: {e}", file=sys.stderr)
    sys.exit(1)
if b"password" in body.lower():
    print("checker: jokes login page OK")
    sys.exit(0)
print(f"checker: unexpected /login body {body[:64]!r}", file=sys.stderr)
sys.exit(3)
PY
