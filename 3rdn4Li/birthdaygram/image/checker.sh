#!/usr/bin/env bash
# CHECKER-level health probe for faust-birthdaygram. Root-owned 555.
set -e
PORT=3000
/opt/venv/bin/python - "$PORT" <<'PY'
import sys, urllib.request
port = int(sys.argv[1])
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3).read()
except Exception as e:
    print(f"checker: HTTP request failed: {e}", file=sys.stderr); sys.exit(1)
if b"Birthdaygram" in body:
    print("checker: birthdaygram index OK"); sys.exit(0)
print(f"checker: unexpected index body {body[:64]!r}", file=sys.stderr); sys.exit(3)
PY
