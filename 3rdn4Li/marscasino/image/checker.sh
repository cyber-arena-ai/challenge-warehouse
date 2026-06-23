#!/usr/bin/env bash
set -e
PORT=7777
/opt/venv/bin/python - "$PORT" <<'PY'
import sys,urllib.request
port=int(sys.argv[1])
try: body=urllib.request.urlopen(f"http://127.0.0.1:{port}/",timeout=3).read()
except Exception as e:
    print(f"checker: HTTP failed: {e}",file=sys.stderr); sys.exit(1)
if b"asino" in body: print("checker: marscasino index OK"); sys.exit(0)
print(f"checker: unexpected {body[:48]!r}",file=sys.stderr); sys.exit(3)
PY
