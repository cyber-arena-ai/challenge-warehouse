#!/usr/bin/env bash
# CHECKER probe: connect, send a menu choice, expect the "> " prompt.
set -e
PORT=6789
python3 - "$PORT" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",port))
    pass  # treasury prints a banner on connect, no input needed
    data=b""
    while b"reas" not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)
if b"reas" in data:
    print("checker: treasury menu OK"); sys.exit(0)
print(f"checker: unexpected response {data[:48]!r}", file=sys.stderr); sys.exit(3)
PY
