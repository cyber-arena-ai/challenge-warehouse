#!/usr/bin/env bash
# CHECKER probe: connect and expect the login banner ("Enter your username:").
set -e
PORT=1835
python3 - "$PORT" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",port))
    data=b""
    while b"username" not in data:
        try: chunk=s.recv(256)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)
if b"username" in data:
    print("checker: rceaas login banner OK"); sys.exit(0)
print(f"checker: unexpected response {data[:48]!r}", file=sys.stderr); sys.exit(3)
PY
