#!/usr/bin/env bash
# CHECKER probe: connect, send a bogus line, expect the service's ERROR reply
# (proves the line-protocol handler is alive, not just the port open).
set -e
PORT=17280
python3 - "$PORT" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",port))
    s.sendall(b"PING\n")
    data=b""
    while b"\n" not in data:
        chunk=s.recv(256)
        if not chunk: break
        data+=chunk
    s.close()
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)
if b"ERROR" in data:
    print("checker: 8-bit-oracle protocol OK"); sys.exit(0)
print(f"checker: unexpected response {data[:48]!r}", file=sys.stderr); sys.exit(3)
PY
