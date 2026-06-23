#!/usr/bin/env bash
# CHECKER probe: hit the log server's get-sth and the monitor's get-pubkey and
# expect well-formed JSON from both daemons.
set -e
python3 - <<'PY'
import sys, socket

def http_get(port, path):
    s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",port))
    s.sendall(f"GET {path} HTTP/1.0\r\nHost: x\r\n\r\n".encode())
    data=b""
    while True:
        try: chunk=s.recv(4096)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
    return data

try:
    sth = http_get(3000, "/api/v1/get-sth")
    pk  = http_get(3001, "/api/v1/get-pubkey")
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)

if b'"sth"' not in sth:
    print(f"checker: log :3000 get-sth bad: {sth[:80]!r}", file=sys.stderr); sys.exit(3)
if b'"pubkey"' not in pk:
    print(f"checker: monitor :3001 get-pubkey bad: {pk[:80]!r}", file=sys.stderr); sys.exit(3)
print("checker: certified-transparency log+monitor OK")
sys.exit(0)
PY
