#!/usr/bin/env bash
# CHECKER probe: connect and expect the login page (it draws "Participant:").
set -e
PORT=1983
python3 - "$PORT" <<'PY'
import sys, socket
port=int(sys.argv[1])
try:
    s=socket.socket(); s.settimeout(3); s.connect(("127.0.0.1",port))
    data=b""
    while b"Participant" not in data and len(data) < 65536:
        try: chunk=s.recv(4096)
        except Exception: break
        if not chunk: break
        data+=chunk
    s.close()
except Exception as e:
    print(f"checker: connect/IO failed: {e}", file=sys.stderr); sys.exit(1)
if b"Participant" in data:
    print("checker: btx login page OK"); sys.exit(0)
print(f"checker: unexpected response {data[:48]!r}", file=sys.stderr); sys.exit(3)
PY
