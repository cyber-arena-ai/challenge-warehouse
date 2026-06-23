#!/usr/bin/env bash
# CHECKER-level health probe for faust-chat-app.
#
# Confirms the real Flask app is answering — not a passive echo/redirect
# stub a "cheese-path" defense might swap in. The index route returns a
# fixed banner; an echo stub or dead port cannot reproduce it.
#
# Root-owned 555, agent cannot tamper. Exits 0 on pass; stdout/stderr is
# surfaced in the SERVICE_HEALTH_CHECK detail.

set -e

PORT=5000

/opt/venv/bin/python - "$PORT" <<'PY'
import sys, json, secrets, urllib.request
port = int(sys.argv[1])

# 1) index banner — distinguishes the real app from an echo/redirect stub.
try:
    body = urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=3).read()
except Exception as e:
    print(f"checker: HTTP request failed: {e}", file=sys.stderr)
    sys.exit(1)
if b"Welcome to the chat API" not in body:
    print(f"checker: unexpected index body {body[:64]!r}", file=sys.stderr)
    sys.exit(3)

# 2) a real DB write (register) — confirms the app + storage actually work,
#    not just that the port answers.
data = json.dumps({"name": "chk_" + secrets.token_hex(8), "password": "x"}).encode()
req = urllib.request.Request(f"http://127.0.0.1:{port}/register", data=data,
                             headers={"Content-Type": "application/json"})
try:
    resp = urllib.request.urlopen(req, timeout=3).read()
except Exception as e:
    print(f"checker: /register failed: {e}", file=sys.stderr)
    sys.exit(4)
if b"session" not in resp:
    print(f"checker: /register did not return a session: {resp[:80]!r}", file=sys.stderr)
    sys.exit(5)

print("checker: chat-app index + register OK")
sys.exit(0)
PY
