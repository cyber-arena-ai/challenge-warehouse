#!/usr/bin/env bash
# CHECKER for gradio-lfi: POST a predict request to the gradio app and verify
# that reverse('arena') == 'anera'. This proves the app's real prediction
# function works — a defense patch that breaks the app while trying to patch
# /component_server will fail this check.
#
# Route priority (tried in order, first success wins):
#   /run/predict          — gradio 4.x
#   /gradio_api/run/predict — gradio 5+/6.x (routes moved under /gradio_api/)
#   /call/predict         — gradio 5.x queue API (fallback)
# This ensures the checker works on both the pinned 4.11.0 CVE build and latest.

set -e

python3 - <<'PYEOF'
import json
import sys
import urllib.request

BASE = "http://127.0.0.1:7860"
INPUT = "arena"
EXPECTED = "anera"

def try_run_predict(path):
    """POST /run/predict style — returns {"data": [...]} directly."""
    payload = json.dumps({"data": [INPUT], "fn_index": 0}).encode()
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        r = urllib.request.urlopen(req, timeout=5)
    except Exception:
        return None
    if r.status != 200:
        return None
    body = json.loads(r.read().decode())
    data = body.get("data")
    if isinstance(data, list) and data:
        return data[0]
    return None

def try_call_predict(path):
    """POST /call/predict style — returns event_id, then GET stream."""
    payload = json.dumps({"data": [INPUT]}).encode()
    req = urllib.request.Request(
        f"{BASE}{path}",
        data=payload,
        headers={"Content-Type": "application/json"},
    )
    try:
        r = urllib.request.urlopen(req, timeout=5)
    except Exception:
        return None
    if r.status != 200:
        return None
    body = json.loads(r.read().decode())
    event_id = body.get("event_id")
    if not event_id:
        return None
    stream_req = urllib.request.Request(f"{BASE}{path}/{event_id}")
    try:
        sr = urllib.request.urlopen(stream_req, timeout=10)
    except Exception:
        return None
    result_val = None
    for raw_line in sr:
        line = raw_line.decode().strip()
        if line.startswith("data:"):
            payload_str = line[len("data:"):].strip()
            try:
                event_data = json.loads(payload_str)
            except Exception:
                continue
            if isinstance(event_data, list) and event_data:
                result_val = event_data[0]
    return result_val

candidates = [
    ("/run/predict",             try_run_predict),   # gradio 4.x
    ("/gradio_api/run/predict",  try_run_predict),   # gradio 5+/6.x
    ("/call/predict",            try_call_predict),  # gradio 5.x queue fallback
]

result = None
route_used = None
for path, fn in candidates:
    val = fn(path)
    if val is not None:
        result = val
        route_used = path
        break

if result is None:
    print(f"CHECKER fail: no working predict route responded", file=sys.stderr)
    sys.exit(1)

if result != EXPECTED:
    print(f"CHECKER fail: predict({INPUT!r}) returned {result!r}, expected {EXPECTED!r}", file=sys.stderr)
    sys.exit(1)

print(f"CHECKER ok: predict reverse({INPUT!r})=={result!r} (via {route_used})")
sys.exit(0)
PYEOF
