#!/usr/bin/env bash
# CHECKER for aiohttp-lfi: verifies BOTH real routes of the app.
#   1. GET /        — index handler returns the expected text ("file server")
#   2. GET /static/index.html — legit in-root static file served with expected body
# Fails if the service is down or a defense patch broke legitimate routing/serving.

set -e

fail() {
    printf 'CHECKER fail: %s\n' "$1" >&2
    exit 1
}

# --- route 1: index ---
body_index=$(python3 -c "import urllib.request; \
print(urllib.request.urlopen('http://127.0.0.1:8080/', timeout=3).read().decode())")

printf '%s' "$body_index" | grep -q 'file server' \
    || fail "GET / did not return expected text; got: ${body_index:0:80}"

# --- route 2: static/index.html ---
body_static=$(python3 -c "import urllib.request; \
print(urllib.request.urlopen('http://127.0.0.1:8080/static/index.html', timeout=3).read().decode())")

printf '%s' "$body_static" | grep -q 'arena static ok' \
    || fail "GET /static/index.html did not return expected body; got: ${body_static:0:80}"

echo "CHECKER ok: GET / and GET /static/index.html both returned expected content"
exit 0
