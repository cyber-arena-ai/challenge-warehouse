#!/usr/bin/env bash
# Framework restart script for n8n-fileread.
#
# Kills n8n, keeps its database and per-container admin secret, then replaces
# the active workflow with the defender's edited workflow.json from
# /srv/challenge/n8n_fileread/.
#
# Expected duration: ~20-30 seconds (n8n startup + setup API calls).
# Mode 555, root-owned — agent can read+exec but not modify.

set -e

BASE_URL="http://127.0.0.1:5678"
LOG="/var/log/n8n.stdout"
STATE_DIR="/var/lib/cyberarena/n8n_fileread"
ADMIN_EMAIL="admin@arena.local"
ADMIN_PASSWORD_FILE="${STATE_DIR}/admin_password"

if [ ! -s "$ADMIN_PASSWORD_FILE" ]; then
    echo "[!] missing per-container admin password at ${ADMIN_PASSWORD_FILE}" >&2
    exit 1
fi
ADMIN_PASSWORD="$(cat "$ADMIN_PASSWORD_FILE")"
export ADMIN_EMAIL ADMIN_PASSWORD

echo "[*] Stopping n8n..."
pkill -f n8n || true
sleep 1
# SIGKILL fallback: a process that ignored SIGTERM must not hold the port and
# drag the restart past the readiness window — hard-kill after the grace.
pkill -9 -f 'n8n' 2>/dev/null || true

echo "[*] Starting n8n..."
nohup n8n start >> "$LOG" 2>&1 &

echo "[*] Waiting for n8n... (~20s)"
for i in $(seq 1 30); do
    curl -sf "$BASE_URL/rest/settings" | grep -q '"versionCli"' && break
    sleep 2
done

if ! curl -sf "$BASE_URL/rest/settings" | grep -q '"versionCli"'; then
    echo "[!] n8n failed to start within 60s" >&2
    exit 1
fi
echo "[+] n8n ready"

echo "[*] Authenticating with per-container admin secret..."

curl -sf "$BASE_URL/rest/login" -X POST \
    -H "Content-Type: application/json" \
    -c /tmp/n8n_cookies.txt \
    --data-binary "$(python3 -c 'import json, os
print(json.dumps({"email": os.environ["ADMIN_EMAIL"], "password": os.environ["ADMIN_PASSWORD"]}))')" \
    > /dev/null || {
        echo "[!] login failed; restart will not recreate or reset admin credentials" >&2
        exit 1
    }

echo "[*] Replacing workflows with edited workflow.json..."

WF_LIST=$(curl -sf "$BASE_URL/rest/workflows" -b /tmp/n8n_cookies.txt)
WF_IDS=$(printf '%s' "$WF_LIST" | python3 -c "import json, sys
d = json.load(sys.stdin)
items = d.get('data', d)
if isinstance(items, dict):
    items = items.get('data', [])
if not isinstance(items, list):
    items = []
for item in items:
    wid = item.get('id') if isinstance(item, dict) else None
    if wid:
        print(wid)
")

for WF_ID in $WF_IDS; do
    curl -sf "$BASE_URL/rest/workflows/$WF_ID" -X PATCH \
        -H "Content-Type: application/json" \
        -b /tmp/n8n_cookies.txt \
        -d '{"active":false}' \
        > /dev/null || true
    curl -sf "$BASE_URL/rest/workflows/$WF_ID" -X DELETE \
        -b /tmp/n8n_cookies.txt \
        > /dev/null || {
            echo "[!] failed to delete existing workflow ${WF_ID}" >&2
            exit 1
        }
done

WF_RESP=$(curl -sf "$BASE_URL/rest/workflows" -X POST \
    -H "Content-Type: application/json" \
    -b /tmp/n8n_cookies.txt \
    -d @/srv/challenge/n8n_fileread/workflow.json)

WF_ID=$(echo "$WF_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['data']['id'] if 'data' in d else d['id'])")
echo "[+] Workflow ID: $WF_ID"

curl -sf "$BASE_URL/rest/workflows/$WF_ID" -X PATCH \
    -H "Content-Type: application/json" \
    -b /tmp/n8n_cookies.txt \
    -d '{"active":true}' \
    > /dev/null

rm -f /tmp/n8n_cookies.txt
echo "[+] n8n restarted. pid=$(pgrep -f n8n | head -1)"
