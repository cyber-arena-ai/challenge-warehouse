#!/usr/bin/env bash
# Framework restart script for n8n-fileread.
#
# Kills n8n, wipes its database so the workflow is reloaded cleanly,
# then restarts with the (possibly edited) workflow.json from the
# defender's writable copy at /srv/challenge/n8n_fileread/.
#
# Expected duration: ~20-30 seconds (n8n startup + setup API calls).
# Mode 555, root-owned — agent can read+exec but not modify.

set -e

BASE_URL="http://127.0.0.1:5678"
DB="/root/.n8n/database.sqlite"
LOG="/var/log/n8n.stdout"

echo "[*] Stopping n8n..."
pkill -f n8n || true
sleep 1

echo "[*] Clearing database..."
rm -f "$DB"

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

echo "[*] Recreating admin and importing workflow..."

curl -sf "$BASE_URL/rest/owner/setup" -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"admin@arena.local","firstName":"Admin","lastName":"Arena","password":"Arena_CTF_2026!"}' \
    > /dev/null

curl -sf "$BASE_URL/rest/login" -X POST \
    -H "Content-Type: application/json" \
    -c /tmp/n8n_cookies.txt \
    -d '{"email":"admin@arena.local","password":"Arena_CTF_2026!"}' \
    > /dev/null

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
