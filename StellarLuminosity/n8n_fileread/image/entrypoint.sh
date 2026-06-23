#!/usr/bin/env bash
# Container startup: SSH scaffolding, writable source copy, n8n init, sshd as PID 1.

set -e

BASE_URL="http://127.0.0.1:5678"

# ── SSH ───────────────────────────────────────────────────────────────────────
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

# ── Writable source copy (arena_agent edits this) ─────────────────────────────
mkdir -p /srv/challenge/n8n_fileread
cp -r /opt/challenge_src/n8n_fileread/. /srv/challenge/n8n_fileread/
chown -R arena_agent:arena_agent /srv/challenge/n8n_fileread
chmod -R u+w /srv/challenge/n8n_fileread

# ── Start n8n ─────────────────────────────────────────────────────────────────
n8n start > /var/log/n8n.stdout 2>&1 &

echo "[*] Waiting for n8n..."
until curl -sf "$BASE_URL/rest/settings" | grep -q '"versionCli"'; do
    sleep 2
done
echo "[+] n8n ready"

# ── First-time setup (skipped if already initialised) ────────────────────────
if curl -sf "$BASE_URL/rest/login" -X POST \
        -H "Content-Type: application/json" \
        -d '{"email":"admin@arena.local","password":"Arena_CTF_2026!"}' \
        | grep -q '"id"'; then
    echo "[+] n8n already initialised"
else
    echo "[*] Setting up n8n..."

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
    echo "[+] Setup complete. Form at: /form/document-upload"
fi

# ── sshd as PID 1 (keeps container alive) ────────────────────────────────────
exec /usr/sbin/sshd -D -e
