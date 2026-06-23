#!/usr/bin/env bash
# Container entrypoint for nginx-backup.
#
# Sequence:
#   1. Generate SSH host keys (first-run only)
#   2. Write initial app.ini so nginx-ui binds on 127.0.0.1:9001 (internal)
#   3. Materialize the defender's writable proxy.conf
#   4. Start nginx-ui in the background
#   5. Wait for nginx-ui to be ready (up to 30 s)
#   6. Start the standalone nginx proxy on port 9000
#   7. exec sshd as PID 1

set -e

# ── SSH ──────────────────────────────────────────────────────────────────────
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd

# ── nginx-ui config: internal port 9001, localhost-only ───────────────────────
# nginx-ui reads this on startup. Binding to 127.0.0.1 means the service
# is unreachable from outside the container; only our nginx proxy (port 9000)
# can reach it. Attackers cannot bypass a patched proxy by hitting 9001 directly.
mkdir -p /etc/nginx-ui
if [ ! -f /etc/nginx-ui/app.ini ]; then
    cat > /etc/nginx-ui/app.ini << 'INI'
[server]
Host = 127.0.0.1
Port = 9001
INI
else
    python3 -c "
import re, pathlib
p = pathlib.Path('/etc/nginx-ui/app.ini')
t = p.read_text()
for key, val in [('Host', '127.0.0.1'), ('Port', '9001')]:
    if re.search('^' + key + r'\s*=', t, re.MULTILINE):
        t = re.sub('^' + key + r'\s*=.*', key + ' = ' + val, t, flags=re.MULTILINE)
    else:
        t = t.rstrip() + '\n' + key + ' = ' + val + '\n'
p.write_text(t)
"
fi

# ── Defender's writable proxy config ─────────────────────────────────────────
mkdir -p /srv/challenge/nginx_backup
cp /arena/proxy.conf.default /srv/challenge/nginx_backup/proxy.conf
chown -R arena_agent:arena_agent /srv/challenge/nginx_backup
chmod u+w /srv/challenge/nginx_backup/proxy.conf

# ── Start nginx-ui on internal port ──────────────────────────────────────────
nohup nginx-ui server --config /etc/nginx-ui/app.ini > /var/log/nginx-ui.stdout 2>&1 &

echo "[entrypoint] waiting for nginx-ui on 127.0.0.1:9001..."
for i in $(seq 1 30); do
    if curl -sf --max-time 2 http://127.0.0.1:9001/ -o /dev/null 2>/dev/null; then
        echo "[entrypoint] nginx-ui ready (${i}s)"
        break
    fi
    sleep 1
done

# ── Start standalone nginx proxy on port 9000 ─────────────────────────────────
nginx -c /arena/nginx-proxy.conf

# ── sshd as PID 1 ────────────────────────────────────────────────────────────
exec /usr/sbin/sshd -D -e
