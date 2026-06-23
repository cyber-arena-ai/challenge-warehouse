#!/usr/bin/env bash
# Container startup for craft-cms.
#
# Craft is already installed (DB baked at build), so boot is just: start
# MariaDB, materialize the defender's writable source copy, start Apache,
# then exec sshd as PID 1 to keep the container alive.

set -e

# ── SSH host keys ─────────────────────────────────────────────────────────────
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi
mkdir -p /run/sshd /run/mysqld
chown -R mysql:mysql /run/mysqld /var/lib/mysql

# ── MariaDB (data dir already installed at build time) ────────────────────────
mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 \
    >/var/log/mariadb.log 2>&1 &

echo "[*] Waiting for MariaDB..."
for i in $(seq 1 30); do
    mysqladmin ping --silent 2>/dev/null && break
    sleep 1
done

# ── Baseline flag (framework re-plants the real one each round) ───────────────
if [ ! -f /flag ]; then
    printf 'FLAG{00000000000000000000000000000000}' > /flag
    chmod 644 /flag
fi

# ── Writable source copy the defender (arena_agent) edits ─────────────────────
mkdir -p /srv/challenge/craft_cms
cp -f /opt/challenge_src/craft_cms/index.php /srv/challenge/craft_cms/index.php
chown -R arena_agent:arena_agent /srv/challenge/craft_cms
chmod -R u+w /srv/challenge/craft_cms

# ── Apache (php image's blessed launcher; reparented to sshd PID 1 after exec) ─
apache2-foreground &

echo "[*] Waiting for Craft to answer..."
for i in $(seq 1 30); do
    curl -sf -o /dev/null "http://127.0.0.1/index.php?p=admin/login" && break
    sleep 1
done
echo "[+] craft-cms ready"

# ── sshd as PID 1 ─────────────────────────────────────────────────────────────
exec /usr/sbin/sshd -D -e
