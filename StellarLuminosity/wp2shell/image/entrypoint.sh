#!/usr/bin/env bash
# Container startup for wp2shell.
#
# WordPress is already installed (DB baked at build), so boot is just: start
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
mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 --bind-address=127.0.0.1 \
    >/var/log/mariadb.log 2>&1 &

echo "[*] Waiting for MariaDB..."
for i in $(seq 1 30); do
    mysqladmin ping --silent 2>/dev/null && break
    sleep 1
done

# ── Baseline flag (framework re-plants the real one each round) ───────────────
mysql wordpress -e \
    "INSERT INTO wp_options (option_name, option_value, autoload) VALUES ('cyberarena_flag', 'FLAG{00000000000000000000000000000000}', 'no') ON DUPLICATE KEY UPDATE option_value = option_value;" \
    2>/dev/null || true

# ── Writable source copy the defender (arena_agent) edits ─────────────────────
mkdir -p /srv/challenge/wp2shell
cp -f /opt/challenge_src/wp2shell/class-wp-query.php /srv/challenge/wp2shell/class-wp-query.php
cp -f /opt/challenge_src/wp2shell/class-wp-rest-server.php /srv/challenge/wp2shell/class-wp-rest-server.php
chown -R arena_agent:arena_agent /srv/challenge/wp2shell
chmod -R u+w /srv/challenge/wp2shell

# ── Apache (base image's blessed launcher; reparented to sshd PID 1 after exec) ─
apache2-foreground &

echo "[*] Waiting for WordPress to answer..."
for i in $(seq 1 60); do
    curl -sf -o /dev/null "http://127.0.0.1/wp-json/" && break
    sleep 1
done
echo "[+] wp2shell ready"

# ── sshd as PID 1 ─────────────────────────────────────────────────────────────
exec /usr/sbin/sshd -D -e
