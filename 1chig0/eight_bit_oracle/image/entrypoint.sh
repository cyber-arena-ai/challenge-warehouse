#!/usr/bin/env bash
# Boot order: mariadb (offline, wait-for-ready) -> writable source copy ->
# compile+spawn the Java service via /arena/restart.sh -> sshd.
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# --- MariaDB (pre-initialised at build) -------------------------------------
mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld
# Offline: no networking, only the unix socket the Java service uses.
/usr/sbin/mariadbd --user=mysql --skip-networking >/var/log/mariadb.log 2>&1 &
for _ in $(seq 1 120); do
    [ -S /run/mysqld/mysqld.sock ] && break
    sleep 0.5
done
if [ ! -S /run/mysqld/mysqld.sock ]; then
    echo "entrypoint: mariadb failed to start (see /var/log/mariadb.log)" >&2
fi

# --- Writable source copy ---------------------------------------------------
mkdir -p /srv/challenge/8-bit-oracle/app
cp -a /opt/challenge_src/8-bit-oracle/app/. /srv/challenge/8-bit-oracle/app/
chown -R arena_agent:arena_agent /srv/challenge/8-bit-oracle
chmod -R u+w /srv/challenge/8-bit-oracle

# --- Spawn the service (pre-built jar; no javac on the hot boot path) --------
# The jar is compiled at image-build time, so the initial start skips javac
# (SKIP_COMPILE=1) to stay fast + CPU-light under concurrent batch deploys.
# Defender rebuilds go through /arena/restart.sh WITHOUT SKIP_COMPILE (recompiles).
SKIP_COMPILE=1 /arena/restart.sh || echo "entrypoint: initial start failed (see /var/log/8-bit-oracle.log)" >&2

exec /usr/sbin/sshd -D -e
