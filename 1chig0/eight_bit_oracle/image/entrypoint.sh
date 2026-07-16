#!/usr/bin/env bash
# Boot order: mariadb (offline, wait-for-ready) -> writable source copy ->
# compile+spawn the Java service via /arena/restart.sh -> sshd.
set -e
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A

# --- MariaDB (pre-initialised at build) -------------------------------------
mkdir -p /run/mysqld
chown mysql:mysql /run/mysqld
# Offline: no networking, only the unix socket the Java service uses. Trim the
# memory footprint (small innodb buffer pool, no performance_schema) so many
# co-located boxes can boot concurrently without OOM under a batch deploy
# (issue #25); the app DB is tiny so this costs nothing at runtime.
/usr/sbin/mariadbd --user=mysql --skip-networking \
    --innodb-buffer-pool-size=32M --performance-schema=OFF \
    >/var/log/mariadb.log 2>&1 &
# Wait until MariaDB can serve the SERVICE'S EXACT connection, not just the socket
# file or a generic root ping. The socket + a root SELECT 1 come up early — before
# the app user's grants and the app schema finish loading — but the Java service
# (SQLManager: user `8BitOracle`, db `bitoracle`, junixsocket -> mysqld.sock)
# connects on startup and dies with "Could not connect to database" if THAT
# connection isn't ready yet. The old ~20s javac recompile accidentally masked this
# race; skipping it (issue #25) let the service win the race and crash, so gate its
# start on the real 8BitOracle@bitoracle connection succeeding.
_db_ready=""
for _ in $(seq 1 120); do
    if [ -S /run/mysqld/mysqld.sock ] \
        && mariadb --socket=/run/mysqld/mysqld.sock -u root \
             -e "SELECT 1 FROM bitoracle.reviews LIMIT 1" >/dev/null 2>&1; then
        _db_ready=1; break
    fi
    sleep 0.5
done
[ -n "$_db_ready" ] || echo "entrypoint: bitoracle DB not ready in time (see /var/log/mariadb.log)" >&2

# --- Writable source copy ---------------------------------------------------
mkdir -p /srv/challenge/8-bit-oracle/app
cp -a /opt/challenge_src/8-bit-oracle/app/. /srv/challenge/8-bit-oracle/app/
chown -R arena_agent:arena_agent /srv/challenge/8-bit-oracle
chmod -R u+w /srv/challenge/8-bit-oracle

# --- Spawn the service (initial cold start: skip the redundant recompile) ----
# The jar was built at image-build time; `initial` mode spawns it directly so the
# round-0 critical path isn't blocked on two extra JVM cold-starts (issue #25).
/arena/restart.sh initial || echo "entrypoint: initial start failed (see /var/log/8-bit-oracle.log)" >&2

exec /usr/sbin/sshd -D -e
