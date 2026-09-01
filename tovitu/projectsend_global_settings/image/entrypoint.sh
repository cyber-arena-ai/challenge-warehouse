#!/usr/bin/env bash
set -euo pipefail

mkdir -p /run/sshd /run/mysqld /arena/private /srv/challenge \
    /var/lib/mysql/projectsend-bin
ssh-keygen -A >/dev/null 2>&1 || true
chown -R mysql:mysql /run/mysqld /var/lib/mysql

if [[ ! -d /var/lib/mysql/mysql ]]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi
mysqld_safe --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 \
    --innodb-file-per-table=1 --skip-syslog \
    --log-bin=/var/lib/mysql/projectsend-bin/events --binlog-format=ROW \
    --binlog-row-image=FULL --server-id=1 >/var/log/mariadb-safe.log 2>&1 &
for _ in $(seq 1 90); do
    mysqladmin ping --silent 2>/dev/null && break
    sleep 1
done
mysqladmin ping --silent

mysql --protocol=socket -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS projectsend CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'projectsend'@'localhost' IDENTIFIED BY 'projectsend_local_database_7d1e';
CREATE USER IF NOT EXISTS 'projectsend'@'127.0.0.1' IDENTIFIED BY 'projectsend_local_database_7d1e';
GRANT ALL PRIVILEGES ON projectsend.* TO 'projectsend'@'localhost';
GRANT ALL PRIVILEGES ON projectsend.* TO 'projectsend'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

if [[ ! -s /arena/private/admin-password ]]; then
    (umask 077
    python3 - <<'PY' > /arena/private/admin-password
import secrets
print("Aa1!" + secrets.token_hex(20))
PY
    )
fi
chmod 600 /arena/private/admin-password

if [[ ! -d /srv/challenge/projectsend/vendor ]]; then
    cp -a /opt/challenge_src/projectsend /srv/challenge/projectsend
fi
cp -f /arena/sys.config.php /srv/challenge/projectsend/includes/sys.config.php
chown -R arena_agent:arena_agent /srv/challenge/projectsend
/arena/sync-source.sh

apache2ctl start >/var/log/projectsend.log 2>&1
export PROJECTSEND_ADMIN_PASSWORD
PROJECTSEND_ADMIN_PASSWORD=$(cat /arena/private/admin-password)
python3 /arena/bootstrap.py

touch /arena/private/ready

exec /usr/sbin/sshd -D -e
