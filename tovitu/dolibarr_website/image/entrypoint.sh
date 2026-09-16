#!/usr/bin/env bash
set -euo pipefail

mkdir -p /run/sshd /run/mysqld /arena/private
ssh-keygen -A >/dev/null 2>&1 || true
chown -R mysql:mysql /run/mysqld /var/lib/mysql

if [[ ! -d /var/lib/mysql/mysql ]]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql >/dev/null
fi
mysqld_safe --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 \
    --skip-syslog >/var/log/mariadb-safe.log 2>&1 &
for _ in $(seq 1 60); do
    mysqladmin ping --silent 2>/dev/null && break
    sleep 1
done
mysqladmin ping --silent

mysql --protocol=socket -uroot <<'SQL'
CREATE DATABASE IF NOT EXISTS dolidb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS 'doli'@'localhost' IDENTIFIED BY 'doli_local_database_3b8e';
CREATE USER IF NOT EXISTS 'doli'@'127.0.0.1' IDENTIFIED BY 'doli_local_database_3b8e';
GRANT ALL PRIVILEGES ON dolidb.* TO 'doli'@'localhost';
GRANT ALL PRIVILEGES ON dolidb.* TO 'doli'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL

if [[ ! -s /arena/private/admin-password ]]; then
    umask 077
    python3 - <<'PY' > /arena/private/admin-password
import secrets
print("Aa1!" + secrets.token_hex(20))
PY
fi
chmod 600 /arena/private/admin-password
export DOLI_ADMIN_PASSWORD
DOLI_ADMIN_PASSWORD=$(cat /arena/private/admin-password)

if [[ ! -d /srv/challenge/dolibarr/htdocs ]]; then
    mkdir -p /srv/challenge
    cp -a /opt/challenge_src/dolibarr /srv/challenge/dolibarr
fi
chown -R arena_agent:arena_agent /srv/challenge/dolibarr

rsync -a --delete /srv/challenge/dolibarr/htdocs/ /var/www/html/
chown -R www-data:www-data /var/www/html

/usr/local/bin/docker-run.sh apache2ctl start >/var/log/dolibarr.log 2>&1
for _ in $(seq 1 300); do
    if curl -fsS --max-time 3 http://127.0.0.1/index.php 2>/dev/null | grep -q Dolibarr; then
        break
    fi
    sleep 1
done
curl -fsS --max-time 10 http://127.0.0.1/index.php | grep -q Dolibarr

# Preserve generated runtime configuration in the editable tree so a source
# replacement retains the installed application while leaving database state
# and Website documents untouched.
cp -f /var/www/html/conf/conf.php /srv/challenge/dolibarr/htdocs/conf/conf.php
chown arena_agent:arena_agent /srv/challenge/dolibarr/htdocs/conf/conf.php

exec /usr/sbin/sshd -D -e
