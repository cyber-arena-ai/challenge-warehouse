#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/dolibarr
LIVE=/var/www/html

ensure_database() {
    if mysqladmin ping --silent 2>/dev/null; then
        return
    fi
    mkdir -p /run/mysqld
    chown -R mysql:mysql /run/mysqld /var/lib/mysql
    mysqld_safe --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 \
        --skip-syslog >/var/log/mariadb-safe.log 2>&1 &
    for _ in $(seq 1 60); do
        mysqladmin ping --silent 2>/dev/null && return
        sleep 1
    done
    return 1
}

test -f "$SOURCE/htdocs/index.php"
test -f "$SOURCE/htdocs/core/lib/functions2.lib.php"
php -l "$SOURCE/htdocs/index.php" >/dev/null
php -l "$SOURCE/htdocs/core/lib/functions2.lib.php" >/dev/null
ensure_database

pkill -TERM -x apache2 >/dev/null 2>&1 || true
for _ in $(seq 1 15); do
    pgrep -x apache2 >/dev/null || break
    sleep 1
done
rsync -a --delete --exclude custom/ "$SOURCE/htdocs/" "$LIVE/"
chown -R www-data:www-data "$LIVE"
apache2ctl start >>/var/log/dolibarr.log 2>&1
ensure_database
for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 http://127.0.0.1/index.php 2>/dev/null | grep -q Dolibarr; then
        echo "Dolibarr source deployed"
        exit 0
    fi
    sleep 1
done
exit 1
