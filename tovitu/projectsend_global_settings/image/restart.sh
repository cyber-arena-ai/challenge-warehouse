#!/usr/bin/env bash
set -euo pipefail

SOURCE=/srv/challenge/projectsend

ensure_database() {
    if mysqladmin ping --silent 2>/dev/null; then
        return
    fi
    mkdir -p /run/mysqld
    chown -R mysql:mysql /run/mysqld /var/lib/mysql
    nohup mysqld_safe --user=mysql --datadir=/var/lib/mysql \
        --bind-address=127.0.0.1 --innodb-file-per-table=1 --skip-syslog \
        --log-bin=/var/lib/mysql/projectsend-bin/events --binlog-format=ROW \
        --binlog-row-image=FULL --server-id=1 \
        >/var/log/mariadb-safe.log 2>&1 </dev/null &
    for _ in $(seq 1 90); do
        mysqladmin ping --silent 2>/dev/null && return
        sleep 1
    done
    return 1
}

test -f "$SOURCE/index.php"
test -f "$SOURCE/options.php"
test -f "$SOURCE/includes/functions.php"
php -l "$SOURCE/index.php" >/dev/null
php -l "$SOURCE/options.php" >/dev/null
ensure_database

pkill -TERM -x apache2 >/dev/null 2>&1 || true
for _ in $(seq 1 15); do
    pgrep -x apache2 >/dev/null || break
    sleep 1
done
/arena/sync-source.sh
apache2ctl start >>/var/log/projectsend.log 2>&1
ensure_database
for _ in $(seq 1 90); do
    if curl -fsS --max-time 3 http://127.0.0.1/index.php 2>/dev/null | grep -q ProjectSend; then
        echo "ProjectSend source deployed"
        exit 0
    fi
    sleep 1
done
exit 1
