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

apache_processes_running() {
    ps -C apache2 -o stat= 2>/dev/null \
        | grep -Eq '^[[:space:]]*[^Z[:space:]]'
}

stop_apache() {
    pkill -TERM -x apache2 >/dev/null 2>&1 || true
    for _ in $(seq 1 15); do
        apache_processes_running || break
        sleep 1
    done
    if apache_processes_running; then
        pkill -KILL -x apache2 >/dev/null 2>&1 || true
        for _ in $(seq 1 5); do
            apache_processes_running || break
            sleep 1
        done
    fi
    if apache_processes_running; then
        echo "Apache processes survived shutdown" >&2
        return 1
    fi
}

cleanup_failed_restart() {
    local rc=$?
    trap - EXIT
    if [[ $rc -ne 0 ]]; then
        stop_apache || true
    fi
    exit "$rc"
}

stop_apache
test -f "$SOURCE/htdocs/index.php"
test -f "$SOURCE/htdocs/core/lib/functions2.lib.php"
php -l "$SOURCE/htdocs/index.php" >/dev/null
php -l "$SOURCE/htdocs/core/lib/functions2.lib.php" >/dev/null
ensure_database
rsync -a --delete "$SOURCE/htdocs/" "$LIVE/"
chown -R www-data:www-data "$LIVE"

trap cleanup_failed_restart EXIT
apache2ctl start >>/var/log/dolibarr.log 2>&1
ensure_database
for _ in $(seq 1 60); do
    if curl -fsS --max-time 3 http://127.0.0.1/index.php 2>/dev/null | grep -q Dolibarr; then
        trap - EXIT
        echo "Dolibarr source deployed"
        exit 0
    fi
    sleep 1
done
exit 1
