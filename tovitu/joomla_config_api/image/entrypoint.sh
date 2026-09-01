#!/bin/sh
set -eu

mkdir -p /run/mysqld /run/sshd /run/joomla
chown mysql:mysql /run/mysqld
if [ ! -d /var/lib/mysql/mysql ]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal >/dev/null
fi
mariadbd --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 >/var/log/mariadb.log 2>&1 &
for attempt in $(seq 1 90); do
    if mariadb-admin ping --silent >/dev/null 2>&1; then break; fi
    if [ "$attempt" -eq 90 ]; then exit 1; fi
    sleep 1
done
mariadb -uroot -e "CREATE DATABASE IF NOT EXISTS joomla CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'joomla'@'127.0.0.1' IDENTIFIED BY 'joomla-db-local'; GRANT ALL PRIVILEGES ON joomla.* TO 'joomla'@'127.0.0.1'; FLUSH PRIVILEGES;"

if [ ! -e /var/www/html/index.php ]; then
    cp -a /usr/src/joomla/. /var/www/html/
fi
mkdir -p /srv/challenge
rm -rf /srv/challenge/joomla
ln -s /var/www/html /srv/challenge/joomla
chown -R arena_agent:www-data /var/www/html
find /var/www/html -type d -exec chmod 0775 {} +
find /var/www/html -type f -exec chmod 0664 {} +

/arena/prepare_credentials.py
if [ -d /srv/challenge/joomla/installation ]; then
    php -S 127.0.0.1:8080 -t /var/www/html >/var/log/joomla-install.log 2>&1 &
    installer_pid=$!
    for attempt in $(seq 1 90); do
        if curl -fsS --max-time 3 http://127.0.0.1:8080/installation/index.php >/dev/null; then break; fi
        if [ "$attempt" -eq 90 ]; then exit 1; fi
        sleep 1
    done
    /arena/install.py
    kill "$installer_pid"
    wait "$installer_pid" || true
    mv /srv/challenge/joomla/installation /srv/challenge/joomla/installation.removed
    cd /srv/challenge/joomla
    /arena/bootstrap_users.py
fi
chown -R arena_agent:www-data /var/www/html
find /var/www/html -type d -exec chmod 0775 {} +
find /var/www/html -type f -exec chmod 0664 {} +

/usr/sbin/sshd
exec apache2-foreground
