#!/bin/sh
set -eu

mkdir -p /run/mysqld /run/sshd /run/navigate /srv/runtime/navigate/generations
chown mysql:mysql /run/mysqld
chown root:root /srv/runtime/navigate /srv/runtime/navigate/generations
test -d /var/lib/navigate-proof
test ! -L /var/lib/navigate-proof
test "$(stat -c '%u:%g:%a' /var/lib/navigate-proof)" = '0:0:700'
test -d /var/lib/navigate-proof/contexts
test ! -L /var/lib/navigate-proof/contexts
test "$(stat -c '%u:%g:%a' /var/lib/navigate-proof/contexts)" = '0:0:700'
test -f /var/lib/navigate-proof/issued.history
test ! -L /var/lib/navigate-proof/issued.history
test "$(stat -c '%u:%g:%a' /var/lib/navigate-proof/issued.history)" = '0:0:600'
test -f /var/lib/.navigate-proof.initialized
test ! -L /var/lib/.navigate-proof.initialized
test "$(stat -c '%u:%g:%a' /var/lib/.navigate-proof.initialized)" = '0:0:400'
test -f /usr/local/bin/nv-proof
test ! -L /usr/local/bin/nv-proof
test "$(stat -c '%U:%G:%a' /usr/local/bin/nv-proof)" = 'root:www-data:4750'
if [ ! -d /var/lib/mysql/mysql ]; then
    mariadb-install-db --user=mysql --datadir=/var/lib/mysql --auth-root-authentication-method=normal >/dev/null
fi
mariadbd --user=mysql --datadir=/var/lib/mysql --bind-address=127.0.0.1 >/var/log/mariadb.log 2>&1 &
for attempt in $(seq 1 90); do
    if mysqladmin ping --silent >/dev/null 2>&1; then break; fi
    if [ "$attempt" -eq 90 ]; then exit 1; fi
    sleep 1
done
mysql -uroot -e "CREATE DATABASE IF NOT EXISTS navigate CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; CREATE USER IF NOT EXISTS 'navigate'@'127.0.0.1' IDENTIFIED BY 'navigate-db-local'; GRANT ALL PRIVILEGES ON navigate.* TO 'navigate'@'127.0.0.1'; FLUSH PRIVILEGES;"
if [ ! -e /var/lib/mysql/.navigate-imported ]; then
    mysql -uroot navigate < /opt/navigate.sql
    touch /var/lib/mysql/.navigate-imported
fi

if [ ! -e /srv/challenge/navigate/login.php ]; then
    mkdir -p /srv/challenge/navigate
    cp -a /opt/challenge_src/navigate/. /srv/challenge/navigate/
    /arena/configure.py
fi
mkdir -p /srv/challenge/navigate/private/sessions /srv/challenge/navigate/cache /srv/challenge/navigate/themes /srv/challenge/navigate/updates
chown -R arena_agent:root /srv/challenge/navigate
find /srv/challenge/navigate -type d -exec chmod 0775 {} +
find /srv/challenge/navigate -type f -exec chmod 0664 {} +
rm -rf /var/www/html/navigate
# Bootstrap runs before Apache starts. This temporary source link is never a
# serving path and keeps bootstrap includes within one coherent source tree.
ln -s /srv/challenge/navigate /var/www/html/navigate

if [ ! -s /run/navigate/admin.json ]; then
    python3 -c 'import json,secrets; json.dump({"username":"arena_admin_"+secrets.token_hex(8),"password":"Aa!"+secrets.token_hex(20)},open("/run/navigate/admin.json","w"))'
    chmod 0600 /run/navigate/admin.json
fi
php /arena/bootstrap.php
chown -R arena_agent:root /srv/challenge/navigate
find /srv/challenge/navigate -type d -exec chmod 0775 {} +
find /srv/challenge/navigate -type f -exec chmod 0664 {} +

/usr/sbin/sshd
rm -rf /var/www/html/navigate
ln -s /srv/runtime/navigate/current /var/www/html/navigate
/arena/restart.sh
exec python3 /arena/supervise.py
