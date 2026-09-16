#!/usr/bin/env bash
set -eu

ssh_pid=
reload_sshd() {
    [ -z "$ssh_pid" ] || kill -HUP "$ssh_pid" 2>/dev/null || true
}
trap reload_sshd HUP

rand_hex() { od -An -tx1 -N"${1:-16}" /dev/urandom | tr -d ' \n'; }

rm -f /run/caddy/arena.ready
[ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -A
passwd -d root >/dev/null

if [ ! -s /arena/secrets/nextcloud.env ]; then
    umask 077
    {
        echo "SQLITE_DATABASE=nextcloud"
        echo "NEXTCLOUD_ADMIN_USER=admin$(rand_hex 6)"
        echo "NEXTCLOUD_ADMIN_PASSWORD=C1!$(rand_hex 24)"
        echo "NEXTCLOUD_TRUSTED_DOMAINS=localhost"
    } > /arena/secrets/nextcloud.env
fi

set -a
. /arena/secrets/nextcloud.env
set +a

/entrypoint.sh php-fpm -t >/tmp/nextcloud-init.log 2>&1
chown -R service:service /var/www/html

php-fpm -F >/tmp/php-fpm.log 2>&1 &
php_pid=$!

for _ in $(seq 1 300); do
    if su-exec service:service php /var/www/html/occ status --output=json \
        2>/dev/null | grep -q '"installed":true'; then
        break
    fi
    sleep .2
done
su-exec service:service php /var/www/html/occ status --output=json \
    | grep -q '"installed":true'

/arena/facility.py initialize
/arena/facility.py configure-apps
kill -TERM "$php_pid"
wait "$php_pid"
php-fpm -F >>/tmp/php-fpm.log 2>&1 &
php_pid=$!

for _ in $(seq 1 100); do
    if su-exec service:service php /var/www/html/occ status --output=json \
        2>/dev/null | grep -q '"installed":true'; then
        break
    fi
    sleep .1
done
su-exec service:service php /var/www/html/occ status --output=json \
    | grep -q '"installed":true'

su-exec service:service env \
    XDG_CONFIG_HOME=/tmp/caddy-config XDG_DATA_HOME=/tmp/caddy-data \
    /srv/runtime/caddy run --config /etc/caddy/Caddyfile --adapter caddyfile \
    >/tmp/caddy.log 2>&1 &
caddy_pid=$!
printf '%s\n' "$caddy_pid" > /run/caddy/caddy.pid

for _ in $(seq 1 300); do
    status=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
        http://127.0.0.1:8080/status.php 2>/dev/null || true)
    [ "$status" = 401 ] && break
    sleep .1
done
[ "$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
    http://127.0.0.1:8080/status.php 2>/dev/null || true)" = 401 ]

setup_complete=
for _ in $(seq 1 300); do
    if /arena/facility.py setup; then
        setup_complete=1
        break
    fi
    sleep .2
done
[ "$setup_complete" = 1 ]
/arena/facility.py status >/dev/null

/usr/sbin/sshd -D -e &
ssh_pid=$!
: > /run/caddy/arena.ready

cleanup() {
    current_caddy=$(cat /run/caddy/caddy.pid 2>/dev/null || true)
    [ -z "$current_caddy" ] || kill "$current_caddy" 2>/dev/null || true
    kill "$php_pid" "$ssh_pid" 2>/dev/null || true
    [ -z "$current_caddy" ] || wait "$current_caddy" 2>/dev/null || true
    wait "$php_pid" "$ssh_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

while kill -0 "$php_pid" 2>/dev/null && kill -0 "$ssh_pid" 2>/dev/null; do
    sleep 1
done
exit 1
