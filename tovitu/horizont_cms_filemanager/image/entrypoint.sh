#!/usr/bin/env bash
set -euo pipefail

STATE=/var/lib/horizont
DATA=$STATE/data
EDITABLE=/srv/challenge/horizont

mkdir -p /run/sshd /srv/challenge "$STATE"
install -d -o www-data -g www-data -m 0700 "$DATA"
if [ ! -f /etc/ssh/ssh_host_ed25519_key ]; then
    ssh-keygen -A
fi

if [ ! -d "$EDITABLE/app" ]; then
    cp -a /opt/horizont "$EDITABLE"
    chown -R arena_agent:arena_agent "$EDITABLE"
    chmod -R a+rX,u+w "$EDITABLE"
fi

if [ ! -f "$STATE/initialized" ]; then
    cp -a "$EDITABLE/storage" "$DATA/storage"
    touch "$DATA/database.sqlite"
    umask 077
    php -r 'echo "Adm9!", bin2hex(random_bytes(24)), PHP_EOL;' > "$STATE/admin-password"
    umask 022
    printf '%s\n' \
      'APP_NAME=HorizontCMS' \
      'APP_ENV=production' \
      'APP_KEY=' \
      'APP_DEBUG=false' \
      'APP_URL=http://127.0.0.1:8080' \
      'DB_CONNECTION=sqlite' \
      "DB_DATABASE=$DATA/database.sqlite" \
      'CACHE_DRIVER=file' \
      'SESSION_DRIVER=file' \
      'QUEUE_CONNECTION=sync' \
      'HCMS_ADMIN_PREFIX=admin' \
      'INSTALLED=YES' > "$DATA/.env"

    rm -rf "$EDITABLE/storage"
    ln -s "$DATA/storage" "$EDITABLE/storage"
    chown -R www-data:www-data "$DATA"
    chmod 0600 "$DATA/database.sqlite" "$DATA/.env"

    cd "$EDITABLE"
    rm -f "$EDITABLE/.env"
    DB_CONNECTION=sqlite DB_DATABASE="$DATA/database.sqlite" php artisan migrate --force
    DB_CONNECTION=sqlite DB_DATABASE="$DATA/database.sqlite" php artisan db:seed --force
    ln -s "$DATA/.env" "$EDITABLE/.env"
    php artisan key:generate --force
    php artisan hcms:user \
      --name=ArenaAdmin \
      --email=admin@arena.invalid \
      --username=arena_admin \
      --password="$(cat "$STATE/admin-password")"
    touch "$STATE/initialized"
fi

rm -rf "$EDITABLE/storage"
ln -s "$DATA/storage" "$EDITABLE/storage"
ln -sf "$DATA/.env" "$EDITABLE/.env"
install -d -o root -g root -m 0700 "$STATE/proofs"
chown root:root "$STATE/admin-password" "$STATE/initialized"
chmod 0600 "$STATE/admin-password" "$STATE/initialized"
chown -R www-data:www-data "$DATA"
chmod 0700 "$DATA"
chmod 0600 "$DATA/database.sqlite" "$DATA/.env"

/arena/restart.sh
exec /usr/sbin/sshd -D -e
