#!/usr/bin/env bash
set -e

mkdir -p /run/sshd /run/mysqld /var/lib/cyberarena
chown -R mysql:mysql /run/mysqld /var/lib/mysql
chmod 0700 /var/lib/cyberarena
test -f /etc/ssh/ssh_host_ed25519_key || ssh-keygen -A

mariadbd --user=mysql --datadir=/var/lib/mysql --port=3306 \
  --bind-address=127.0.0.1 >/var/log/mariadb.log 2>&1 &
for i in $(seq 1 60); do
  mysqladmin ping --silent 2>/dev/null && break
  sleep 1
done
mysqladmin ping --silent

if [ ! -f /var/lib/cyberarena/runtime-initialized ]; then
  for key in AUTH_KEY SECURE_AUTH_KEY LOGGED_IN_KEY NONCE_KEY AUTH_SALT SECURE_AUTH_SALT LOGGED_IN_SALT NONCE_SALT; do
    value=$(head -c 48 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
    runuser -u www-data -- wp --path=/var/www/html config set "$key" "$value" --type=constant >/dev/null
  done
  owner_password=$(head -c 36 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
  owner_email="owner-$(od -An -N12 -tx1 /dev/urandom | tr -d ' \n')@invalid.example"
  runuser -u www-data -- wp --path=/var/www/html user update site-owner \
    --user_pass="$owner_password" --user_email="$owner_email" >/dev/null
  runuser -u www-data -- wp --path=/var/www/html option update admin_email "$owner_email" >/dev/null
  touch /var/lib/cyberarena/runtime-initialized
  chmod 0600 /var/lib/cyberarena/runtime-initialized
fi

if [ ! -f /srv/challenge/wordpress/wp-includes/version.php ]; then
  mkdir -p /srv/challenge/wordpress
  cp -a /opt/wordpress-source/. /srv/challenge/wordpress/
  chown -R arena_agent:arena_agent /srv/challenge/wordpress
fi

apache2-foreground >/var/log/apache2-foreground.log 2>&1 &
for i in $(seq 1 90); do
  curl -fsS --max-time 3 \
    'http://127.0.0.1/?rest_route=/wp/v2/posts&_fields=id&per_page=1' \
    >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS --max-time 5 \
  'http://127.0.0.1/?rest_route=/wp/v2/posts&_fields=id&per_page=1' >/dev/null
touch /var/lib/cyberarena/runtime-ready
chmod 0600 /var/lib/cyberarena/runtime-ready

exec /usr/sbin/sshd -D -e
