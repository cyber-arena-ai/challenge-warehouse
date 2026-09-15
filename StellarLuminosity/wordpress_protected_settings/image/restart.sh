#!/usr/bin/env bash
set -e

SOURCE=/srv/challenge/wordpress
LIVE=/var/www/html

for file in \
  wp-includes/class-wp-query.php \
  wp-includes/rest-api/class-wp-rest-server.php \
  wp-includes/rest-api.php; do
  php -l "$SOURCE/$file" >/dev/null
done
echo 'wordpress-restart: lint ok'

rsync -a --delete \
  --exclude wp-config.php \
  --exclude .htaccess \
  --exclude wp-content/uploads/ \
  "$SOURCE/" "$LIVE/"
chown -R www-data:www-data "$LIVE"
echo 'wordpress-restart: deploy ok'

if pgrep -x apache2 >/dev/null; then
  apache2ctl graceful
else
  apache2-foreground >/var/log/apache2-foreground.log 2>&1 &
fi

for i in $(seq 1 40); do
  curl -fsS --max-time 3 \
    'http://127.0.0.1/?rest_route=/wp/v2/posts&_fields=id&per_page=1' \
    >/dev/null 2>&1 && break
  sleep .25
done
curl -fsS --max-time 5 \
  'http://127.0.0.1/?rest_route=/wp/v2/posts&_fields=id&per_page=1' >/dev/null
echo 'wordpress-restart: service ready'
