#!/bin/sh
set -eu

find /srv/challenge/navigate -type f -name '*.php' ! -name 'globals.setup.php' -print0 \
    | xargs -0 -n1 php -l >/tmp/navigate-php-lint.log
test -s /srv/challenge/navigate/login.php
test -s /srv/challenge/navigate/navigate.php
apache2ctl -k graceful
for attempt in $(seq 1 30); do
    if curl -fsS --max-time 3 http://127.0.0.1/navigate/login.php >/dev/null; then
        echo "PHP lint and Apache reload passed"
        exit 0
    fi
    sleep 1
done
echo "Navigate login did not recover" >&2
exit 1
