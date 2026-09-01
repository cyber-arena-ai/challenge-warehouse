#!/bin/sh
set -eu

find /var/www/html -type f -name '*.php' ! -path '*/cache/*' -print0 \
    | xargs -0 -P4 -n1 php -l >/tmp/joomla-php-lint.log
test -s /srv/challenge/joomla/index.php
test -s /srv/challenge/joomla/api/index.php
apache2ctl -k graceful
for attempt in $(seq 1 30); do
    if curl -fsS --max-time 3 http://127.0.0.1/ >/dev/null; then
        echo "PHP lint and Apache reload passed"
        exit 0
    fi
    sleep 1
done
echo "Joomla homepage did not recover" >&2
exit 1
