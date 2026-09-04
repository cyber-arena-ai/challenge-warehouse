#!/bin/sh
set -eu

ROOT=/srv/challenge/suitecrm
LINT=/tmp/suitecrm-lint.log
started=$(date +%s)

find "$ROOT" \
    -path "$ROOT/vendor" -prune -o \
    -path "$ROOT/cache" -prune -o \
    -path "$ROOT/upload" -prune -o \
    -path "$ROOT/include/SugarObjects/templates/basic/Dashlets/Dashlet/m-n-Dashlet.php" -prune -o \
    -path "$ROOT/include/SugarObjects/templates/file/views/view.edit.php" -prune -o \
    -type f -name '*.php' -print0 \
    | xargs -0 -n1 -P4 php -l >"$LINT" 2>&1 || {
        tail -40 "$LINT" >&2
        exit 1
    }

/command/s6-svc -r /run/service/php-fpm
/command/s6-svc -r /run/service/nginx
/command/s6-svc -u /run/service/php-fpm
/command/s6-svc -u /run/service/nginx

for _ in $(seq 1 600); do
    status=$(curl -sS --max-time 2 -o /dev/null -w '%{http_code}' \
        'http://127.0.0.1:8080/index.php?action=Login&module=Users' 2>/dev/null || true)
    if [ "$status" = 200 ]; then
        printf 'READY seconds=%s\n' "$(($(date +%s) - started))"
        exit 0
    fi
    sleep .1
done
echo "SuiteCRM failed to become ready" >&2
exit 1
